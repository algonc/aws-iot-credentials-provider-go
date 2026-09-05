// Copyright (c) 2026 André Gonçalves
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package iotcredentials

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// credentialsResponse is the body returned by the AWS IoT credentials provider:
//
//	{"credentials":{"accessKeyId":"...","secretAccessKey":"...",
//	                "sessionToken":"...","expiration":"2018-01-18T09:18:06Z"}}
type credentialsResponse struct {
	Credentials struct {
		AccessKeyID     string    `json:"accessKeyId"`
		SecretAccessKey string    `json:"secretAccessKey"`
		SessionToken    string    `json:"sessionToken"`
		Expiration      time.Time `json:"expiration"`
	} `json:"credentials"`
}

// errorResponse is the body AWS IoT returns on failure.
type errorResponse struct {
	Message string `json:"message"`
	// Some AWS IoT error paths capitalize the field.
	MessageAlt string `json:"Message"`
}

// fetch calls AWS IoT and returns the credentials along with their lifetime as
// measured against the local clock.
func (p *Provider) fetch(ctx context.Context) (aws.Credentials, time.Duration, error) {
	body, err := p.do(ctx)
	if err != nil {
		return aws.Credentials{}, 0, err
	}

	var parsed credentialsResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return aws.Credentials{}, 0, fmt.Errorf(
			"iotcredentials: parsing credentials response: %w (body: %s)", err, truncate(string(body)))
	}

	c := parsed.Credentials
	switch {
	case c.AccessKeyID == "":
		return aws.Credentials{}, 0, errors.New("iotcredentials: response contained no access key id")
	case c.SecretAccessKey == "":
		return aws.Credentials{}, 0, errors.New("iotcredentials: response contained no secret access key")
	case c.SessionToken == "":
		return aws.Credentials{}, 0, errors.New("iotcredentials: response contained no session token")
	case c.Expiration.IsZero():
		return aws.Credentials{}, 0, errors.New("iotcredentials: response contained no expiration")
	}

	now := p.opts.now()
	lifetime := c.Expiration.Sub(now)
	if lifetime <= 0 {
		return aws.Credentials{}, 0, fmt.Errorf("%w: expiration %s is not after local time %s",
			ErrCredentialsExpired, c.Expiration.Format(time.RFC3339), now.Format(time.RFC3339))
	}

	return aws.Credentials{
		AccessKeyID:     c.AccessKeyID,
		SecretAccessKey: c.SecretAccessKey,
		SessionToken:    c.SessionToken,
		Source:          ProviderName,
		CanExpire:       true,
		Expires:         c.Expiration,
	}, lifetime, nil
}

// do performs the request, retrying transient failures, and returns the body of
// a successful response.
func (p *Provider) do(ctx context.Context) ([]byte, error) {
	var lastErr error

	for attempt := 0; ; attempt++ {
		body, err := p.attempt(ctx)
		if err == nil {
			return body, nil
		}
		lastErr = err

		if attempt >= p.opts.MaxRetries || !p.retryable(err) {
			return nil, lastErr
		}
		if err := sleep(ctx, p.backoff(attempt)); err != nil {
			// Report the AWS failure, not the cancellation that stopped us
			// from retrying it.
			return nil, fmt.Errorf("%w (retries abandoned: %v)", lastErr, err)
		}
	}
}

// attempt performs a single request.
func (p *Provider) attempt(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("iotcredentials: building request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", fmt.Sprintf("aws-iot-credentials-provider-go/%s (%s; %s)",
		version, runtime.Version(), runtime.GOOS))
	if p.opts.ThingName != "" {
		req.Header.Set("x-amzn-iot-thingname", p.opts.ThingName)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		// The client error already names the URL.
		return nil, fmt.Errorf("iotcredentials: requesting credentials: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	// The success body is a few kilobytes; cap it well above that so a
	// misdirected request cannot exhaust memory.
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode != http.StatusOK {
		return nil, newAPIError(resp, body)
	}
	if readErr != nil {
		return nil, fmt.Errorf("iotcredentials: reading credentials response: %w", readErr)
	}
	return body, nil
}

// newAPIError builds an APIError from a failed response.
func newAPIError(resp *http.Response, body []byte) *APIError {
	apiErr := &APIError{
		StatusCode: resp.StatusCode,
		RequestID:  resp.Header.Get("x-amzn-RequestId"),
		ErrorType:  resp.Header.Get("x-amzn-ErrorType"),
		Body:       truncate(strings.TrimSpace(string(body))),
	}

	var parsed errorResponse
	if err := json.Unmarshal(body, &parsed); err == nil {
		if parsed.Message != "" {
			apiErr.Message = parsed.Message
		} else {
			apiErr.Message = parsed.MessageAlt
		}
	}
	return apiErr
}

// retryable reports whether err is worth another attempt. Transport errors are
// always retried; status codes are retried when they are 429, 5xx, or listed in
// ExtraRetryStatusCodes.
func (p *Provider) retryable(err error) bool {
	// The caller gave up; retrying cannot succeed.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		// Connection reset, DNS failure, timeout, and similar.
		return true
	}

	if apiErr.StatusCode == http.StatusTooManyRequests || apiErr.StatusCode >= 500 {
		return true
	}
	for _, code := range p.opts.ExtraRetryStatusCodes {
		if apiErr.StatusCode == code {
			return true
		}
	}
	return false
}

// backoff returns the delay before the attempt after the given one, using
// exponential growth with full jitter so that a fleet refreshing at the same
// moment spreads out instead of retrying in lockstep.
func (p *Provider) backoff(attempt int) time.Duration {
	const maxDelay = 20 * time.Second

	delay := p.opts.RetryBaseDelay << attempt
	if delay > maxDelay || delay <= 0 {
		delay = maxDelay
	}
	return delay/2 + time.Duration(rand.Int64N(int64(delay/2)+1))
}

// sleep waits for d, or returns early if ctx is done.
func sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// truncate bounds a string retained for error reporting.
func truncate(s string) string {
	if len(s) <= maxErrorBodyBytes {
		return s
	}
	return s[:maxErrorBodyBytes] + "... (truncated)"
}
