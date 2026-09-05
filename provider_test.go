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
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRetrieveReturnsCredentials(t *testing.T) {
	expiration := time.Now().Add(15 * time.Minute).Truncate(time.Second)
	endpoint := newFakeEndpoint(t, expiration)
	provider := newTestProvider(t, endpoint)

	creds, err := provider.Retrieve(context.Background())
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}

	if creds.AccessKeyID != "ASIAEXAMPLE" {
		t.Errorf("AccessKeyID = %q, want ASIAEXAMPLE", creds.AccessKeyID)
	}
	if creds.SecretAccessKey != "secret-example" {
		t.Errorf("SecretAccessKey = %q, want secret-example", creds.SecretAccessKey)
	}
	if creds.SessionToken != "token-example" {
		t.Errorf("SessionToken = %q, want token-example", creds.SessionToken)
	}
	if creds.Source != ProviderName {
		t.Errorf("Source = %q, want %q", creds.Source, ProviderName)
	}
	if !creds.CanExpire {
		t.Error("CanExpire = false, want true")
	}
	if !creds.Expires.Equal(expiration) {
		t.Errorf("Expires = %s, want %s", creds.Expires, expiration)
	}

	// The request must match what AWS IoT expects, including the client
	// certificate and the SNI host name.
	got := endpoint.last(t)
	if got.Method != http.MethodGet {
		t.Errorf("method = %s, want GET", got.Method)
	}
	if want := "/role-aliases/iot-credentials-demo/credentials"; got.Path != want {
		t.Errorf("path = %s, want %s", got.Path, want)
	}
	if got.ClientCN != "device-test" {
		t.Errorf("client certificate CN = %q, want device-test", got.ClientCN)
	}
	if got.ThingName != "" {
		t.Errorf("x-amzn-iot-thingname = %q, want it unset", got.ThingName)
	}
	if !strings.HasPrefix(got.UserAgent, "aws-iot-credentials-provider-go/") {
		t.Errorf("User-Agent = %q, want the provider's user agent", got.UserAgent)
	}
}

func TestRetrieveSendsThingNameHeader(t *testing.T) {
	endpoint := newFakeEndpoint(t, time.Now().Add(15*time.Minute))
	provider := newTestProvider(t, endpoint, WithThingName("device-42"))

	if _, err := provider.Retrieve(context.Background()); err != nil {
		t.Fatalf("Retrieve: %v", err)
	}

	if got := endpoint.last(t).ThingName; got != "device-42" {
		t.Errorf("x-amzn-iot-thingname = %q, want device-42", got)
	}
}

func TestRetrieveUsesCache(t *testing.T) {
	endpoint := newFakeEndpoint(t, time.Now().Add(15*time.Minute))
	provider := newTestProvider(t, endpoint)

	first, err := provider.Retrieve(context.Background())
	if err != nil {
		t.Fatalf("first Retrieve: %v", err)
	}
	second, err := provider.Retrieve(context.Background())
	if err != nil {
		t.Fatalf("second Retrieve: %v", err)
	}

	if first != second {
		t.Error("second Retrieve returned different credentials")
	}
	if got := endpoint.count(); got != 1 {
		t.Errorf("endpoint received %d requests, want 1 because the second call is cached", got)
	}
}

func TestRetrieveRefreshesWithinMargin(t *testing.T) {
	base := time.Now()
	now := base

	endpoint := newFakeEndpointWith(t, func(w http.ResponseWriter, _ int) {
		// Each response expires 15 minutes after the current fake time.
		writeCredentials(w, now.Add(15*time.Minute))
	})
	provider := newTestProvider(t, endpoint,
		WithRefreshMargin(5*time.Minute),
		withClock(func() time.Time { return now }),
	)

	if _, err := provider.Retrieve(context.Background()); err != nil {
		t.Fatalf("Retrieve at T0: %v", err)
	}

	// Still outside the refresh margin: cached.
	now = base.Add(9 * time.Minute)
	if _, err := provider.Retrieve(context.Background()); err != nil {
		t.Fatalf("Retrieve at T0+9m: %v", err)
	}
	if got := endpoint.count(); got != 1 {
		t.Fatalf("endpoint received %d requests at T0+9m, want 1", got)
	}

	// Inside the 5 minute margin of the 15 minute credential: refetch.
	now = base.Add(10*time.Minute + time.Second)
	if _, err := provider.Retrieve(context.Background()); err != nil {
		t.Fatalf("Retrieve at T0+10m: %v", err)
	}
	if got := endpoint.count(); got != 2 {
		t.Errorf("endpoint received %d requests at T0+10m, want 2", got)
	}
}

func TestRefreshMarginCappedAtHalfLifetime(t *testing.T) {
	base := time.Now()
	now := base

	endpoint := newFakeEndpointWith(t, func(w http.ResponseWriter, _ int) {
		writeCredentials(w, now.Add(10*time.Minute))
	})
	// A margin longer than the credential lifetime would otherwise make every
	// call miss the cache and hammer AWS IoT.
	provider := newTestProvider(t, endpoint,
		WithRefreshMargin(30*time.Minute),
		withClock(func() time.Time { return now }),
	)

	if _, err := provider.Retrieve(context.Background()); err != nil {
		t.Fatalf("Retrieve at T0: %v", err)
	}

	now = base.Add(4 * time.Minute)
	if _, err := provider.Retrieve(context.Background()); err != nil {
		t.Fatalf("Retrieve at T0+4m: %v", err)
	}
	if got := endpoint.count(); got != 1 {
		t.Fatalf("endpoint received %d requests at T0+4m, want 1 because the margin is capped to 5m", got)
	}

	now = base.Add(6 * time.Minute)
	if _, err := provider.Retrieve(context.Background()); err != nil {
		t.Fatalf("Retrieve at T0+6m: %v", err)
	}
	if got := endpoint.count(); got != 2 {
		t.Errorf("endpoint received %d requests at T0+6m, want 2", got)
	}
}

func TestInvalidateForcesRefetch(t *testing.T) {
	endpoint := newFakeEndpoint(t, time.Now().Add(15*time.Minute))
	provider := newTestProvider(t, endpoint)

	if _, err := provider.Retrieve(context.Background()); err != nil {
		t.Fatalf("first Retrieve: %v", err)
	}
	provider.Invalidate()
	if _, err := provider.Retrieve(context.Background()); err != nil {
		t.Fatalf("Retrieve after Invalidate: %v", err)
	}

	if got := endpoint.count(); got != 2 {
		t.Errorf("endpoint received %d requests, want 2", got)
	}
}

func TestConcurrentRetrieveFetchesOnce(t *testing.T) {
	endpoint := newFakeEndpoint(t, time.Now().Add(15*time.Minute))
	provider := newTestProvider(t, endpoint)

	const goroutines = 8
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := provider.Retrieve(context.Background()); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Fatalf("concurrent Retrieve: %v", err)
	}
	if got := endpoint.count(); got != 1 {
		t.Errorf("endpoint received %d requests, want 1", got)
	}
}

func TestAPIErrorNotRetried(t *testing.T) {
	endpoint := newFakeEndpointWith(t, func(w http.ResponseWriter, _ int) {
		w.Header().Set("x-amzn-RequestId", "req-123")
		w.Header().Set("x-amzn-ErrorType", "AccessDeniedException")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"access denied"}`))
	})
	provider := newTestProvider(t, endpoint)

	_, err := provider.Retrieve(context.Background())
	if err == nil {
		t.Fatal("Retrieve succeeded, want an error")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error is %T, want *APIError", err)
	}
	if apiErr.StatusCode != http.StatusForbidden {
		t.Errorf("StatusCode = %d, want 403", apiErr.StatusCode)
	}
	if apiErr.Message != "access denied" {
		t.Errorf("Message = %q, want %q", apiErr.Message, "access denied")
	}
	if apiErr.RequestID != "req-123" {
		t.Errorf("RequestID = %q, want req-123", apiErr.RequestID)
	}
	if apiErr.ErrorType != "AccessDeniedException" {
		t.Errorf("ErrorType = %q, want AccessDeniedException", apiErr.ErrorType)
	}
	if !strings.Contains(err.Error(), "req-123") {
		t.Errorf("error message %q does not mention the request id", err.Error())
	}

	// 403 means the policy is wrong, so retrying it is pointless.
	if got := endpoint.count(); got != 1 {
		t.Errorf("endpoint received %d requests, want 1 because 403 is not retryable", got)
	}
}

func TestRetriesServerErrors(t *testing.T) {
	endpoint := newFakeEndpointWith(t, func(w http.ResponseWriter, n int) {
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		writeCredentials(w, time.Now().Add(15*time.Minute))
	})
	provider := newTestProvider(t, endpoint)

	if _, err := provider.Retrieve(context.Background()); err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if got := endpoint.count(); got != 3 {
		t.Errorf("endpoint received %d requests, want 3", got)
	}
}

func TestRetryOnStatusOption(t *testing.T) {
	endpoint := newFakeEndpointWith(t, func(w http.ResponseWriter, n int) {
		if n < 2 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		writeCredentials(w, time.Now().Add(15*time.Minute))
	})
	// Mirrors the propagation retry in iotresume.sh.
	provider := newTestProvider(t, endpoint, WithRetryOnStatus(http.StatusForbidden))

	if _, err := provider.Retrieve(context.Background()); err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if got := endpoint.count(); got != 2 {
		t.Errorf("endpoint received %d requests, want 2", got)
	}
}

func TestMaxRetriesZeroDisablesRetrying(t *testing.T) {
	endpoint := newFakeEndpointWith(t, func(w http.ResponseWriter, _ int) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	provider := newTestProvider(t, endpoint, WithMaxRetries(0))

	if _, err := provider.Retrieve(context.Background()); err == nil {
		t.Fatal("Retrieve succeeded, want an error")
	}
	if got := endpoint.count(); got != 1 {
		t.Errorf("endpoint received %d requests, want 1", got)
	}
}

func TestRetriesExhausted(t *testing.T) {
	endpoint := newFakeEndpointWith(t, func(w http.ResponseWriter, _ int) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	provider := newTestProvider(t, endpoint, WithMaxRetries(2))

	_, err := provider.Retrieve(context.Background())
	if err == nil {
		t.Fatal("Retrieve succeeded, want an error")
	}
	// The initial attempt plus two retries.
	if got := endpoint.count(); got != 3 {
		t.Errorf("endpoint received %d requests, want 3", got)
	}
}

func TestExpiredCredentialsRejected(t *testing.T) {
	endpoint := newFakeEndpoint(t, time.Now().Add(-time.Minute))
	provider := newTestProvider(t, endpoint)

	_, err := provider.Retrieve(context.Background())
	if !errors.Is(err, ErrCredentialsExpired) {
		t.Fatalf("error = %v, want ErrCredentialsExpired", err)
	}
}

func TestMalformedResponses(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"not json", `<html>proxy error</html>`, "parsing credentials response"},
		{"empty object", `{}`, "no access key id"},
		{"missing secret", `{"credentials":{"accessKeyId":"A"}}`, "no secret access key"},
		{"missing token", `{"credentials":{"accessKeyId":"A","secretAccessKey":"S"}}`, "no session token"},
		{
			"missing expiration",
			`{"credentials":{"accessKeyId":"A","secretAccessKey":"S","sessionToken":"T"}}`,
			"no expiration",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			endpoint := newFakeEndpointWith(t, func(w http.ResponseWriter, _ int) {
				_, _ = w.Write([]byte(tc.body))
			})
			provider := newTestProvider(t, endpoint)

			_, err := provider.Retrieve(context.Background())
			if err == nil {
				t.Fatal("Retrieve succeeded, want an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestKeyPairSources(t *testing.T) {
	t.Run("files", func(t *testing.T) {
		endpoint := newFakeEndpoint(t, time.Now().Add(15*time.Minute))
		client := endpoint.clientCA.issueClient(t, "device-files")
		certPath, keyPath := client.writeFiles(t)

		provider, err := NewProvider(
			WithEndpoint(endpoint.endpoint()),
			WithRoleAlias("iot-credentials-demo"),
			WithCertificatePath(certPath),
			WithPrivateKeyPath(keyPath),
			WithRootCAs(endpoint.rootCAs),
		)
		if err != nil {
			t.Fatalf("NewProvider: %v", err)
		}
		if _, err := provider.Retrieve(context.Background()); err != nil {
			t.Fatalf("Retrieve: %v", err)
		}
		if got := endpoint.last(t).ClientCN; got != "device-files" {
			t.Errorf("client certificate CN = %q, want device-files", got)
		}
	})

	t.Run("pkcs8 key", func(t *testing.T) {
		endpoint := newFakeEndpoint(t, time.Now().Add(15*time.Minute))
		client := endpoint.clientCA.issueClient(t, "device-pkcs8")

		provider, err := NewProvider(
			WithEndpoint(endpoint.endpoint()),
			WithRoleAlias("iot-credentials-demo"),
			WithKeyPairPEM(client.certPEM, client.pkcs8KeyPEM(t)),
			WithRootCAs(endpoint.rootCAs),
		)
		if err != nil {
			t.Fatalf("NewProvider: %v", err)
		}
		if _, err := provider.Retrieve(context.Background()); err != nil {
			t.Fatalf("Retrieve: %v", err)
		}
	})

	t.Run("tls certificate", func(t *testing.T) {
		endpoint := newFakeEndpoint(t, time.Now().Add(15*time.Minute))
		client := endpoint.clientCA.issueClient(t, "device-signer")

		// Mirrors supplying a hardware-backed crypto.Signer.
		provider, err := NewProvider(
			WithEndpoint(endpoint.endpoint()),
			WithRoleAlias("iot-credentials-demo"),
			WithTLSCertificate(client.tlsCertificate()),
			WithRootCAs(endpoint.rootCAs),
		)
		if err != nil {
			t.Fatalf("NewProvider: %v", err)
		}
		if _, err := provider.Retrieve(context.Background()); err != nil {
			t.Fatalf("Retrieve: %v", err)
		}
		if got := endpoint.last(t).ClientCN; got != "device-signer" {
			t.Errorf("client certificate CN = %q, want device-signer", got)
		}
	})
}

func TestRotatedCertificateIsPickedUp(t *testing.T) {
	endpoint := newFakeEndpoint(t, time.Now().Add(15*time.Minute))
	first := endpoint.clientCA.issueClient(t, "device-before-rotation")
	certPath, keyPath := first.writeFiles(t)

	provider, err := NewProvider(
		WithEndpoint(endpoint.endpoint()),
		WithRoleAlias("iot-credentials-demo"),
		WithCertificatePath(certPath),
		WithPrivateKeyPath(keyPath),
		WithRootCAs(endpoint.rootCAs),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	if _, err := provider.Retrieve(context.Background()); err != nil {
		t.Fatalf("Retrieve before rotation: %v", err)
	}
	if got := endpoint.last(t).ClientCN; got != "device-before-rotation" {
		t.Fatalf("client certificate CN = %q, want device-before-rotation", got)
	}

	// Rotate the files on disk, as a provisioning agent would.
	second := endpoint.clientCA.issueClient(t, "device-after-rotation")
	writeFile(t, certPath, second.certPEM)
	writeFile(t, keyPath, second.keyPEM)

	// Drop the cached credentials and the pooled connection so the next call
	// performs a fresh handshake.
	provider.Invalidate()
	provider.httpClient.CloseIdleConnections()

	if _, err := provider.Retrieve(context.Background()); err != nil {
		t.Fatalf("Retrieve after rotation: %v", err)
	}
	if got := endpoint.last(t).ClientCN; got != "device-after-rotation" {
		t.Errorf("client certificate CN = %q, want device-after-rotation", got)
	}
}

func TestNewProviderValidation(t *testing.T) {
	validPEM := func(t *testing.T) ([]byte, []byte) {
		ca := newCA(t, "Test CA")
		client := ca.issueClient(t, "device")
		return client.certPEM, client.keyPEM
	}

	tests := []struct {
		name string
		opts func(t *testing.T) []Option
		want string
	}{
		{
			name: "missing endpoint",
			opts: func(t *testing.T) []Option {
				cert, key := validPEM(t)
				return []Option{WithRoleAlias("alias"), WithKeyPairPEM(cert, key)}
			},
			want: "endpoint is required",
		},
		{
			name: "missing role alias",
			opts: func(t *testing.T) []Option {
				cert, key := validPEM(t)
				return []Option{WithEndpoint("example.credentials.iot.eu-central-1.amazonaws.com"),
					WithKeyPairPEM(cert, key)}
			},
			want: "role alias is required",
		},
		{
			name: "role alias with a slash",
			opts: func(t *testing.T) []Option {
				cert, key := validPEM(t)
				return []Option{WithEndpoint("example.credentials.iot.eu-central-1.amazonaws.com"),
					WithRoleAlias("alias/../other"), WithKeyPairPEM(cert, key)}
			},
			want: "invalid character",
		},
		{
			name: "missing key material",
			opts: func(*testing.T) []Option {
				return []Option{WithEndpoint("example.credentials.iot.eu-central-1.amazonaws.com"),
					WithRoleAlias("alias")}
			},
			want: "certificate and private key are required",
		},
		{
			name: "certificate without key",
			opts: func(*testing.T) []Option {
				return []Option{WithEndpoint("example.credentials.iot.eu-central-1.amazonaws.com"),
					WithRoleAlias("alias"), WithCertificatePath("/tmp/cert.pem")}
			},
			want: "private key path is required",
		},
		{
			name: "mismatched key pair",
			opts: func(t *testing.T) []Option {
				cert, _ := validPEM(t)
				_, otherKey := validPEM(t)
				return []Option{WithEndpoint("example.credentials.iot.eu-central-1.amazonaws.com"),
					WithRoleAlias("alias"), WithKeyPairPEM(cert, otherKey)}
			},
			want: "loading key pair from memory",
		},
		{
			name: "unreadable certificate file",
			opts: func(*testing.T) []Option {
				return []Option{WithEndpoint("example.credentials.iot.eu-central-1.amazonaws.com"),
					WithRoleAlias("alias"),
					WithCertificatePath("/nonexistent/cert.pem"),
					WithPrivateKeyPath("/nonexistent/key.pem")}
			},
			want: "loading key pair from disk",
		},
		{
			name: "http endpoint",
			opts: func(t *testing.T) []Option {
				cert, key := validPEM(t)
				return []Option{WithEndpoint("http://example.credentials.iot.eu-central-1.amazonaws.com"),
					WithRoleAlias("alias"), WithKeyPairPEM(cert, key)}
			},
			want: "must use https",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewProvider(tc.opts(t)...)
			if err == nil {
				t.Fatal("NewProvider succeeded, want an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestNormalizeEndpoint(t *testing.T) {
	const host = "c2abcdefghij1k.credentials.iot.eu-central-1.amazonaws.com"

	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: host, want: host},
		{in: "https://" + host, want: host},
		{in: "https://" + host + "/", want: host},
		{in: "  " + host + "  ", want: host},
		{in: host + "/", want: host},
		{in: "127.0.0.1:8443", want: "127.0.0.1:8443"},
		{in: "", wantErr: true},
		{in: "   ", wantErr: true},
		{in: "http://" + host, wantErr: true},
		{in: host + "/role-aliases", wantErr: true},
	}

	for _, tc := range tests {
		got, err := normalizeEndpoint(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("normalizeEndpoint(%q) = %q, want an error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("normalizeEndpoint(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("normalizeEndpoint(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestRequestURL(t *testing.T) {
	ca := newCA(t, "Test CA")
	client := ca.issueClient(t, "device")

	provider, err := NewProvider(
		WithEndpoint("https://c2abcdefghij1k.credentials.iot.eu-central-1.amazonaws.com/"),
		WithRoleAlias("My-Role_Alias@1"),
		WithKeyPairPEM(client.certPEM, client.keyPEM),
	)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	want := "https://c2abcdefghij1k.credentials.iot.eu-central-1.amazonaws.com/role-aliases/My-Role_Alias@1/credentials"
	if got := provider.RequestURL(); got != want {
		t.Errorf("RequestURL() = %q, want %q", got, want)
	}
}

func TestContextCancellation(t *testing.T) {
	endpoint := newFakeEndpointWith(t, func(w http.ResponseWriter, _ int) {
		time.Sleep(2 * time.Second)
		writeCredentials(w, time.Now().Add(15*time.Minute))
	})
	provider := newTestProvider(t, endpoint)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if _, err := provider.Retrieve(ctx); err == nil {
		t.Fatal("Retrieve succeeded, want a context deadline error")
	}
}
