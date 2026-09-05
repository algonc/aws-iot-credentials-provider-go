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

// Package iotcredentials provides an AWS SDK for Go v2 credentials provider
// that authenticates with an X.509 client certificate against the AWS IoT Core
// credentials provider, exchanging the certificate for temporary AWS
// credentials.
//
// It is the AWS IoT counterpart to a IAM Roles Anywhere provider: the device
// keeps only a certificate and private key, and never a long-lived access key.
//
// Setup on the AWS side needs an IAM role trusted by credentials.iot.amazonaws.com,
// an AWS IoT role alias pointing at that role, and an AWS IoT policy granting
// iot:AssumeRoleWithCertificate on the role alias to the device certificate.
//
// Usage:
//
//	provider, err := iotcredentials.NewProvider(
//		iotcredentials.WithEndpoint("c2abcdefghij1k.credentials.iot.eu-central-1.amazonaws.com"),
//		iotcredentials.WithRoleAlias("my-role-alias"),
//		iotcredentials.WithCertificatePath("/etc/device/device.pem"),
//		iotcredentials.WithPrivateKeyPath("/etc/device/device.key"),
//	)
//	if err != nil {
//		return err
//	}
//
//	cfg, err := config.LoadDefaultConfig(ctx,
//		config.WithRegion("eu-central-1"),
//		config.WithCredentialsProvider(provider),
//	)
package iotcredentials

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// ProviderName identifies this provider in aws.Credentials.Source.
const ProviderName = "IoTCredentialsProvider"

// version is reported in the User-Agent header.
const version = "0.1.0"

// Provider retrieves temporary AWS credentials from the AWS IoT Core
// credentials provider. It caches them in memory and refetches shortly before
// they expire, so it is safe to install as the only credentials provider of a
// long-running process. Provider is safe for concurrent use.
type Provider struct {
	opts       Options
	httpClient *http.Client
	requestURL string

	// staticCert is set unless the key pair is loaded from files, in which
	// case it is re-read on every handshake to pick up rotation.
	staticCert *tls.Certificate

	mu             sync.Mutex
	cached         aws.Credentials
	cachedLifetime time.Duration
}

// Provider implements the AWS SDK for Go v2 credentials provider interface.
var _ aws.CredentialsProvider = (*Provider)(nil)

// NewProvider validates the options, loads the key pair and returns a ready
// Provider. No network call is made here; credentials are fetched on the first
// Retrieve.
func NewProvider(optFns ...Option) (*Provider, error) {
	opts := Options{}
	for _, fn := range optFns {
		fn(&opts)
	}

	if opts.RefreshMargin <= 0 {
		opts.RefreshMargin = DefaultRefreshMargin
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if !opts.maxRetriesSet && opts.MaxRetries == 0 {
		opts.MaxRetries = DefaultMaxRetries
	}
	if opts.MaxRetries < 0 {
		opts.MaxRetries = 0
	}
	if opts.RetryBaseDelay <= 0 {
		opts.RetryBaseDelay = DefaultRetryBaseDelay
	}
	if opts.now == nil {
		opts.now = time.Now
	}

	host, err := normalizeEndpoint(opts.Endpoint)
	if err != nil {
		return nil, err
	}
	if err := validateRoleAlias(opts.RoleAlias); err != nil {
		return nil, err
	}

	p := &Provider{
		opts: opts,
		requestURL: (&url.URL{
			Scheme: "https",
			Host:   host,
			Path:   "/role-aliases/" + opts.RoleAlias + "/credentials",
		}).String(),
	}

	// Fail fast on bad key material instead of at the first AWS call.
	cert, err := loadKeyPair(opts)
	if err != nil {
		return nil, err
	}

	if opts.HTTPClient != nil {
		p.httpClient = opts.HTTPClient
		return p, nil
	}
	if cert == nil {
		return nil, errors.New("iotcredentials: a certificate and private key are required; " +
			"use WithCertificatePath/WithPrivateKeyPath, WithKeyPairPEM, WithTLSCertificate or WithHTTPClient")
	}

	if opts.CertificatePath == "" || opts.PrivateKeyPath == "" {
		p.staticCert = cert
	}
	p.httpClient = newHTTPClient(p, opts)

	return p, nil
}

// Retrieve returns cached credentials while they are fresh, and otherwise
// fetches a new set from AWS IoT. It satisfies aws.CredentialsProvider.
func (p *Provider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.isFresh(p.opts.now()) {
		return p.cached, nil
	}

	creds, lifetime, err := p.fetch(ctx)
	if err != nil {
		return aws.Credentials{}, err
	}

	p.cached, p.cachedLifetime = creds, lifetime
	return creds, nil
}

// Invalidate drops the cached credentials, forcing the next Retrieve to call
// AWS IoT. Useful when a caller observes an authorization failure it believes
// a fresh session would fix.
func (p *Provider) Invalidate() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.cached, p.cachedLifetime = aws.Credentials{}, 0
}

// RequestURL reports the URL this provider calls, for logging and diagnostics.
func (p *Provider) RequestURL() string { return p.requestURL }

// isFresh reports whether the cached credentials are usable past the refresh
// margin. Callers must hold p.mu.
func (p *Provider) isFresh(now time.Time) bool {
	if !p.cached.HasKeys() || p.cached.Expires.IsZero() {
		return false
	}
	return now.Before(p.cached.Expires.Add(-p.effectiveMargin()))
}

// effectiveMargin caps the configured margin at half the credential lifetime.
// Without the cap, a margin at or above the lifetime — for example the 5 minute
// default against a role alias issuing 900 second credentials, if that default
// were raised — would make every Retrieve miss the cache and hammer AWS IoT.
func (p *Provider) effectiveMargin() time.Duration {
	margin := p.opts.RefreshMargin
	if p.cachedLifetime > 0 && margin > p.cachedLifetime/2 {
		return p.cachedLifetime / 2
	}
	return margin
}

// newHTTPClient builds the mTLS client used to call AWS IoT.
func newHTTPClient(p *Provider, opts Options) *http.Client {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    opts.RootCAs,
		// Resolved at handshake time so that certificates rotated on disk are
		// picked up without a restart.
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if p.staticCert != nil {
				return p.staticCert, nil
			}
			return loadKeyPair(opts)
		},
	}

	return &http.Client{
		Timeout: opts.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
			// Credentials are fetched at most a few times an hour, so idle
			// connections are of little use. Letting them go also means each
			// fetch handshakes afresh and so re-reads a rotated certificate.
			IdleConnTimeout:     30 * time.Second,
			MaxIdleConnsPerHost: 1,
			ForceAttemptHTTP2:   true,
		},
		// Credentials must never be sent to a redirect target.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf("iotcredentials: unexpected redirect to %s", req.URL.Redacted())
		},
	}
}

// loadKeyPair resolves the configured key pair. It returns (nil, nil) when no
// key material is configured at all, which is only valid alongside a
// caller-supplied HTTP client.
func loadKeyPair(opts Options) (*tls.Certificate, error) {
	switch {
	case opts.TLSCertificate != nil:
		return opts.TLSCertificate, nil

	case len(opts.CertificatePEM) > 0 || len(opts.PrivateKeyPEM) > 0:
		if len(opts.CertificatePEM) == 0 {
			return nil, errors.New("iotcredentials: certificate PEM is empty")
		}
		if len(opts.PrivateKeyPEM) == 0 {
			return nil, errors.New("iotcredentials: private key PEM is empty")
		}
		cert, err := tls.X509KeyPair(opts.CertificatePEM, opts.PrivateKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("iotcredentials: loading key pair from memory: %w", err)
		}
		return &cert, nil

	case opts.CertificatePath != "" || opts.PrivateKeyPath != "":
		if opts.CertificatePath == "" {
			return nil, errors.New("iotcredentials: certificate path is required alongside the private key path")
		}
		if opts.PrivateKeyPath == "" {
			return nil, errors.New("iotcredentials: private key path is required alongside the certificate path")
		}
		cert, err := tls.LoadX509KeyPair(opts.CertificatePath, opts.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("iotcredentials: loading key pair from disk: %w", err)
		}
		return &cert, nil

	default:
		return nil, nil
	}
}

// normalizeEndpoint accepts a bare host, or a URL, and returns the host that
// AWS IoT must see in the TLS SNI extension.
func normalizeEndpoint(endpoint string) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", errors.New("iotcredentials: endpoint is required; " +
			"get it with: aws iot describe-endpoint --endpoint-type iot:CredentialProvider")
	}

	if strings.Contains(endpoint, "://") {
		u, err := url.Parse(endpoint)
		if err != nil {
			return "", fmt.Errorf("iotcredentials: parsing endpoint %q: %w", endpoint, err)
		}
		if u.Scheme != "https" {
			return "", fmt.Errorf("iotcredentials: endpoint must use https, got %q", u.Scheme)
		}
		endpoint = u.Host
	}

	endpoint = strings.Trim(endpoint, "/")
	if endpoint == "" || strings.ContainsAny(endpoint, "/ ") {
		return "", fmt.Errorf("iotcredentials: invalid endpoint %q", endpoint)
	}
	return endpoint, nil
}

// validateRoleAlias enforces the character set documented for CreateRoleAlias
// (alphanumeric plus "=", "@" and "-", with "_" also accepted here), so that a
// mistyped alias fails locally rather than silently changing the request path.
func validateRoleAlias(roleAlias string) error {
	if roleAlias == "" {
		return errors.New("iotcredentials: role alias is required")
	}
	if len(roleAlias) > 128 {
		return fmt.Errorf("iotcredentials: role alias must be at most 128 characters, got %d", len(roleAlias))
	}
	for _, r := range roleAlias {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '=', r == '@', r == '-', r == '_':
		default:
			return fmt.Errorf("iotcredentials: role alias %q contains invalid character %q", roleAlias, r)
		}
	}
	return nil
}
