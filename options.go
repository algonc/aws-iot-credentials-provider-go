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
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"time"
)

// Defaults applied by NewProvider when the corresponding option is not set.
const (
	// DefaultRefreshMargin is how long before expiration cached credentials
	// are considered stale and refetched.
	DefaultRefreshMargin = 5 * time.Minute

	// DefaultTimeout bounds a single credentials request, including the TLS
	// handshake. It is only used when no custom HTTP client is supplied.
	DefaultTimeout = 30 * time.Second

	// DefaultMaxRetries is the number of retries (in addition to the initial
	// attempt) for transient failures.
	DefaultMaxRetries = 3

	// DefaultRetryBaseDelay is the base of the exponential backoff.
	DefaultRetryBaseDelay = 500 * time.Millisecond
)

// Options is the resolved configuration of a Provider. Use the With* functions
// rather than building this directly.
type Options struct {
	// Endpoint is the account-specific credentials provider endpoint, as
	// returned by:
	//
	//	aws iot describe-endpoint --endpoint-type iot:CredentialProvider
	//
	// For example "c2abcdefghij1k.credentials.iot.eu-central-1.amazonaws.com".
	// A "https://" prefix and trailing slashes are tolerated.
	Endpoint string

	// RoleAlias is the AWS IoT role alias to assume. Case sensitive.
	RoleAlias string

	// ThingName is sent in the x-amzn-iot-thingname header. It is only
	// required when policies reference thing attributes. When set it must
	// match the thing the certificate is attached to, otherwise AWS IoT
	// returns 403.
	ThingName string

	// CertificatePath and PrivateKeyPath point at unencrypted PEM files. The
	// certificate file may contain an intermediate chain after the leaf.
	//
	// When paths are used the key pair is re-read on every TLS handshake, so
	// a rotated certificate is picked up without restarting the process.
	CertificatePath string
	PrivateKeyPath  string

	// CertificatePEM and PrivateKeyPEM hold the key pair in memory as an
	// alternative to CertificatePath / PrivateKeyPath.
	CertificatePEM []byte
	PrivateKeyPEM  []byte

	// TLSCertificate supplies the key pair directly. Use this when the
	// private key lives in a TPM, HSM or PKCS#11 token and is only reachable
	// through a crypto.Signer.
	TLSCertificate *tls.Certificate

	// RootCAs verifies the AWS IoT endpoint. Nil means the system trust
	// store, which already trusts the Amazon root CAs.
	RootCAs *x509.CertPool

	// RefreshMargin, Timeout, MaxRetries and RetryBaseDelay fall back to the
	// Default* constants when zero.
	RefreshMargin  time.Duration
	Timeout        time.Duration
	MaxRetries     int
	RetryBaseDelay time.Duration

	// ExtraRetryStatusCodes are retried in addition to 429 and 5xx.
	ExtraRetryStatusCodes []int

	// maxRetriesSet distinguishes an explicit WithMaxRetries(0), which
	// disables retrying, from MaxRetries being left at its zero value.
	maxRetriesSet bool

	// HTTPClient replaces the internally constructed client. Its transport is
	// responsible for presenting the client certificate; the key pair options
	// above are then ignored for the TLS handshake.
	HTTPClient *http.Client

	// now is injectable for tests.
	now func() time.Time
}

// Option configures a Provider.
type Option func(*Options)

// WithEndpoint sets the account-specific iot:CredentialProvider endpoint.
func WithEndpoint(endpoint string) Option {
	return func(o *Options) { o.Endpoint = endpoint }
}

// WithRoleAlias sets the AWS IoT role alias to assume.
func WithRoleAlias(roleAlias string) Option {
	return func(o *Options) { o.RoleAlias = roleAlias }
}

// WithThingName sets the x-amzn-iot-thingname header.
func WithThingName(thingName string) Option {
	return func(o *Options) { o.ThingName = thingName }
}

// WithCertificatePath sets the PEM file holding the device certificate, and
// optionally its intermediate chain.
func WithCertificatePath(path string) Option {
	return func(o *Options) { o.CertificatePath = path }
}

// WithPrivateKeyPath sets the unencrypted PEM file holding the device private
// key. RSA (PKCS#1, PKCS#8) and ECDSA (SEC1, PKCS#8) keys are supported.
func WithPrivateKeyPath(path string) Option {
	return func(o *Options) { o.PrivateKeyPath = path }
}

// WithKeyPairPEM supplies the certificate and private key as PEM bytes.
func WithKeyPairPEM(certPEM, keyPEM []byte) Option {
	return func(o *Options) {
		o.CertificatePEM = certPEM
		o.PrivateKeyPEM = keyPEM
	}
}

// WithTLSCertificate supplies an already assembled key pair, for example one
// backed by a hardware crypto.Signer.
func WithTLSCertificate(cert tls.Certificate) Option {
	return func(o *Options) { o.TLSCertificate = &cert }
}

// WithRootCAs sets the pool used to verify the AWS IoT endpoint.
func WithRootCAs(pool *x509.CertPool) Option {
	return func(o *Options) { o.RootCAs = pool }
}

// WithRefreshMargin sets how long before expiration credentials are refetched.
func WithRefreshMargin(d time.Duration) Option {
	return func(o *Options) { o.RefreshMargin = d }
}

// WithTimeout bounds a single credentials request.
func WithTimeout(d time.Duration) Option {
	return func(o *Options) { o.Timeout = d }
}

// WithMaxRetries sets the number of retries after the initial attempt. Zero
// disables retrying.
func WithMaxRetries(n int) Option {
	return func(o *Options) {
		o.MaxRetries = n
		o.maxRetriesSet = true
	}
}

// WithRetryBaseDelay sets the base of the exponential backoff.
func WithRetryBaseDelay(d time.Duration) Option {
	return func(o *Options) { o.RetryBaseDelay = d }
}

// WithRetryOnStatus marks additional status codes as retryable.
//
// Useful right after provisioning: while an IAM role, role alias or
// certificate policy is still propagating, AWS IoT can answer 403 or 400 for
// a few seconds. Retrying those is not appropriate in steady state, because
// they otherwise indicate a genuine authorization problem.
func WithRetryOnStatus(codes ...int) Option {
	return func(o *Options) {
		o.ExtraRetryStatusCodes = append(o.ExtraRetryStatusCodes, codes...)
	}
}

// WithHTTPClient replaces the internally constructed HTTP client. The caller's
// transport must present the device certificate.
func WithHTTPClient(client *http.Client) Option {
	return func(o *Options) { o.HTTPClient = client }
}

// withClock overrides the time source, for tests.
func withClock(now func() time.Time) Option {
	return func(o *Options) { o.now = now }
}
