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

//go:build integration

// These tests call the real AWS IoT Core credentials provider and AWS STS with
// a real device certificate. They are excluded from a normal `go test ./...` by
// the integration build tag.
//
// Set the required values individually:
//
//	export AWS_IOT_CREDENTIALS_ENDPOINT=myaccountendpoint.credentials.iot.eu-east-1.amazonaws.com
//	export AWS_IOT_ROLE_ALIAS=my-role-alias
//	export AWS_IOT_CERT=/etc/device/device.pem
//	export AWS_IOT_KEY=/etc/device/device.key
//	export AWS_REGION=eu-east-1
//
// Callers already authenticated to the target AWS account can retrieve its
// credentials provider endpoint with the AWS CLI instead of setting it
// manually:
//
//	export AWS_IOT_CREDENTIALS_ENDPOINT=$(aws iot describe-endpoint \
//	    --endpoint-type iot:CredentialProvider --query endpointAddress --output text)
//
// Optional:
//
//	AWS_IOT_THING_NAME   sent as x-amzn-iot-thingname; must match the thing the
//	                     certificate is attached to, or AWS IoT returns 403
//	AWS_IOT_CA_BUNDLE    root CAs for verifying the endpoint, e.g. AmazonRootCA1.pem
//
// The tests only read: they fetch credentials and call sts:GetCallerIdentity.
// They create and modify nothing in your account.
//
// Run them with:
//
//	go test -tags integration -v -run Integration .
package iotcredentials_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	iotcredentials "github.com/algonc/aws-iot-credentials-provider-go"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// testConfig is the real-world configuration read from the environment.
type testConfig struct {
	endpoint  string
	roleAlias string
	certPath  string
	keyPath   string
	thingName string
	caBundle  string
	region    string
}

// loadTestConfig resolves the environment, skipping the test with actionable
// instructions when something required is missing.
func loadTestConfig(t *testing.T) testConfig {
	t.Helper()

	cfg := testConfig{
		endpoint:  os.Getenv("AWS_IOT_CREDENTIALS_ENDPOINT"),
		roleAlias: os.Getenv("AWS_IOT_ROLE_ALIAS"),
		certPath:  os.Getenv("AWS_IOT_CERT"),
		keyPath:   os.Getenv("AWS_IOT_KEY"),
		thingName: os.Getenv("AWS_IOT_THING_NAME"),
		caBundle:  os.Getenv("AWS_IOT_CA_BUNDLE"),
		region:    firstNonEmpty(os.Getenv("AWS_REGION"), os.Getenv("AWS_DEFAULT_REGION")),
	}

	var missing []string
	if cfg.endpoint == "" {
		missing = append(missing, "AWS_IOT_CREDENTIALS_ENDPOINT")
	}
	if cfg.roleAlias == "" {
		missing = append(missing, "AWS_IOT_ROLE_ALIAS")
	}
	if cfg.certPath == "" {
		missing = append(missing, "AWS_IOT_CERT")
	}
	if cfg.keyPath == "" {
		missing = append(missing, "AWS_IOT_KEY")
	}
	if len(missing) > 0 {
		t.Skipf("set %s to run the integration tests; see the comment at the top of %s",
			strings.Join(missing, ", "), "provider_integration_test.go")
	}

	for _, path := range []string{cfg.certPath, cfg.keyPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("%s is not readable: %v", path, err)
		}
	}

	t.Logf("endpoint:   %s", cfg.endpoint)
	t.Logf("role alias: %s", cfg.roleAlias)
	t.Logf("certificate: %s", cfg.certPath)
	if cfg.thingName != "" {
		t.Logf("thing name: %s", cfg.thingName)
	}
	return cfg
}

// options builds the provider options for this configuration.
func (c testConfig) options(t *testing.T, extra ...iotcredentials.Option) []iotcredentials.Option {
	t.Helper()

	opts := []iotcredentials.Option{
		iotcredentials.WithEndpoint(c.endpoint),
		iotcredentials.WithRoleAlias(c.roleAlias),
		iotcredentials.WithCertificatePath(c.certPath),
		iotcredentials.WithPrivateKeyPath(c.keyPath),
	}
	if c.thingName != "" {
		opts = append(opts, iotcredentials.WithThingName(c.thingName))
	}
	if c.caBundle != "" {
		caPEM, err := os.ReadFile(c.caBundle)
		if err != nil {
			t.Fatalf("reading AWS_IOT_CA_BUNDLE: %v", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			t.Fatalf("no certificates found in AWS_IOT_CA_BUNDLE %s", c.caBundle)
		}
		opts = append(opts, iotcredentials.WithRootCAs(pool))
	}
	return append(opts, extra...)
}

// newProvider builds a provider for this configuration.
func (c testConfig) newProvider(t *testing.T, extra ...iotcredentials.Option) *iotcredentials.Provider {
	t.Helper()

	provider, err := iotcredentials.NewProvider(c.options(t, extra...)...)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	return provider
}

// TestIntegrationDeviceCertificate reports what the certificate actually says.
// An expired certificate, or one issued by a CA that was never registered, is a
// common cause of a 403 from the credentials provider, so this runs first.
func TestIntegrationDeviceCertificate(t *testing.T) {
	cfg := loadTestConfig(t)

	pemBytes, err := os.ReadFile(cfg.certPath)
	if err != nil {
		t.Fatalf("reading certificate: %v", err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatalf("%s contains no PEM block", cfg.certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}

	t.Logf("subject:    %s", cert.Subject)
	t.Logf("issuer:     %s", cert.Issuer)
	t.Logf("serial:     %x", cert.SerialNumber)
	t.Logf("key type:   %s", cert.PublicKeyAlgorithm)
	t.Logf("not before: %s", cert.NotBefore.UTC().Format(time.RFC3339))
	t.Logf("not after:  %s", cert.NotAfter.UTC().Format(time.RFC3339))

	now := time.Now()
	if now.Before(cert.NotBefore) {
		t.Fatalf("certificate is not valid until %s; check the system clock",
			cert.NotBefore.UTC().Format(time.RFC3339))
	}
	if now.After(cert.NotAfter) {
		t.Fatalf("certificate expired on %s", cert.NotAfter.UTC().Format(time.RFC3339))
	}
	t.Logf("valid for another %d days", int(time.Until(cert.NotAfter).Hours()/24))
}

// TestIntegrationRetrieve fetches credentials from AWS IoT and checks their
// shape. Secret values are never logged, only their lengths.
func TestIntegrationRetrieve(t *testing.T) {
	cfg := loadTestConfig(t)
	provider := cfg.newProvider(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	t.Logf("GET %s", provider.RequestURL())

	start := time.Now()
	creds, err := provider.Retrieve(ctx)
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	elapsed := time.Since(start)

	if creds.AccessKeyID == "" {
		t.Error("AccessKeyID is empty")
	}
	if creds.SecretAccessKey == "" {
		t.Error("SecretAccessKey is empty")
	}
	if creds.SessionToken == "" {
		t.Error("SessionToken is empty")
	}
	if creds.Source != iotcredentials.ProviderName {
		t.Errorf("Source = %q, want %q", creds.Source, iotcredentials.ProviderName)
	}
	if !creds.CanExpire {
		t.Error("CanExpire = false, want true")
	}

	lifetime := time.Until(creds.Expires)
	if lifetime <= 0 {
		t.Fatalf("credentials expire at %s, which is in the past", creds.Expires)
	}
	// A role alias caps credentialDurationSeconds at 43200.
	if lifetime > 12*time.Hour+time.Minute {
		t.Errorf("lifetime %s exceeds the 12 hour maximum", lifetime)
	}

	t.Logf("fetched in %s", elapsed.Round(time.Millisecond))
	t.Logf("access key id: %s", creds.AccessKeyID)
	t.Logf("secret key:    %d characters (not logged)", len(creds.SecretAccessKey))
	t.Logf("session token: %d characters (not logged)", len(creds.SessionToken))
	t.Logf("expires:       %s (in %s)",
		creds.Expires.UTC().Format(time.RFC3339), lifetime.Round(time.Second))
	t.Logf("this lifetime reflects credentialDurationSeconds on role alias %s", cfg.roleAlias)

	// Temporary credentials from STS use the ASIA prefix. Logged rather than
	// asserted, since the prefix is not part of any API contract.
	if !strings.HasPrefix(creds.AccessKeyID, "ASIA") {
		t.Logf("note: access key id does not start with ASIA, which is unusual for temporary credentials")
	}
}

// TestIntegrationCallerIdentity proves the credentials are real by signing an
// AWS request with them.
func TestIntegrationCallerIdentity(t *testing.T) {
	cfg := loadTestConfig(t)
	if cfg.region == "" {
		t.Skip("set AWS_REGION to call sts:GetCallerIdentity")
	}

	provider := cfg.newProvider(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(cfg.region),
		awsconfig.WithCredentialsProvider(provider),
		// Ignore any ambient profile, so a pass here cannot be produced by
		// administrative credentials that happen to be configured. These must
		// be non-nil empty slices: the SDK reads a nil slice as "option not
		// set" and falls back to the default file locations.
		awsconfig.WithSharedConfigFiles([]string{}),
		awsconfig.WithSharedCredentialsFiles([]string{}),
	)
	if err != nil {
		t.Fatalf("LoadDefaultConfig: %v", err)
	}

	identity, err := sts.NewFromConfig(awsCfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		t.Fatalf("sts:GetCallerIdentity: %v", err)
	}

	account := aws.ToString(identity.Account)
	arn := aws.ToString(identity.Arn)

	t.Logf("account: %s", account)
	t.Logf("arn:     %s", arn)
	t.Logf("user id: %s", aws.ToString(identity.UserId))

	if account == "" {
		t.Error("account is empty")
	}
	if !strings.Contains(arn, ":assumed-role/") {
		t.Errorf("arn %q is not an assumed role; the credentials did not come from the role alias", arn)
	}
}

// TestIntegrationCaching checks that a second Retrieve is served from memory and
// that Invalidate forces a new call.
func TestIntegrationCaching(t *testing.T) {
	cfg := loadTestConfig(t)
	provider := cfg.newProvider(t)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	first, err := provider.Retrieve(ctx)
	if err != nil {
		t.Fatalf("first Retrieve: %v", err)
	}

	start := time.Now()
	second, err := provider.Retrieve(ctx)
	if err != nil {
		t.Fatalf("second Retrieve: %v", err)
	}
	cachedCall := time.Since(start)

	if first != second {
		t.Error("second Retrieve returned different credentials, so the cache was missed")
	}
	// A cache hit takes microseconds; a round trip to AWS IoT takes tens of
	// milliseconds at best. The bound is loose so this cannot flake.
	if cachedCall > 5*time.Millisecond {
		t.Errorf("second Retrieve took %s, which is too slow to have been a cache hit", cachedCall)
	}
	t.Logf("cache hit in %s", cachedCall)

	provider.Invalidate()

	third, err := provider.Retrieve(ctx)
	if err != nil {
		t.Fatalf("Retrieve after Invalidate: %v", err)
	}
	if third.AccessKeyID == "" {
		t.Error("Retrieve after Invalidate returned no access key id")
	}
	t.Logf("after Invalidate, expires %s", third.Expires.UTC().Format(time.RFC3339))
}

// TestIntegrationUnknownRoleAlias checks the error path against real AWS. An
// alias that does not exist must produce an *APIError carrying the status and,
// where AWS supplies one, a request id to quote in a support case.
func TestIntegrationUnknownRoleAlias(t *testing.T) {
	cfg := loadTestConfig(t)

	cfg.roleAlias = fmt.Sprintf("nonexistent-%d", time.Now().UnixNano())
	// The certificate policy cannot grant access to this alias, so do not spend
	// retries on the failure.
	provider := cfg.newProvider(t, iotcredentials.WithMaxRetries(0))

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	_, err := provider.Retrieve(ctx)
	if err == nil {
		t.Fatalf("Retrieve succeeded for role alias %s, which should not exist", cfg.roleAlias)
	}

	var apiErr *iotcredentials.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error is %T (%v), want *APIError", err, err)
	}

	t.Logf("status:     %d", apiErr.StatusCode)
	t.Logf("message:    %s", apiErr.Message)
	t.Logf("error type: %s", apiErr.ErrorType)
	t.Logf("request id: %s", apiErr.RequestID)

	switch apiErr.StatusCode {
	case http.StatusForbidden, http.StatusNotFound:
		// 403 is what AWS IoT returns when the certificate policy does not
		// authorize the alias, which is the case for an alias that does not
		// exist. 404 is accepted in case that behavior differs.
	default:
		t.Errorf("StatusCode = %d, want 403 or 404", apiErr.StatusCode)
	}
}

// TestIntegrationThingNameMismatch confirms that a wrong thing name is rejected,
// which is the documented behavior and an easy misconfiguration to hit. It only
// runs when a thing name is configured, because a certificate with no thing
// attached ignores the header.
func TestIntegrationThingNameMismatch(t *testing.T) {
	cfg := loadTestConfig(t)
	if cfg.thingName == "" {
		t.Skip("set AWS_IOT_THING_NAME to test thing name handling")
	}

	cfg.thingName = fmt.Sprintf("nonexistent-thing-%d", time.Now().UnixNano())
	provider := cfg.newProvider(t, iotcredentials.WithMaxRetries(0))

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	_, err := provider.Retrieve(ctx)
	if err == nil {
		t.Fatal("Retrieve succeeded with a thing name that does not match the certificate, want 403")
	}

	var apiErr *iotcredentials.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error is %T (%v), want *APIError", err, err)
	}
	if apiErr.StatusCode != http.StatusForbidden {
		t.Errorf("StatusCode = %d, want 403", apiErr.StatusCode)
	}
	t.Logf("status %d: %s", apiErr.StatusCode, apiErr.Message)
}

// TestIntegrationConcurrentRetrieve checks that many goroutines starting at once
// on a cold provider produce one set of credentials rather than a burst of calls
// to AWS IoT.
func TestIntegrationConcurrentRetrieve(t *testing.T) {
	cfg := loadTestConfig(t)
	provider := cfg.newProvider(t)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	const goroutines = 10
	type result struct {
		creds aws.Credentials
		err   error
	}
	results := make(chan result, goroutines)

	for range goroutines {
		go func() {
			creds, err := provider.Retrieve(ctx)
			results <- result{creds, err}
		}()
	}

	var first aws.Credentials
	for i := range goroutines {
		r := <-results
		if r.err != nil {
			t.Fatalf("concurrent Retrieve: %v", r.err)
		}
		if i == 0 {
			first = r.creds
			continue
		}
		if r.creds != first {
			t.Error("concurrent callers received different credentials")
		}
	}

	t.Logf("%d goroutines shared one set of credentials expiring %s",
		goroutines, first.Expires.UTC().Format(time.RFC3339))
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
