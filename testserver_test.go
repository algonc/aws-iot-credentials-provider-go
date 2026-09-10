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

// This file provides the shared integration-test harness used by
// provider_test.go. It creates an ephemeral PKI, starts a local HTTPS server
// that emulates the AWS IoT credentials endpoint and enforces mTLS, records
// request details for assertions, and supplies helpers for credential
// responses, certificate formats, certificate files, and certificate rotation.
// This keeps the tests realistic and self-contained without contacting AWS or
// requiring permanent certificates.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// keyPair is a certificate together with its private key, in the several
// encodings the tests need.
type keyPair struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
	keyPEM  []byte
}

// newCA creates a self-signed CA, standing in for the customer PKI.
func newCA(t *testing.T, commonName string) keyPair {
	t.Helper()

	return issue(t, nil, &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	})
}

// issueClient issues a leaf client certificate, as the device certificate in
// the shell proof of concept.
func (kp keyPair) issueClient(t *testing.T, commonName string) keyPair {
	t.Helper()

	return issue(t, &kp, &x509.Certificate{
		SerialNumber: serial(t),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
}

// issueServer issues the certificate presented by the fake AWS IoT endpoint.
func (kp keyPair) issueServer(t *testing.T) keyPair {
	t.Helper()

	return issue(t, &kp, &x509.Certificate{
		SerialNumber: serial(t),
		Subject:      pkix.Name{CommonName: "credentials.iot.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "credentials.iot.test"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	})
}

// issue creates a key and certificate, self-signed when parent is nil.
func issue(t *testing.T, parent *keyPair, template *x509.Certificate) keyPair {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	signerCert, signerKey := template, any(key)
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}

	der, err := x509.CreateCertificate(rand.Reader, template, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling key: %v", err)
	}

	return keyPair{
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}
}

// pkcs8KeyPEM re-encodes the private key as PKCS#8.
func (kp keyPair) pkcs8KeyPEM(t *testing.T) []byte {
	t.Helper()

	der, err := x509.MarshalPKCS8PrivateKey(kp.key)
	if err != nil {
		t.Fatalf("marshaling PKCS#8 key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// writeFiles writes the pair to a temporary directory and returns the paths.
func (kp keyPair) writeFiles(t *testing.T) (certPath, keyPath string) {
	t.Helper()

	dir := t.TempDir()
	certPath = filepath.Join(dir, "device.pem")
	keyPath = filepath.Join(dir, "device.key")

	if err := os.WriteFile(certPath, kp.certPEM, 0o600); err != nil {
		t.Fatalf("writing certificate: %v", err)
	}
	if err := os.WriteFile(keyPath, kp.keyPEM, 0o600); err != nil {
		t.Fatalf("writing key: %v", err)
	}
	return certPath, keyPath
}

// recordedRequest captures what the fake endpoint saw.
type recordedRequest struct {
	Method     string
	Path       string
	ThingName  string
	UserAgent  string
	ServerName string
	ClientCN   string
}

// fakeEndpoint is an mTLS server that stands in for the AWS IoT credentials
// provider endpoint. It requires a client certificate, exactly as AWS IoT does.
type fakeEndpoint struct {
	server   *httptest.Server
	rootCAs  *x509.CertPool
	clientCA keyPair

	// respond writes the response for request number n (1-based).
	respond func(w http.ResponseWriter, n int)

	mu       sync.Mutex
	requests []recordedRequest
}

// newFakeEndpoint starts a server that answers with the credentials body AWS
// IoT returns, expiring at the given time.
func newFakeEndpoint(t *testing.T, expiration time.Time) *fakeEndpoint {
	t.Helper()

	f := newFakeEndpointWith(t, nil)
	f.respond = func(w http.ResponseWriter, _ int) {
		writeCredentials(w, expiration)
	}
	return f
}

// newFakeEndpointWith starts a server using a custom response function.
func newFakeEndpointWith(t *testing.T, respond func(w http.ResponseWriter, n int)) *fakeEndpoint {
	t.Helper()

	serverCA := newCA(t, "Test Server CA")
	serverCert := serverCA.issueServer(t)
	clientCA := newCA(t, "Test Customer Device CA")

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(serverCA.cert)
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(clientCA.cert)

	f := &fakeEndpoint{rootCAs: rootCAs, clientCA: clientCA, respond: respond}

	tlsServerCert, err := tls.X509KeyPair(serverCert.certPEM, serverCert.keyPEM)
	if err != nil {
		t.Fatalf("loading server key pair: %v", err)
	}

	f.server = httptest.NewUnstartedServer(http.HandlerFunc(f.handle))
	f.server.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsServerCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		MinVersion:   tls.VersionTLS12,
	}
	f.server.StartTLS()
	t.Cleanup(f.server.Close)

	return f
}

func (f *fakeEndpoint) handle(w http.ResponseWriter, r *http.Request) {
	rec := recordedRequest{
		Method:    r.Method,
		Path:      r.URL.Path,
		ThingName: r.Header.Get("x-amzn-iot-thingname"),
		UserAgent: r.Header.Get("User-Agent"),
	}
	if r.TLS != nil {
		rec.ServerName = r.TLS.ServerName
		if len(r.TLS.PeerCertificates) > 0 {
			rec.ClientCN = r.TLS.PeerCertificates[0].Subject.CommonName
		}
	}

	f.mu.Lock()
	f.requests = append(f.requests, rec)
	n := len(f.requests)
	f.mu.Unlock()

	f.respond(w, n)
}

// endpoint returns the host:port to configure the provider with.
func (f *fakeEndpoint) endpoint() string {
	return f.server.Listener.Addr().String()
}

// count returns how many requests the endpoint received.
func (f *fakeEndpoint) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

// last returns the most recent request.
func (f *fakeEndpoint) last(t *testing.T) recordedRequest {
	t.Helper()

	f.mu.Lock()
	defer f.mu.Unlock()

	if len(f.requests) == 0 {
		t.Fatal("endpoint received no requests")
	}
	return f.requests[len(f.requests)-1]
}

// writeCredentials writes a success body in the AWS IoT response shape.
func writeCredentials(w http.ResponseWriter, expiration time.Time) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"credentials":{` +
		`"accessKeyId":"ASIAEXAMPLE",` +
		`"secretAccessKey":"secret-example",` +
		`"sessionToken":"token-example",` +
		`"expiration":"` + expiration.UTC().Format(time.RFC3339) + `"}}`))
}

// newTestProvider builds a provider wired to the fake endpoint.
func newTestProvider(t *testing.T, f *fakeEndpoint, extra ...Option) *Provider {
	t.Helper()

	client := f.clientCA.issueClient(t, "device-test")

	opts := append([]Option{
		WithEndpoint(f.endpoint()),
		WithRoleAlias("iot-credentials-demo"),
		WithKeyPairPEM(client.certPEM, client.keyPEM),
		WithRootCAs(f.rootCAs),
		WithRetryBaseDelay(time.Millisecond),
	}, extra...)

	provider, err := NewProvider(opts...)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	return provider
}

// tlsCertificate assembles a tls.Certificate directly, as a caller holding a
// crypto.Signer would.
func (kp keyPair) tlsCertificate() tls.Certificate {
	return tls.Certificate{
		Certificate: [][]byte{kp.cert.Raw},
		PrivateKey:  kp.key,
		Leaf:        kp.cert,
	}
}

// writeFile replaces a file's contents.
func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()

	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

func serial(t *testing.T) *big.Int {
	t.Helper()

	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generating serial: %v", err)
	}
	return n
}
