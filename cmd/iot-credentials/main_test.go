// Copyright (c) 2026 André Gonçalves
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

type stubCredentialsProvider struct {
	credentials aws.Credentials
	err         error
}

func (p stubCredentialsProvider) Retrieve(context.Context) (aws.Credentials, error) {
	return p.credentials, p.err
}

func TestRunValidation(t *testing.T) {
	for _, key := range []string{
		"AWS_IOT_CREDENTIALS_ENDPOINT",
		"AWS_IOT_ROLE_ALIAS",
		"AWS_IOT_CERT",
		"AWS_IOT_KEY",
		"AWS_IOT_THING_NAME",
		"AWS_IOT_CA_BUNDLE",
		"AWS_REGION",
		"AWS_DEFAULT_REGION",
	} {
		t.Setenv(key, "")
	}

	missingBundle := filepath.Join(t.TempDir(), "missing-ca.pem")
	tests := []struct {
		name       string
		args       []string
		want       string
		wantStderr string
	}{
		{
			name:       "help",
			args:       []string{"-h"},
			want:       "flag: help requested",
			wantStderr: "usage: iot-credentials",
		},
		{
			name:       "too many commands",
			args:       []string{"env", "whoami"},
			want:       "expected at most one command",
			wantStderr: "usage: iot-credentials",
		},
		{
			name: "missing endpoint",
			want: "an endpoint is required",
		},
		{
			name: "missing role alias",
			args: []string{"-endpoint=credentials.iot.test"},
			want: "a role alias is required",
		},
		{
			name: "missing key pair",
			args: []string{
				"-endpoint=credentials.iot.test",
				"-role-alias=test-role",
			},
			want: "a device certificate and private key are required",
		},
		{
			name: "unreadable CA bundle",
			args: []string{
				"-endpoint=credentials.iot.test",
				"-role-alias=test-role",
				"-cert=device.pem",
				"-key=device.key",
				"-ca-bundle=" + missingBundle,
			},
			want: "reading CA bundle",
		},
		{
			name: "invalid retry status",
			args: []string{
				"-endpoint=credentials.iot.test",
				"-role-alias=test-role",
				"-cert=device.pem",
				"-key=device.key",
				"-thing-name=device-1",
				"-retry-on-status=invalid",
			},
			want: "invalid HTTP status code",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			err := run(tc.args, &stdout, &stderr)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("run() error = %v, want it to contain %q", err, tc.want)
			}
			if tc.wantStderr != "" && !strings.Contains(stderr.String(), tc.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tc.wantStderr)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want no output", stdout.String())
			}
		})
	}
}

func TestEmitCredentialProcess(t *testing.T) {
	expiration := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	provider := stubCredentialsProvider{credentials: aws.Credentials{
		AccessKeyID:     "AKIAEXAMPLE",
		SecretAccessKey: "secret-example",
		SessionToken:    "token-example",
		CanExpire:       true,
		Expires:         expiration,
	}}

	var out bytes.Buffer
	if err := emitCredentialProcess(context.Background(), provider, &out); err != nil {
		t.Fatalf("emitCredentialProcess: %v", err)
	}

	var got credentialProcessOutput
	if err := json.NewDecoder(&out).Decode(&got); err != nil {
		t.Fatalf("decoding credential_process output: %v", err)
	}
	want := credentialProcessOutput{
		Version:         1,
		AccessKeyID:     "AKIAEXAMPLE",
		SecretAccessKey: "secret-example",
		SessionToken:    "token-example",
		Expiration:      expiration.Format(time.RFC3339),
	}
	if got != want {
		t.Errorf("credential_process output = %#v, want %#v", got, want)
	}

	wantErr := errors.New("retrieve failed")
	err := emitCredentialProcess(context.Background(), stubCredentialsProvider{err: wantErr}, io.Discard)
	if !errors.Is(err, wantErr) {
		t.Errorf("error = %v, want %v", err, wantErr)
	}
}

func TestEmitEnv(t *testing.T) {
	expiration := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	provider := stubCredentialsProvider{credentials: aws.Credentials{
		AccessKeyID:     "AKIAEXAMPLE",
		SecretAccessKey: "sec'ret",
		SessionToken:    "tok'en",
		CanExpire:       true,
		Expires:         expiration,
	}}

	var out bytes.Buffer
	if err := emitEnv(context.Background(), provider, &out); err != nil {
		t.Fatalf("emitEnv: %v", err)
	}
	for _, want := range []string{
		"export AWS_ACCESS_KEY_ID='AKIAEXAMPLE'\n",
		"export AWS_SECRET_ACCESS_KEY='sec'\\''ret'\n",
		"export AWS_SESSION_TOKEN='tok'\\''en'\n",
		"# expires " + expiration.Format(time.RFC3339) + " (in ",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output = %q, want it to contain %q", out.String(), want)
		}
	}

	wantErr := errors.New("retrieve failed")
	err := emitEnv(context.Background(), stubCredentialsProvider{err: wantErr}, io.Discard)
	if !errors.Is(err, wantErr) {
		t.Errorf("error = %v, want %v", err, wantErr)
	}
}

func TestWhoamiRequiresRegion(t *testing.T) {
	err := whoami(context.Background(), nil, "", io.Discard)
	if err == nil || !strings.Contains(err.Error(), "a region is required") {
		t.Fatalf("whoami() error = %v, want missing-region error", err)
	}
}

func TestLoadCABundle(t *testing.T) {
	server := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(server.Close)

	validPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: server.Certificate().Raw,
	})
	validPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(validPath, validPEM, 0o600); err != nil {
		t.Fatalf("writing valid CA bundle: %v", err)
	}

	t.Run("valid", func(t *testing.T) {
		pool, err := loadCABundle(validPath)
		if err != nil {
			t.Fatalf("loadCABundle: %v", err)
		}
		if pool == nil {
			t.Fatal("loadCABundle returned a nil pool")
		}
	})

	t.Run("missing", func(t *testing.T) {
		_, err := loadCABundle(filepath.Join(t.TempDir(), "missing.pem"))
		if err == nil || !strings.Contains(err.Error(), "reading CA bundle") {
			t.Fatalf("loadCABundle error = %v, want read error", err)
		}
	})

	t.Run("invalid PEM", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "invalid.pem")
		if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
			t.Fatalf("writing invalid CA bundle: %v", err)
		}
		_, err := loadCABundle(path)
		if err == nil || !strings.Contains(err.Error(), "no certificates found") {
			t.Fatalf("loadCABundle error = %v, want certificate error", err)
		}
	})
}

func TestParseStatusCodes(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []int
		wantErr bool
	}{
		{name: "list", input: "403, 500", want: []int{403, 500}},
		{name: "empty fields", input: " ,403,, ", want: []int{403}},
		{name: "empty", input: ""},
		{name: "not a number", input: "invalid", wantErr: true},
		{name: "below HTTP range", input: "99", wantErr: true},
		{name: "above HTTP range", input: "600", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseStatusCodes(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseStatusCodes(%q) succeeded, want error", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseStatusCodes(%q): %v", tc.input, err)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("parseStatusCodes(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestFirstNonEmpty(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   string
	}{
		{name: "first", values: []string{"one", "two"}, want: "one"},
		{name: "fallback", values: []string{"", "two"}, want: "two"},
		{name: "all empty", values: []string{"", ""}},
		{name: "no values"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := firstNonEmpty(tc.values...); got != tc.want {
				t.Errorf("firstNonEmpty(%q) = %q, want %q", tc.values, got, tc.want)
			}
		})
	}
}

func TestShellQuote(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "", want: "''"},
		{input: "plain", want: "'plain'"},
		{input: "sec'ret", want: "'sec'\\''ret'"},
	}

	for _, tc := range tests {
		if got := shellQuote(tc.input); got != tc.want {
			t.Errorf("shellQuote(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
