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

// Command iot-credentials exchanges an AWS IoT device certificate for
// temporary AWS credentials.
//
// It can act as an AWS CLI/SDK credential_process helper, print shell exports,
// or prove the credentials work by calling sts:GetCallerIdentity.
package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	iotcredentials "github.com/algonc/aws-iot-credentials-provider-go"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// credentialProcessOutput is the JSON the AWS CLI and SDKs expect from a
// credential_process helper.
type credentialProcessOutput struct {
	Version         int    `json:"Version"`
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken"`
	Expiration      string `json:"Expiration"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)

		// Surface the AWS status code for scripting.
		var apiErr *iotcredentials.APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == 403 {
			fmt.Fprintln(os.Stderr,
				"hint: 403 usually means the certificate policy does not allow "+
					"iot:AssumeRoleWithCertificate on this role alias, or the thing name does not match")
		}
		os.Exit(1)
	}
}

func run() error {
	fs := flag.NewFlagSet("iot-credentials", flag.ContinueOnError)

	endpoint := fs.String("endpoint", os.Getenv("AWS_IOT_CREDENTIALS_ENDPOINT"),
		"iot:CredentialProvider endpoint (env AWS_IOT_CREDENTIALS_ENDPOINT)")
	roleAlias := fs.String("role-alias", os.Getenv("AWS_IOT_ROLE_ALIAS"),
		"AWS IoT role alias, case sensitive (env AWS_IOT_ROLE_ALIAS)")
	certPath := fs.String("cert", os.Getenv("AWS_IOT_CERT"),
		"device certificate PEM file (env AWS_IOT_CERT)")
	keyPath := fs.String("key", os.Getenv("AWS_IOT_KEY"),
		"device private key PEM file (env AWS_IOT_KEY)")
	thingName := fs.String("thing-name", os.Getenv("AWS_IOT_THING_NAME"),
		"value for the x-amzn-iot-thingname header (env AWS_IOT_THING_NAME)")
	caBundle := fs.String("ca-bundle", os.Getenv("AWS_IOT_CA_BUNDLE"),
		"PEM file of root CAs used to verify the endpoint (default: system trust store)")
	region := fs.String("region", firstNonEmpty(os.Getenv("AWS_REGION"), os.Getenv("AWS_DEFAULT_REGION")),
		"AWS region, used by the whoami command (env AWS_REGION)")
	timeout := fs.Duration("timeout", iotcredentials.DefaultTimeout, "timeout for a single request")
	maxRetries := fs.Int("max-retries", iotcredentials.DefaultMaxRetries, "retries after the first attempt")
	retryOn := fs.String("retry-on-status", "",
		"comma separated extra HTTP status codes to retry, e.g. 403,400 while a fresh setup propagates")

	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprintf(out, "usage: iot-credentials [flags] [command]\n\ncommands:\n")
		fmt.Fprintf(out, "  credential-process  emit credential_process JSON for the AWS CLI/SDKs (default)\n")
		fmt.Fprintf(out, "  env                 emit shell export statements\n")
		fmt.Fprintf(out, "  whoami              call sts:GetCallerIdentity with the credentials\n\nflags:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}

	command := "credential-process"
	switch fs.NArg() {
	case 0:
	case 1:
		command = fs.Arg(0)
	default:
		fs.Usage()
		return fmt.Errorf("expected at most one command, got %d", fs.NArg())
	}

	// Checked here so the message names flags rather than library options.
	switch {
	case *endpoint == "":
		return errors.New("an endpoint is required; pass -endpoint or set AWS_IOT_CREDENTIALS_ENDPOINT " +
			"(get it with: aws iot describe-endpoint --endpoint-type iot:CredentialProvider)")
	case *roleAlias == "":
		return errors.New("a role alias is required; pass -role-alias or set AWS_IOT_ROLE_ALIAS")
	case *certPath == "" || *keyPath == "":
		return errors.New("a device certificate and private key are required; " +
			"pass -cert and -key, or set AWS_IOT_CERT and AWS_IOT_KEY")
	}

	opts := []iotcredentials.Option{
		iotcredentials.WithEndpoint(*endpoint),
		iotcredentials.WithRoleAlias(*roleAlias),
		iotcredentials.WithCertificatePath(*certPath),
		iotcredentials.WithPrivateKeyPath(*keyPath),
		iotcredentials.WithTimeout(*timeout),
		iotcredentials.WithMaxRetries(*maxRetries),
	}
	if *thingName != "" {
		opts = append(opts, iotcredentials.WithThingName(*thingName))
	}
	if *caBundle != "" {
		pool, err := loadCABundle(*caBundle)
		if err != nil {
			return err
		}
		opts = append(opts, iotcredentials.WithRootCAs(pool))
	}
	if *retryOn != "" {
		codes, err := parseStatusCodes(*retryOn)
		if err != nil {
			return err
		}
		opts = append(opts, iotcredentials.WithRetryOnStatus(codes...))
	}

	provider, err := iotcredentials.NewProvider(opts...)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch command {
	case "credential-process":
		return emitCredentialProcess(ctx, provider)
	case "env":
		return emitEnv(ctx, provider)
	case "whoami":
		return whoami(ctx, provider, *region)
	default:
		fs.Usage()
		return fmt.Errorf("unknown command %q", command)
	}
}

func emitCredentialProcess(ctx context.Context, provider *iotcredentials.Provider) error {
	creds, err := provider.Retrieve(ctx)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	// G117: AWS credential_process requires temporary credentials on stdout.
	//nolint:gosec
	return enc.Encode(credentialProcessOutput{
		Version:         1,
		AccessKeyID:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.SessionToken,
		Expiration:      creds.Expires.UTC().Format(time.RFC3339),
	})
}

func emitEnv(ctx context.Context, provider *iotcredentials.Provider) error {
	creds, err := provider.Retrieve(ctx)
	if err != nil {
		return err
	}

	fmt.Printf("export AWS_ACCESS_KEY_ID=%s\n", shellQuote(creds.AccessKeyID))
	fmt.Printf("export AWS_SECRET_ACCESS_KEY=%s\n", shellQuote(creds.SecretAccessKey))
	fmt.Printf("export AWS_SESSION_TOKEN=%s\n", shellQuote(creds.SessionToken))
	fmt.Printf("# expires %s (in %s)\n",
		creds.Expires.UTC().Format(time.RFC3339),
		time.Until(creds.Expires).Round(time.Second))
	return nil
}

func whoami(ctx context.Context, provider *iotcredentials.Provider, region string) error {
	if region == "" {
		return errors.New("a region is required for whoami; pass -region or set AWS_REGION")
	}

	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(provider),
		// The device has no AWS config or profile; do not read any. These must
		// be non-nil empty slices, because the SDK reads a nil slice as "option
		// not set" and falls back to the default file locations.
		config.WithSharedConfigFiles([]string{}),
		config.WithSharedCredentialsFiles([]string{}),
	)
	if err != nil {
		return fmt.Errorf("loading AWS config: %w", err)
	}

	identity, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return fmt.Errorf("sts:GetCallerIdentity: %w", err)
	}

	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return err
	}

	fmt.Printf("Endpoint:   %s\n", provider.RequestURL())
	fmt.Printf("Account:    %s\n", aws.ToString(identity.Account))
	fmt.Printf("ARN:        %s\n", aws.ToString(identity.Arn))
	fmt.Printf("UserId:     %s\n", aws.ToString(identity.UserId))
	fmt.Printf("Expiration: %s (in %s)\n",
		creds.Expires.UTC().Format(time.RFC3339),
		time.Until(creds.Expires).Round(time.Second))
	return nil
}

func loadCABundle(path string) (*x509.CertPool, error) {
	// G703: this CLI intentionally accepts an operator-selected CA bundle path.
	pem, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("reading CA bundle: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates found in CA bundle %s", path)
	}
	return pool, nil
}

func parseStatusCodes(list string) ([]int, error) {
	var codes []int
	for _, field := range strings.Split(list, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}

		var code int
		if _, err := fmt.Sscanf(field, "%d", &code); err != nil || code < 100 || code > 599 {
			return nil, fmt.Errorf("invalid HTTP status code %q", field)
		}
		codes = append(codes, code)
	}
	return codes, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// shellQuote makes a credential safe to paste into a POSIX shell.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
