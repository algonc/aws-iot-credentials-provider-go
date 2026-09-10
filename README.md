# AWS IoT Credentials Provider for Go

An [`aws.CredentialsProvider`](https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/aws#CredentialsProvider)
for the AWS SDK for Go v2. It authenticates to the AWS IoT Core credentials
provider with an X.509 device certificate and returns temporary AWS
credentials.

Applications keep a certificate and private key instead of a long-lived AWS
access key.

## Features

- Mutual TLS authentication with an AWS IoT device certificate
- In-memory credential caching with concurrency-safe refresh
- Exponential backoff with jitter for transient failures
- Automatic certificate rotation when credentials are loaded from files
- File, in-memory PEM, `tls.Certificate`, and custom HTTP client inputs
- A command-line helper for AWS `credential_process`

## Requirements

- Go 1.24 or later
- An AWS IoT credentials provider endpoint
- An active AWS IoT certificate and its private key
- An AWS IoT role alias backed by an IAM role
- An AWS IoT policy that allows `iot:AssumeRoleWithCertificate` on the role
  alias

Get the account-specific credentials endpoint with the AWS CLI:

```sh
aws iot describe-endpoint \
  --endpoint-type iot:CredentialProvider \
  --query endpointAddress \
  --output text
```

## Installation

```sh
go get github.com/algonc/aws-iot-credentials-provider-go
```

## Library usage

```go
package main

import (
	"context"
	"log"

	iotcredentials "github.com/algonc/aws-iot-credentials-provider-go"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func main() {
	ctx := context.Background()

	provider, err := iotcredentials.NewProvider(
		iotcredentials.WithEndpoint("c2abcdefghij1k.credentials.iot.eu-central-1.amazonaws.com"),
		iotcredentials.WithRoleAlias("my-role-alias"),
		iotcredentials.WithCertificatePath("/etc/device/device.pem"),
		iotcredentials.WithPrivateKeyPath("/etc/device/device.key"),
	)
	if err != nil {
		log.Fatal(err)
	}

	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("eu-central-1"),
		config.WithCredentialsProvider(provider),
	)
	if err != nil {
		log.Fatal(err)
	}

	_, err = sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		log.Fatal(err)
	}
}
```

`NewProvider` validates its configuration and key material immediately. It does
not make a network request; the first call to `Retrieve` fetches credentials.

### Options

| Option | Description | Default |
|---|---|---|
| `WithEndpoint(string)` | AWS IoT credentials provider endpoint | Required |
| `WithRoleAlias(string)` | Case-sensitive AWS IoT role alias | Required |
| `WithCertificatePath(string)` and `WithPrivateKeyPath(string)` | Certificate and unencrypted private-key PEM files | One key-pair source is required |
| `WithKeyPairPEM(cert, key []byte)` | Certificate and private key held in memory | — |
| `WithTLSCertificate(tls.Certificate)` | Preassembled key pair, including hardware-backed signers | — |
| `WithThingName(string)` | Value of the `x-amzn-iot-thingname` header | Unset |
| `WithRootCAs(*x509.CertPool)` | Roots used to verify the endpoint | System trust store |
| `WithRefreshMargin(time.Duration)` | Time before expiration at which credentials are refreshed | 5 minutes |
| `WithTimeout(time.Duration)` | Timeout for one credentials request | 30 seconds |
| `WithMaxRetries(int)` | Retries after the initial request | 3 |
| `WithRetryBaseDelay(time.Duration)` | Base delay for exponential backoff | 500 milliseconds |
| `WithRetryOnStatus(...int)` | Additional HTTP status codes to retry | None |
| `WithHTTPClient(*http.Client)` | Custom client responsible for mTLS | Internal mTLS client |

File-based keys may be RSA (PKCS#1 or PKCS#8) or ECDSA (SEC1 or PKCS#8).

Set `WithThingName` only when IAM policies use AWS IoT thing policy variables.
The value must match the thing to which the certificate is attached; otherwise,
AWS IoT returns HTTP 403.

## Command-line helper

Install the executable:

```sh
go install github.com/algonc/aws-iot-credentials-provider-go/cmd/iot-credentials@latest
```

Or build it from a source checkout:

```sh
go build ./cmd/iot-credentials
```

Usage:

```text
iot-credentials [flags] [command]
```

| Command | Purpose |
|---|---|
| `credential-process` | Emit AWS `credential_process` JSON; this is the default |
| `env` | Emit POSIX shell export statements |
| `whoami` | Call STS `GetCallerIdentity` with the retrieved credentials |

Example:

```sh
iot-credentials \
  -endpoint "c2abcdefghij1k.credentials.iot.eu-central-1.amazonaws.com" \
  -role-alias "my-role-alias" \
  -cert "/etc/device/device.pem" \
  -key "/etc/device/device.key"
```

Use the helper from an AWS shared configuration file:

```ini
[profile device]
region = eu-central-1
credential_process = /usr/local/bin/iot-credentials -endpoint c2abcdefghij1k.credentials.iot.eu-central-1.amazonaws.com -role-alias my-role-alias -cert /etc/device/device.pem -key /etc/device/device.key
```

The following environment variables can replace the corresponding flags:

| Environment variable | Flag |
|---|---|
| `AWS_IOT_CREDENTIALS_ENDPOINT` | `-endpoint` |
| `AWS_IOT_ROLE_ALIAS` | `-role-alias` |
| `AWS_IOT_CERT` | `-cert` |
| `AWS_IOT_KEY` | `-key` |
| `AWS_IOT_THING_NAME` | `-thing-name` |
| `AWS_IOT_CA_BUNDLE` | `-ca-bundle` |
| `AWS_REGION` or `AWS_DEFAULT_REGION` | `-region` for `whoami` |

Run `iot-credentials -help` for all timeout and retry flags.

## AWS configuration

The provider expects these resources to exist:

1. An IAM role whose trust policy allows `credentials.iot.amazonaws.com` to
   assume it.
2. An AWS IoT role alias that points to the IAM role.
3. An active AWS IoT certificate.
4. An AWS IoT policy attached to the certificate that permits
   `iot:AssumeRoleWithCertificate` on the role alias ARN.

No AWS IoT thing is required unless the policy uses thing attributes or thing
policy variables.

For least privilege, scope the IAM role to the permissions the device needs and
restrict its trust policy with `aws:SourceAccount` and the role alias ARN in
`aws:SourceArn`.

## Runtime behavior

- **Caching:** credentials remain in memory until the refresh margin is
  reached. Concurrent calls share a single refresh. Call `Invalidate` to force
  the next `Retrieve` to fetch new credentials.
- **Refresh margin:** the configured margin is capped at half the credential
  lifetime, preventing short-lived credentials from being refreshed on every
  call.
- **Retries:** transport errors, HTTP 429, and HTTP 5xx responses are retried
  with exponential backoff and equal jitter. Add other retryable statuses with
  `WithRetryOnStatus`.
- **Certificate rotation:** file-based certificate and key pairs are reloaded
  for each TLS handshake, so replacements are picked up without restarting the
  process.
- **Redirects:** HTTP redirects are rejected to prevent credentials from being
  sent to another endpoint.
- **Clock skew:** credentials already expired on arrival return
  `ErrCredentialsExpired`.

## Error handling

Non-successful responses are returned as `*iotcredentials.APIError`, including
the HTTP status, AWS request ID, error type, and a bounded response body.

```go
var apiErr *iotcredentials.APIError
if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusForbidden {
	// Check the certificate policy, role alias, and optional thing name.
}
```

AWS support may require the value in `apiErr.RequestID` when investigating a
failed request.

## Security considerations

- Protect certificate and private-key files with restrictive filesystem
  permissions.
- The built-in file loader accepts unencrypted private keys. Use
  `WithTLSCertificate` for TPM-, HSM-, or PKCS#11-backed keys.
- The CLI writes credentials to standard output. Treat its output as sensitive
  and avoid logging it.
- Use a custom CA pool only when the endpoint is intentionally signed by a CA
  outside the system trust store.

## Testing

```sh
go test ./...
```

The tests use a local HTTPS server with a temporary certificate authority and
mandatory client-certificate verification. They cover request construction,
credential parsing, caching, retries, error mapping, certificate formats, and
certificate rotation without contacting AWS.

## License

Licensed under the [Apache License 2.0](LICENSE).
