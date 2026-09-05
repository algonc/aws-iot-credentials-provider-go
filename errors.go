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
	"errors"
	"fmt"
	"net/http"
)

// maxErrorBodyBytes bounds how much of a failed response body is retained.
const maxErrorBodyBytes = 2048

// APIError is returned when the AWS IoT credentials provider answers with a
// non-200 status.
type APIError struct {
	// StatusCode is the HTTP status returned by AWS IoT.
	StatusCode int

	// Message is the "message" field of the error body, when present.
	Message string

	// RequestID and ErrorType come from the x-amzn-RequestId and
	// x-amzn-ErrorType response headers. Quote the request ID in AWS support
	// cases.
	RequestID string
	ErrorType string

	// Body is the raw response body, truncated.
	Body string
}

func (e *APIError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = e.Body
	}
	if msg == "" {
		msg = http.StatusText(e.StatusCode)
	}

	s := fmt.Sprintf("iotcredentials: %d %s", e.StatusCode, msg)
	if e.RequestID != "" {
		s += fmt.Sprintf(" (request id %s)", e.RequestID)
	}
	return s
}

// HTTPStatusCode reports the status returned by AWS IoT, matching the
// convention used by the AWS SDK for Go v2 error types.
func (e *APIError) HTTPStatusCode() int { return e.StatusCode }

// ErrCredentialsExpired is reported when AWS IoT returns credentials that have
// already expired, which means the local clock is wrong.
var ErrCredentialsExpired = errors.New("iotcredentials: credentials already expired on arrival, check the system clock")
