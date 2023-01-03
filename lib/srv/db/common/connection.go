/*
Copyright 2023 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package common

import (
	"context"
	"net"
	"net/http"

	"github.com/gravitational/trace"
)

// TestTCPConnection tests if provided address can be accessed.
func TestTCPConnection(ctx context.Context, address string) error {
	dialer := net.Dialer{
		Timeout: DefaultTestConnectionTimeout,
	}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	conn.Close()
	return trace.Wrap(err)
}

// TestHTTPConnection tests if provided HTTP URL can be accessed.
func TestHTTPConnection(ctx context.Context, url string) error {
	ctx, cancel := context.WithTimeout(ctx, DefaultTestConnectionTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return trace.Wrap(err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return trace.Wrap(err)
	}

	// Ignore the response code.
	resp.Body.Close()
	return nil
}
