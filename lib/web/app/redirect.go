/*
Copyright 2020 Gravitational, Inc.

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

package app

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gravitational/teleport/lib/httplib"
)

func SetRedirectPageHeaders(h http.Header, nonce string) {
	httplib.SetNoCacheHeaders(h)
	httplib.SetDefaultSecurityHeaders(h)

	// Set content security policy flags
	scriptSrc := "none"
	if nonce != "" {
		// Should match the <script> tab nonce (random value).
		scriptSrc = fmt.Sprintf("nonce-%v", nonce)
	}
	var csp = strings.Join([]string{
		httplib.GetDefaultContentSecurityPolicy(),
		fmt.Sprintf("script-src '%v'", scriptSrc),
		"style-src 'self'",
		"img-src 'self'",
	}, ";")
	h.Set("Content-Security-Policy", csp)
}
