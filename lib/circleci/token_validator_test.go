/*
Copyright 2022 Gravitational, Inc.

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

package circleci

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// fakeIDP pretends to be a circle CI org OIDC provider, e.g:
// https://oidc.circleci.com/org/00f45056-5918-4171-9222-b538c76ed3f8/.well-known/openid-configuration
type fakeIDP struct {
	signer jose.Signer
	server *httptest.Server
}

func (f *fakeIDP) issueToken(
	t *testing.T,
	organizationID string,
	projectID string,
	contextIDs []string,
	issuedAt time.Time,
	expiry time.Time,
) string {
	stdClaims := jwt.Claims{
		Issuer:   fmt.Sprintf(f.issuerURLTemplate(), organizationID),
		Subject:  fmt.Sprintf("org/%s/project/%s/user/USER_ID", organizationID, projectID),
		Audience: jwt.Audience{organizationID},
		IssuedAt: jwt.NewNumericDate(issuedAt),
		Expiry:   jwt.NewNumericDate(expiry),
	}
	customClaims := map[string]interface{}{
		"oidc.circleci.com/project-id":  projectID,
		"oidc.circleci.com/context-ids": contextIDs,
	}
	token, err := jwt.Signed(f.signer).
		Claims(stdClaims).
		Claims(customClaims).
		CompactSerialize()
	require.NoError(t, err)

	return token
}

func (f *fakeIDP) issuerURLTemplate() string {
	return f.server.URL + "/org/%s"
}

func newFakeIDP(t *testing.T, organizationID string) *fakeIDP {
	// Generate keypair for IDP
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	require.NoError(t, err)

	providerMux := http.NewServeMux()
	srv := httptest.NewServer(providerMux)
	t.Cleanup(srv.Close)
	orgURL := "/org/" + organizationID
	providerMux.HandleFunc(orgURL+"/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"claims_supported": []string{
				"sub",
				"aud",
				"exp",
				"iat",
				"iss",
				"jti",
				"oidc.circleci.com/project-id",
				"oidc.circleci.com/context-ids",
			},
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"issuer":                                srv.URL + orgURL,
			"jwks_uri": fmt.Sprintf(
				"%s/.well-known/jwks-pub.json",
				srv.URL+orgURL,
			),
			"response_types_supported": []string{"id_token"},
			"scopes_supported":         []string{"openid"},
			"subject_types_supported":  []string{"public", "pairwise"},
		}
		responseBytes, err := json.Marshal(response)
		require.NoError(t, err)
		_, err = w.Write(responseBytes)
		require.NoError(t, err)
	})
	providerMux.HandleFunc(orgURL+"/.well-known/jwks-pub.json", func(w http.ResponseWriter, r *http.Request) {
		// mimic jwks endpoint with our own key
		jwks := jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				{
					Key: &privateKey.PublicKey,
				},
			},
		}
		responseBytes, err := json.Marshal(jwks)
		require.NoError(t, err)
		_, err = w.Write(responseBytes)
		require.NoError(t, err)
	})

	return &fakeIDP{
		signer: signer,
		server: srv,
	}
}

func TestValidateToken(t *testing.T) {
	t.Parallel()
	realOrgID := "xyz-foo-bar-123"
	fake := newFakeIDP(t, realOrgID)

	tests := []struct {
		name        string
		assertError require.ErrorAssertionFunc
		want        *IDTokenClaims
		token       string
	}{
		{
			name:        "success",
			assertError: require.NoError,
			token: fake.issueToken(
				t,
				realOrgID,
				"a-project",
				[]string{"a-context"},
				time.Now().Add(-5*time.Minute),
				time.Now().Add(5*time.Minute),
			),
			want: &IDTokenClaims{
				ContextIDs: []string{"a-context"},
				ProjectID:  "a-project",
				Sub:        "org/xyz-foo-bar-123/project/a-project/user/USER_ID",
			},
		},
		{
			name:        "expired",
			assertError: require.Error,
			token: fake.issueToken(
				t,
				realOrgID,
				"a-project",
				[]string{"a-context"},
				time.Now().Add(-10*time.Minute),
				time.Now().Add(-5*time.Minute),
			),
		},
		{
			name:        "another org",
			assertError: require.Error,
			token: fake.issueToken(
				t,
				"not-the-configured-org",
				"a-project",
				[]string{"a-context"},
				time.Now().Add(-5*time.Minute),
				time.Now().Add(5*time.Minute),
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			claims, err := ValidateToken(
				ctx, clockwork.NewRealClock(), fake.issuerURLTemplate(), realOrgID, tt.token,
			)
			tt.assertError(t, err)
			require.Equal(t, tt.want, claims)
		})
	}
}
