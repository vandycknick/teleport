// Copyright 2022 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package azure

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/gravitational/oxy/forward"
	oxyutils "github.com/gravitational/oxy/utils"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/sirupsen/logrus"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/utils/azure"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/httplib"
	"github.com/gravitational/teleport/lib/jwt"
	"github.com/gravitational/teleport/lib/srv/app/common"
	"github.com/gravitational/teleport/lib/utils"
	awsutils "github.com/gravitational/teleport/lib/utils/aws"
)

// HandlerConfig is the configuration for an Azure app-access handler.
type HandlerConfig struct {
	// RoundTripper is the underlying transport given to an oxy Forwarder.
	RoundTripper http.RoundTripper
	// Log is the Logger.
	Log logrus.FieldLogger
	// Clock is used to override time in tests.
	Clock clockwork.Clock

	// getAccessToken is a function for getting access token, pluggable for the sake of testing.
	getAccessToken getAccessTokenFunc
}

// CheckAndSetDefaults validates the HandlerConfig.
func (s *HandlerConfig) CheckAndSetDefaults() error {
	if s.RoundTripper == nil {
		tr, err := defaults.Transport()
		if err != nil {
			return trace.Wrap(err)
		}
		s.RoundTripper = tr
	}
	if s.Clock == nil {
		s.Clock = clockwork.NewRealClock()
	}
	if s.Log == nil {
		s.Log = logrus.WithField(trace.Component, "azure:fwd")
	}
	if s.getAccessToken == nil {
		s.getAccessToken = getAccessTokenManagedIdentity
	}
	return nil
}

// handler is an Azure CLI proxy service handler that forwards the requests to Azure API, but updates the authorization headers
// based on user identity.
type handler struct {
	// config is the handler configuration.
	HandlerConfig

	// fwd is used to forward requests to Azure API after the handler has rewritten them.
	fwd *forward.Forwarder

	// tokenCache caches access tokens.
	tokenCache *utils.FnCache
}

// NewAzureHandler creates a new instance of a http.Handler for Azure requests.
func NewAzureHandler(ctx context.Context, config HandlerConfig) (http.Handler, error) {
	return newAzureHandler(ctx, config)
}

// newAzureHandler creates a new instance of a handler for Azure requests. Used by NewAzureHandler and in tests.
func newAzureHandler(ctx context.Context, config HandlerConfig) (*handler, error) {
	if err := config.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	tokenCache, err := utils.NewFnCache(utils.FnCacheConfig{
		TTL:     time.Second * 60,
		Clock:   config.Clock,
		Context: ctx,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	svc := &handler{
		HandlerConfig: config,
		tokenCache:    tokenCache,
	}

	fwd, err := forward.New(
		forward.RoundTripper(config.RoundTripper),
		forward.ErrorHandler(oxyutils.ErrorHandlerFunc(svc.formatForwardResponseError)),
		// Explicitly passing false here to be clear that we always want the host
		// header to be the same as the outbound request's URL host.
		forward.PassHostHeader(false),
	)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	svc.fwd = fwd
	return svc, nil
}

// RoundTrip handles incoming requests and forwards them to the proper API.
func (s *handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if err := s.serveHTTP(w, req); err != nil {
		s.formatForwardResponseError(w, req, err)
		return
	}
}

// serveHTTP is a helper to simplify error handling in ServeHTTP.
func (s *handler) serveHTTP(w http.ResponseWriter, req *http.Request) error {
	sessionCtx, err := common.GetSessionContext(req)
	if err != nil {
		return trace.Wrap(err)
	}
	fwdRequest, err := s.prepareForwardRequest(req, sessionCtx)
	if err != nil {
		return trace.Wrap(err)
	}
	recorder := httplib.NewResponseStatusRecorder(w)
	s.fwd.ServeHTTP(recorder, fwdRequest)
	status := uint32(recorder.Status())

	if err := sessionCtx.Audit.OnRequest(req.Context(), sessionCtx, fwdRequest, status, nil); err != nil {
		// log but don't return the error, because we already handed off request/response handling to the oxy forwarder.
		s.Log.WithError(err).Warn("Failed to emit audit event.")
	}
	return nil
}

func (s *handler) formatForwardResponseError(rw http.ResponseWriter, r *http.Request, err error) {
	s.Log.WithError(err).Debugf("Failed to process request.")
	common.SetTeleportAPIErrorHeader(rw, err)

	// Convert trace error type to HTTP and write response.
	code := trace.ErrorToCode(err)
	http.Error(rw, http.StatusText(code), code)
}

// prepareForwardRequest prepares a request for forwarding, updating headers and target host. Several checks are made along the way.
func (s *handler) prepareForwardRequest(r *http.Request, sessionCtx *common.SessionContext) (*http.Request, error) {
	forwardedHost := r.Header.Get("X-Forwarded-Host")
	if !azure.IsAzureEndpoint(forwardedHost) {
		return nil, trace.AccessDenied("%q is not an Azure endpoint", forwardedHost)
	}

	payload, err := awsutils.GetAndReplaceReqBody(r)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	reqCopy, err := http.NewRequest(r.Method, r.URL.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, trace.Wrap(err)
	}

	reqCopy.URL.Scheme = "https"
	reqCopy.URL.Host = forwardedHost
	reqCopy.Header = r.Header.Clone()

	err = s.replaceAuthHeaders(r, sessionCtx, reqCopy)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return reqCopy, trace.Wrap(err)
}

func getPeerKey(certs []*x509.Certificate) (crypto.PublicKey, error) {
	if len(certs) != 1 {
		return nil, trace.BadParameter("unexpected number of peer certificates: %v", len(certs))
	}

	cert := certs[0]

	pk, ok := cert.PublicKey.(crypto.PublicKey)
	if !ok {
		return nil, trace.BadParameter("peer cert public key not a crypto.Signer")
	}

	return pk, nil

}

func (s *handler) replaceAuthHeaders(r *http.Request, sessionCtx *common.SessionContext, reqCopy *http.Request) error {
	auth := reqCopy.Header.Get("Authorization")
	if auth == "" {
		s.Log.Debugf("No Authorization header present, skipping replacement.")
		return nil
	}

	pubKey, err := getPeerKey(r.TLS.PeerCertificates)
	if err != nil {
		return trace.Wrap(err)
	}

	claims, err := s.parseAuthHeader(auth, pubKey)
	if err != nil {
		return trace.Wrap(err, "failed to parse Authorization header")
	}

	s.Log.Debugf("Processing request, sessionId = %q, azureIdentity = %q, claims = %v", sessionCtx.Identity.RouteToApp.SessionID, sessionCtx.Identity.RouteToApp.AzureIdentity, claims)
	token, err := s.getToken(r.Context(), sessionCtx.Identity.RouteToApp.AzureIdentity, claims.Resource)
	if err != nil {
		return trace.Wrap(err)
	}

	// Set new authorization
	reqCopy.Header.Set("Authorization", "Bearer "+token.Token)
	return nil
}

func (s *handler) parseAuthHeader(token string, pubKey crypto.PublicKey) (*jwt.AzureTokenClaims, error) {
	before, after, found := strings.Cut(token, " ")
	if !found {
		return nil, trace.BadParameter("Unable to parse auth header")
	}
	if before != "Bearer" {
		return nil, trace.BadParameter("Unable to parse auth header")
	}

	// Create a new key that can sign and verify tokens.
	key, err := jwt.New(&jwt.Config{
		Clock:       s.Clock,
		PublicKey:   pubKey,
		Algorithm:   defaults.ApplicationTokenAlgorithm,
		ClusterName: types.TeleportAzureMSIEndpoint,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return key.VerifyAzureToken(after)
}

type getAccessTokenFunc func(ctx context.Context, managedIdentity string, scope string) (*azcore.AccessToken, error)

func getAccessTokenManagedIdentity(ctx context.Context, managedIdentity string, scope string) (*azcore.AccessToken, error) {
	identityCredential, err := azidentity.NewManagedIdentityCredential(&azidentity.ManagedIdentityCredentialOptions{ID: azidentity.ResourceID(managedIdentity)})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	opts := policy.TokenRequestOptions{Scopes: []string{scope}}
	token, err := identityCredential.GetToken(ctx, opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &token, nil
}

type cacheKey struct {
	managedIdentity string
	scope           string
}

const getTokenTimeout = time.Second * 5

func (s *handler) getToken(ctx context.Context, managedIdentity string, scope string) (*azcore.AccessToken, error) {
	key := cacheKey{managedIdentity, scope}

	cancelCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var tokenResult *azcore.AccessToken
	var errorResult error

	go func() {
		tokenResult, errorResult = utils.FnCacheGet(cancelCtx, s.tokenCache, key, func(ctx context.Context) (*azcore.AccessToken, error) {
			return s.getAccessToken(ctx, managedIdentity, scope)
		})
		cancel()
	}()

	select {
	case <-s.Clock.After(getTokenTimeout):
		return nil, trace.Wrap(context.DeadlineExceeded, "timeout waiting for access token for %v", getTokenTimeout)
	case <-cancelCtx.Done():
		return tokenResult, errorResult
	}
}
