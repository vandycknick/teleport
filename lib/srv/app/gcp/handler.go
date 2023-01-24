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

package gcp

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"time"

	gcpcredentials "cloud.google.com/go/iam/credentials/apiv1"
	"cloud.google.com/go/iam/credentials/apiv1/credentialspb"
	"github.com/googleapis/gax-go/v2"
	"github.com/gravitational/oxy/forward"
	oxyutils "github.com/gravitational/oxy/utils"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/sirupsen/logrus"

	"github.com/gravitational/teleport/api/utils/gcp"
	"github.com/gravitational/teleport/lib/cloud"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/httplib"
	"github.com/gravitational/teleport/lib/srv/app/common"
	"github.com/gravitational/teleport/lib/utils"
	awsutils "github.com/gravitational/teleport/lib/utils/aws"
)

// iamCredentialsClient is an interface that defines the methods which we use from IAM Service Account Credentials API.
// It is implemented by *gcpcredentials.IamCredentialsClient and can be mocked in tests unlike the concrete struct.
type iamCredentialsClient interface {
	GenerateAccessToken(ctx context.Context, req *credentialspb.GenerateAccessTokenRequest, opts ...gax.CallOption) (*credentialspb.GenerateAccessTokenResponse, error)
}

// cloudClientGCP is an interface that defines the GetGCPIAMClient method we use in this module.
type cloudClientGCP interface {
	GetGCPIAMClient(context.Context) (iamCredentialsClient, error)
}

// cloudClientGCPImpl is a wrapper around callback function implementing cloudClientGCP interface.
type cloudClientGCPImpl[T iamCredentialsClient] struct {
	getGCPIAMClient func(ctx context.Context) (T, error)
}

func (t *cloudClientGCPImpl[T]) GetGCPIAMClient(ctx context.Context) (iamCredentialsClient, error) {
	return t.getGCPIAMClient(ctx)
}

var _ cloudClientGCP = (*cloudClientGCPImpl[iamCredentialsClient])(nil)

// HandlerConfig is the configuration for an GCP app-access handler.
type HandlerConfig struct {
	// RoundTripper is the underlying transport given to an oxy Forwarder.
	RoundTripper http.RoundTripper
	// Log is the Logger.
	Log logrus.FieldLogger
	// Clock is used to override time in tests.
	Clock clockwork.Clock
	// cloudClientGCP holds a reference to GCP IAM client. Normally set in CheckAndSetDefaults, it is overridden in tests.
	cloudClientGCP cloudClientGCP
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
		s.Log = logrus.WithField(trace.Component, "gcp:fwd")
	}
	if s.cloudClientGCP == nil {
		clients := cloud.NewClients()
		s.cloudClientGCP = &cloudClientGCPImpl[*gcpcredentials.IamCredentialsClient]{getGCPIAMClient: clients.GetGCPIAMClient}
	}
	return nil
}

// Forwarder is an GCP CLI proxy service that forwards the requests to GCP API, but updates the authorization headers
// based on user identity.
type handler struct {
	// config is the handler configuration.
	HandlerConfig

	// fwd is used to forward requests to GCP API after the handler has rewritten them.
	fwd *forward.Forwarder

	// tokenCache caches access tokens.
	tokenCache *utils.FnCache
}

// NewGCPHandler creates a new instance of a http.Handler for GCP requests.
func NewGCPHandler(ctx context.Context, config HandlerConfig) (http.Handler, error) {
	return newGCPHandler(ctx, config)
}

// newGCPHandler creates a new instance of a handler for GCP requests. Used by NewGCPHandler and in tests.
func newGCPHandler(ctx context.Context, config HandlerConfig) (*handler, error) {
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
	s.Log.Debugf("Processing request, sessionId = %q, gcpServiceAccount = %q", sessionCtx.Identity.RouteToApp.SessionID, sessionCtx.Identity.RouteToApp.GCPServiceAccount)

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
	if !gcp.IsGCPEndpoint(forwardedHost) {
		return nil, trace.AccessDenied("%q is not a GCP endpoint", forwardedHost)
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

func (s *handler) replaceAuthHeaders(r *http.Request, sessionCtx *common.SessionContext, reqCopy *http.Request) error {
	auth := reqCopy.Header.Get("Authorization")
	if auth == "" {
		s.Log.Debugf("No Authorization header present, skipping replacement.")
		return nil
	}

	token, err := s.getToken(r.Context(), sessionCtx.Identity.RouteToApp.GCPServiceAccount)
	if err != nil {
		return trace.Wrap(err)
	}

	// Set new authorization
	reqCopy.Header.Set("Authorization", "Bearer "+token.AccessToken)
	return nil
}

type cacheKey struct {
	serviceAccount string
}

const getTokenTimeout = time.Second * 5

// defaultScopeList is a fixed list of scopes requested for a token.
// If needed we can extend it or make it configurable.
// For scope documentation see: https://developers.google.com/identity/protocols/oauth2/scopes
var defaultScopeList = []string{
	"https://www.googleapis.com/auth/cloud-platform",

	"openid",
	"https://www.googleapis.com/auth/userinfo.email",
	"https://www.googleapis.com/auth/appengine.admin",
	"https://www.googleapis.com/auth/sqlservice.login",
	"https://www.googleapis.com/auth/compute",
}

func (s *handler) getToken(ctx context.Context, serviceAccount string) (*credentialspb.GenerateAccessTokenResponse, error) {
	key := cacheKey{serviceAccount}

	cancelCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var tokenResult *credentialspb.GenerateAccessTokenResponse
	var errorResult error

	// call Clock.After() before FnCacheGet gets called in a different go-routine.
	// this ensures there is no race condition in the timeout tests
	timeoutChan := s.Clock.After(getTokenTimeout)

	go func() {
		tokenResult, errorResult = utils.FnCacheGet(cancelCtx, s.tokenCache, key, func(ctx context.Context) (*credentialspb.GenerateAccessTokenResponse, error) {
			return s.generateAccessToken(ctx, serviceAccount, defaultScopeList)
		})
		cancel()
	}()

	select {
	case <-timeoutChan:
		return nil, trace.Wrap(context.DeadlineExceeded, "timeout waiting for access token for %v", getTokenTimeout)
	case <-cancelCtx.Done():
		return tokenResult, errorResult
	}
}

func (s *handler) generateAccessToken(ctx context.Context, serviceAccount string, scopes []string) (*credentialspb.GenerateAccessTokenResponse, error) {
	client, err := s.cloudClientGCP.GetGCPIAMClient(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	request := &credentialspb.GenerateAccessTokenRequest{
		// expected format: projects/-/serviceAccounts/{ACCOUNT_EMAIL_OR_UNIQUEID}
		Name:  fmt.Sprintf("projects/-/serviceAccounts/%v", serviceAccount),
		Scope: scopes,
	}
	accessToken, err := client.GenerateAccessToken(ctx, request)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return accessToken, nil
}
