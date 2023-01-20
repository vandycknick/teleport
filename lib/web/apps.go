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

// Package web implements web proxy handler that provides
// web interface to view and connect to teleport nodes
package web

import (
	"context"
	"net/http"
	"strings"

	"github.com/gravitational/trace"
	"github.com/julienschmidt/httprouter"

	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/httplib"
	"github.com/gravitational/teleport/lib/reversetunnel"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/teleport/lib/web/app"
	"github.com/gravitational/teleport/lib/web/ui"
)

// clusterAppsGet returns a list of applications in a form the UI can present.
func (h *Handler) clusterAppsGet(w http.ResponseWriter, r *http.Request, p httprouter.Params, sctx *SessionContext, site reversetunnel.RemoteSite) (interface{}, error) {
	identity, err := sctx.GetIdentity()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Get a list of application servers and their proxied apps.
	clt, err := sctx.GetUserClient(r.Context(), site)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	resp, err := listResources(clt, r, types.KindAppServer)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	appServers, err := types.ResourcesWithLabels(resp.Resources).AsAppServers()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	apps := removeUnsupportedApps(appServers)

	return listResourcesGetResponse{
		Items: ui.MakeApps(ui.MakeAppsConfig{
			LocalClusterName:  h.auth.clusterName,
			LocalProxyDNSName: h.proxyDNSName(),
			AppClusterName:    site.GetName(),
			Identity:          identity,
			Apps:              apps,
		}),
		StartKey:   resp.NextKey,
		TotalCount: len(apps),
	}, nil
}

type GetAppFQDNRequest resolveAppParams

type GetAppFQDNResponse struct {
	// FQDN is application FQDN.
	FQDN string `json:"fqdn"`
}

type CreateAppSessionRequest resolveAppParams

type CreateAppSessionResponse struct {
	// CookieValue is the application session cookie value.
	CookieValue string `json:"cookie_value"`
	// SubjectCookieValue is the application session subject cookie token.
	SubjectCookieValue string `json:"subject_cookie_value"`
	// FQDN is application FQDN.
	FQDN string `json:"fqdn"`
}

// getAppFQDN resolves the input params to a known application and returns
// its valid FQDN.
//
// GET /v1/webapi/apps/:fqdnHint/:clusterName/:publicAddr
func (h *Handler) getAppFQDN(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *SessionContext) (interface{}, error) {
	req := GetAppFQDNRequest{
		FQDNHint:    p.ByName("fqdnHint"),
		ClusterName: p.ByName("clusterName"),
		PublicAddr:  p.ByName("publicAddr"),
	}

	// Get an auth client connected with the user's identity.
	authClient, err := ctx.GetClient()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Get a reverse tunnel proxy aware of the user's permissions.
	proxy, err := h.ProxyWithRoles(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Use the information the caller provided to attempt to resolve to an
	// application running within either the root or leaf cluster.
	result, err := h.resolveApp(r.Context(), authClient, proxy, resolveAppParams(req))
	if err != nil {
		return nil, trace.Wrap(err, "unable to resolve FQDN: %v", req.FQDNHint)
	}

	return &GetAppFQDNResponse{
		FQDN: result.FQDN,
	}, nil
}

// createAppSession creates a new application session.
//
// POST /v1/webapi/sessions/app
func (h *Handler) createAppSession(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *SessionContext) (interface{}, error) {
	var req CreateAppSessionRequest
	if err := httplib.ReadJSON(r, &req); err != nil {
		return nil, trace.Wrap(err)
	}

	// Get an auth client connected with the user's identity.
	authClient, err := ctx.GetClient()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Get a reverse tunnel proxy aware of the user's permissions.
	proxy, err := h.ProxyWithRoles(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Use the information the caller provided to attempt to resolve to an
	// application running within either the root or leaf cluster.
	result, err := h.resolveApp(r.Context(), authClient, proxy, resolveAppParams(req))
	if err != nil {
		return nil, trace.Wrap(err, "unable to resolve FQDN: %v", req.FQDNHint)
	}

	h.log.Debugf("Creating application web session for %v in %v.", result.App.GetPublicAddr(), result.ClusterName)

	// Create an application web session.
	//
	// Application sessions should not last longer than the parent session.TTL
	// will be derived from the identity which has the same expiration as the
	// parent web session.
	//
	// PublicAddr and ClusterName will get encoded within the certificate and
	// used for request routing.
	ws, err := authClient.CreateAppSession(r.Context(), types.CreateAppSessionRequest{
		Username:    ctx.GetUser(),
		PublicAddr:  result.App.GetPublicAddr(),
		ClusterName: result.ClusterName,
		AWSRoleARN:  req.AWSRole,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Block and wait a few seconds for the session that was created to show up
	// in the cache. If this request is not blocked here, it can get stuck in a
	// racy session creation loop.
	err = h.waitForAppSession(r.Context(), ws.GetName(), ctx.GetUser())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Extract the identity of the user.
	certificate, err := tlsca.ParseCertificatePEM(ws.GetTLSCert())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	identity, err := tlsca.FromSubject(certificate.Subject, certificate.NotAfter)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	userMetadata := identity.GetUserMetadata()
	userMetadata.User = ws.GetUser()
	userMetadata.AWSRoleARN = req.AWSRole

	// Now that the certificate has been issued, emit a "new session created"
	// for all events associated with this certificate.
	appSessionStartEvent := &apievents.AppSessionStart{
		Metadata: apievents.Metadata{
			Type:        events.AppSessionStartEvent,
			Code:        events.AppSessionStartCode,
			ClusterName: identity.RouteToApp.ClusterName,
		},
		ServerMetadata: apievents.ServerMetadata{
			ServerID:        h.cfg.HostUUID,
			ServerNamespace: apidefaults.Namespace,
		},
		SessionMetadata: apievents.SessionMetadata{
			SessionID: identity.RouteToApp.SessionID,
			WithMFA:   identity.MFAVerified,
		},
		UserMetadata: userMetadata,
		ConnectionMetadata: apievents.ConnectionMetadata{
			RemoteAddr: r.RemoteAddr,
		},
		PublicAddr: identity.RouteToApp.PublicAddr,
		AppMetadata: apievents.AppMetadata{
			AppURI:        result.App.GetURI(),
			AppPublicAddr: result.App.GetPublicAddr(),
			AppName:       result.App.GetName(),
		},
	}
	if err := h.cfg.Emitter.EmitAuditEvent(h.cfg.Context, appSessionStartEvent); err != nil {
		return nil, trace.Wrap(err)
	}

	return &CreateAppSessionResponse{
		CookieValue:        ws.GetName(),
		SubjectCookieValue: ws.GetBearerToken(),
		FQDN:               result.FQDN,
	}, nil
}

// waitForAppSession will block until the requested application session shows up in the
// cache or a timeout occurs.
func (h *Handler) waitForAppSession(ctx context.Context, sessionID, user string) error {
	return auth.WaitForAppSession(ctx, sessionID, user, h.cfg.AccessPoint)
}

type resolveAppParams struct {
	// FQDNHint indicates (tentatively) the fully qualified domain name of the application.
	FQDNHint string `json:"fqdn"`

	// PublicAddr is the public address of the application.
	PublicAddr string `json:"public_addr"`

	// ClusterName is the cluster within which this application is running.
	ClusterName string `json:"cluster_name"`

	// AWSRole is the AWS role ARN when accessing AWS management console.
	AWSRole string `json:"arn,omitempty"`
}

type resolveAppResult struct {
	// ServerID is the ID of the server this application is running on.
	ServerID string
	// FQDN is the best effort FQDN resolved for this application.
	FQDN string
	// ClusterName is the name of the cluster within which the application
	// is running.
	ClusterName string
	// App is the requested application.
	App types.Application
}

func (h *Handler) resolveApp(ctx context.Context, clt app.Getter, proxy reversetunnel.Tunnel, params resolveAppParams) (*resolveAppResult, error) {
	var (
		server         types.AppServer
		appClusterName string
		err            error
	)

	// If the request contains a public address and cluster name (for example, if it came
	// from the application launcher in the Web UI) then directly exactly resolve the
	// application that the caller is requesting. If it does not, do best effort FQDN resolution.
	switch {
	case params.PublicAddr != "" && params.ClusterName != "":
		server, appClusterName, err = h.resolveDirect(ctx, proxy, params.PublicAddr, params.ClusterName)
	case params.FQDNHint != "":
		server, appClusterName, err = h.resolveFQDN(ctx, clt, proxy, params.FQDNHint)
	default:
		err = trace.BadParameter("no inputs to resolve application")
	}
	if err != nil {
		return nil, trace.Wrap(err)
	}

	fqdn := ui.AssembleAppFQDN(h.auth.clusterName, h.proxyDNSName(), appClusterName, server.GetApp())

	return &resolveAppResult{
		ServerID:    server.GetName(),
		FQDN:        fqdn,
		ClusterName: appClusterName,
		App:         server.GetApp(),
	}, nil
}

// resolveDirect takes a public address and cluster name and exactly resolves
// the application and the server on which it is running.
func (h *Handler) resolveDirect(ctx context.Context, proxy reversetunnel.Tunnel, publicAddr string, clusterName string) (types.AppServer, string, error) {
	clusterClient, err := proxy.GetSite(clusterName)
	if err != nil {
		return nil, "", trace.Wrap(err)
	}

	authClient, err := clusterClient.GetClient()
	if err != nil {
		return nil, "", trace.Wrap(err)
	}

	servers, err := app.Match(ctx, authClient, app.MatchPublicAddr(publicAddr))
	if err != nil {
		return nil, "", trace.Wrap(err)
	}

	if len(servers) == 0 {
		return nil, "", trace.NotFound("failed to match applications with public addr %s", publicAddr)
	}

	return servers[0], clusterName, nil
}

// resolveFQDN makes a best effort attempt to resolve FQDN to an application
// running within a root or leaf cluster.
func (h *Handler) resolveFQDN(ctx context.Context, clt app.Getter, proxy reversetunnel.Tunnel, fqdn string) (types.AppServer, string, error) {
	return app.ResolveFQDN(ctx, clt, proxy, h.proxyDNSNames(), fqdn)
}

// proxyDNSName is a DNS name the HTTP proxy is available at, where
// the local cluster name is used as a best-effort fallback.
func (h *Handler) proxyDNSName() string {
	dnsNames := h.proxyDNSNames()
	if len(dnsNames) == 0 {
		return h.auth.clusterName
	}
	return dnsNames[0]
}

// proxyDNSNames returns DNS names the HTTP proxy is available at, the local
// cluster name is used as a best-effort fallback.
func (h *Handler) proxyDNSNames() (dnsNames []string) {
	for _, addr := range h.cfg.ProxyPublicAddrs {
		dnsName, err := utils.DNSName(addr.String())
		if err != nil {
			continue
		}
		dnsNames = append(dnsNames, dnsName)
	}
	if len(dnsNames) == 0 {
		return []string{h.auth.clusterName}
	}
	return dnsNames
}

// removeUnsupportedApps filters unsupported (TCP, Cloud API-only) apps out of the list of app servers.
func removeUnsupportedApps(appServers []types.AppServer) (apps types.Apps) {
	for _, server := range appServers {
		a := server.GetApp()
		// Skip over API-only Cloud apps
		if strings.HasPrefix(a.GetURI(), "cloud://") {
			continue
		}

		// Skip over TCP apps since they cannot be accessed through web UI.
		if server.GetApp().IsTCP() {
			continue
		}
		apps = append(apps, server.GetApp())
	}
	return apps
}
