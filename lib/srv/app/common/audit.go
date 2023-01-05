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

package common

import (
	"context"
	"net/http"

	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"

	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/tlsca"
	awsutils "github.com/gravitational/teleport/lib/utils/aws"
)

// Audit defines an interface for app access audit events logger.
type Audit interface {
	// OnSessionStart is called when new app session starts.
	OnSessionStart(ctx context.Context, serverID string, identity *tlsca.Identity, app types.Application) error
	// OnSessionEnd is called when an app session ends.
	OnSessionEnd(ctx context.Context, serverID string, identity *tlsca.Identity, app types.Application) error
	// OnSessionChunk is called when a new session chunk is created.
	OnSessionChunk(ctx context.Context, serverID, chunkID string, identity *tlsca.Identity, app types.Application) error
	// OnRequest is called when an app request is sent during the session and a response is received.
	OnRequest(ctx context.Context, sessionCtx *SessionContext, req *http.Request, status uint32, re *endpoints.ResolvedEndpoint) error
	// OnDynamoDBRequest is called when app request for a DynamoDB API is sent and a response is received.
	OnDynamoDBRequest(ctx context.Context, sessionCtx *SessionContext, req *http.Request, status uint32, re *endpoints.ResolvedEndpoint) error
	// EmitEvent emits the provided audit event.
	EmitEvent(ctx context.Context, event apievents.AuditEvent) error
}

// AuditConfig is the audit events emitter configuration.
type AuditConfig struct {
	// Emitter is used to emit audit events.
	Emitter apievents.Emitter
}

// Check validates the config.
func (c *AuditConfig) Check() error {
	if c.Emitter == nil {
		return trace.BadParameter("missing Emitter")
	}
	return nil
}

// audit provides methods for emitting app access audit events.
type audit struct {
	// cfg is the audit events emitter configuration.
	cfg AuditConfig
	// log is used for logging
	log logrus.FieldLogger
}

// NewAudit returns a new instance of the audit events emitter.
func NewAudit(config AuditConfig) (Audit, error) {
	if err := config.Check(); err != nil {
		return nil, trace.Wrap(err)
	}
	return &audit{
		cfg: config,
		log: logrus.WithField(trace.Component, "app:audit"),
	}, nil
}

// OnSessionStart is called when new app session starts.
func (a *audit) OnSessionStart(ctx context.Context, serverID string, identity *tlsca.Identity, app types.Application) error {
	event := &apievents.AppSessionStart{
		Metadata: apievents.Metadata{
			Type:        events.AppSessionStartEvent,
			Code:        events.AppSessionStartCode,
			ClusterName: identity.RouteToApp.ClusterName,
		},
		ServerMetadata: apievents.ServerMetadata{
			ServerID:        serverID,
			ServerNamespace: apidefaults.Namespace,
		},
		SessionMetadata: apievents.SessionMetadata{
			SessionID: identity.RouteToApp.SessionID,
			WithMFA:   identity.MFAVerified,
		},
		UserMetadata: identity.GetUserMetadata(),
		ConnectionMetadata: apievents.ConnectionMetadata{
			RemoteAddr: identity.ClientIP,
		},
		AppMetadata: apievents.AppMetadata{
			AppURI:        app.GetURI(),
			AppPublicAddr: app.GetPublicAddr(),
			AppName:       app.GetName(),
		},
	}
	return trace.Wrap(a.EmitEvent(ctx, event))
}

// OnSessionEnd is called when an app session ends.
func (a *audit) OnSessionEnd(ctx context.Context, serverID string, identity *tlsca.Identity, app types.Application) error {
	event := &apievents.AppSessionEnd{
		Metadata: apievents.Metadata{
			Type:        events.AppSessionEndEvent,
			Code:        events.AppSessionEndCode,
			ClusterName: identity.RouteToApp.ClusterName,
		},
		ServerMetadata: apievents.ServerMetadata{
			ServerID:        serverID,
			ServerNamespace: apidefaults.Namespace,
		},
		SessionMetadata: apievents.SessionMetadata{
			SessionID: identity.RouteToApp.SessionID,
			WithMFA:   identity.MFAVerified,
		},
		UserMetadata: identity.GetUserMetadata(),
		ConnectionMetadata: apievents.ConnectionMetadata{
			RemoteAddr: identity.ClientIP,
		},
		AppMetadata: apievents.AppMetadata{
			AppURI:        app.GetURI(),
			AppPublicAddr: app.GetPublicAddr(),
			AppName:       app.GetName(),
		},
	}
	return trace.Wrap(a.EmitEvent(ctx, event))
}

// OnSessionChunk is called when a new session chunk is created.
func (a *audit) OnSessionChunk(ctx context.Context, serverID, chunkID string, identity *tlsca.Identity, app types.Application) error {
	event := &apievents.AppSessionChunk{
		Metadata: apievents.Metadata{
			Type:        events.AppSessionChunkEvent,
			Code:        events.AppSessionChunkCode,
			ClusterName: identity.RouteToApp.ClusterName,
		},
		ServerMetadata: apievents.ServerMetadata{
			ServerID:        serverID,
			ServerNamespace: apidefaults.Namespace,
		},
		SessionMetadata: apievents.SessionMetadata{
			SessionID: identity.RouteToApp.SessionID,
			WithMFA:   identity.MFAVerified,
		},
		UserMetadata: identity.GetUserMetadata(),
		AppMetadata: apievents.AppMetadata{
			AppURI:        app.GetURI(),
			AppPublicAddr: app.GetPublicAddr(),
			AppName:       app.GetName(),
		},
		SessionChunkID: chunkID,
	}
	return trace.Wrap(a.EmitEvent(ctx, event))
}

// OnRequest is called when an app request is sent during the session and a response is received.
func (a *audit) OnRequest(ctx context.Context, sessionCtx *SessionContext, req *http.Request, status uint32, re *endpoints.ResolvedEndpoint) error {
	event := &apievents.AppSessionRequest{
		Metadata: apievents.Metadata{
			Type: events.AppSessionRequestEvent,
			Code: events.AppSessionRequestCode,
		},
		AppMetadata:        *MakeAppMetadata(sessionCtx.App),
		Method:             req.Method,
		Path:               req.URL.Path,
		RawQuery:           req.URL.RawQuery,
		StatusCode:         status,
		AWSRequestMetadata: *MakeAWSRequestMetadata(req, re),
	}
	return trace.Wrap(a.EmitEvent(ctx, event))
}

// OnDynamoDBRequest is called when a DynamoDB app request is sent during the session.
func (a *audit) OnDynamoDBRequest(ctx context.Context, sessionCtx *SessionContext, req *http.Request, status uint32, re *endpoints.ResolvedEndpoint) error {
	// Try to read the body and JSON unmarshal it.
	// If this fails, we still want to emit the rest of the event info; the request event Body is nullable, so it's ok if body is left nil here.
	body, err := awsutils.UnmarshalRequestBody(req)
	if err != nil {
		a.log.WithError(err).Warn("Failed to read request body as JSON, omitting the body from the audit event.")
	}
	// get the API target from the request header, according to the API request format documentation:
	// https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Programming.LowLevelAPI.html#Programming.LowLevelAPI.RequestFormat
	target := req.Header.Get(awsutils.AmzTargetHeader)
	event := &apievents.AppSessionDynamoDBRequest{
		Metadata: apievents.Metadata{
			Type: events.AppSessionDynamoDBRequestEvent,
			Code: events.AppSessionDynamoDBRequestCode,
		},
		UserMetadata:       sessionCtx.Identity.GetUserMetadata(),
		AppMetadata:        *MakeAppMetadata(sessionCtx.App),
		AWSRequestMetadata: *MakeAWSRequestMetadata(req, re),
		SessionChunkID:     sessionCtx.ChunkID,
		StatusCode:         status,
		Path:               req.URL.Path,
		RawQuery:           req.URL.RawQuery,
		Method:             req.Method,
		Target:             target,
		Body:               body,
	}
	return trace.Wrap(a.EmitEvent(ctx, event))
}

// EmitEvent emits the provided audit event.
func (a *audit) EmitEvent(ctx context.Context, event apievents.AuditEvent) error {
	return trace.Wrap(a.cfg.Emitter.EmitAuditEvent(ctx, event))
}

// MakeAppMetadata returns common server metadata for database session.
func MakeAppMetadata(app types.Application) *apievents.AppMetadata {
	return &apievents.AppMetadata{
		AppURI:        app.GetURI(),
		AppPublicAddr: app.GetPublicAddr(),
		AppName:       app.GetName(),
	}
}

// MakeAWSRequestMetadata is a helper to build AWSRequestMetadata from the provided request and endpoint.
// If the aws endpoint is nil, returns an empty request metadata.
func MakeAWSRequestMetadata(req *http.Request, awsEndpoint *endpoints.ResolvedEndpoint) *apievents.AWSRequestMetadata {
	if awsEndpoint == nil {
		return &apievents.AWSRequestMetadata{}
	}
	return &apievents.AWSRequestMetadata{
		AWSRegion:  awsEndpoint.SigningRegion,
		AWSService: awsEndpoint.SigningName,
		AWSHost:    req.URL.Host,
	}
}
