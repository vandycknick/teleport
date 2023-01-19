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

package alpnproxy

import (
	"encoding/xml"
	"net/http"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"

	appcommon "github.com/gravitational/teleport/lib/srv/app/common"
	"github.com/gravitational/teleport/lib/utils"
	awsutils "github.com/gravitational/teleport/lib/utils/aws"
)

// AWSAccessMiddleware verifies the requests to AWS proxy are properly signed.
type AWSAccessMiddleware struct {
	// AWSCredentials are AWS Credentials used by LocalProxy for request's signature verification.
	AWSCredentials *credentials.Credentials

	Log logrus.FieldLogger

	assumedRoles map[string]*sts.AssumeRoleOutput
	mu           sync.RWMutex
}

var _ LocalProxyHTTPMiddleware = &AWSAccessMiddleware{}

func (m *AWSAccessMiddleware) CheckAndSetDefaults() error {
	if m.Log == nil {
		m.Log = logrus.WithField(trace.Component, "aws_access")
	}

	if m.AWSCredentials == nil {
		return trace.BadParameter("missing AWSCredentials")
	}

	return nil
}

// HandleRequest handles a request from the AWS client.
//
// Normally, the requets are signed with the local-proxy-generated credentials.
// We verify the signatures of these requests using the local-proxy-generated
// credentials then forward them to the proxy. The app agent will re-sign these
// requests with real credentials before sending them to AWS.
//
// When this AWS middleware receives a valid AssumeRole output (through
// HandleResponse), the middleware caches the credentials.
//
// When the middleware receives requests signed with these assumed-roles'
// credentials, in addition to verifying the signatures using the cached
// credentials, the middleware also rewrites the headers to indicate that these
// requests are signed by assumed roles. Upon receiving requests by assumed
// roles, the app agent restore the headers without re-signing before sending
// them to AWS.
//
// Here's a sample sequence for request by assumed role:
//
// client                   tsh                teleport                 AWS
// |                         |                    |                       |
// │ sts:AssumeRole          │                    │                       │
// ├────────────────────────►│ forward            │                       │
// │                         ├───────────────────►│ re-sign               │
// │                         │                    ├──────────────────────►│
// │                         │                    │ sts:AssumeRole output │
// │                         │                    │◄──────────────────────┤
// │                         │◄───────────────────┤                       │
// │                         │                    │                       │
// │                         ├────┐ cache         │                       │
// │                         │    │ sts:AssumeRole│                       │
// │ sts:AssuemRole output   │◄───┘ output        │                       │
// │◄────────────────────────┤                    │                       │
// │                         │                    │                       │
// │                         │                    │                       │
// │                         │                    │                       │
// │ request by assumed role │                    │                       │
// ├────────────────────────►│ rewrite headers    │                       │
// │                         ├───────────────────►│ restore headers       │
// │                         │                    ├──────────────────────►│
// │                         │                    │                       │
// │                         │                    │◄──────────────────────┤
// │                         │◄───────────────────┤                       │
// │◄────────────────────────┤                    │                       │
//
// Note that the first sts:AssumeRole should be signed with the
// local-proxy-generated credentials by the AWS client, while the second
// request is signed with real credentials of the assumed role.
func (m *AWSAccessMiddleware) HandleRequest(rw http.ResponseWriter, req *http.Request) bool {
	sigV4, err := awsutils.ParseSigV4(req.Header.Get(awsutils.AuthorizationHeader))
	if err != nil {
		m.Log.WithError(err).Error("Failed to parse AWS request authorization header.")
		rw.WriteHeader(http.StatusForbidden)
		return true
	}

	if assumedRole, found := m.findAssumedRole(sigV4.KeyID); found {
		return m.handleRequestByAssumedRole(rw, req, assumedRole)
	}
	return m.handleCommonRequest(rw, req)
}

func (m *AWSAccessMiddleware) handleCommonRequest(rw http.ResponseWriter, req *http.Request) bool {
	if err := awsutils.VerifyAWSSignature(req, m.AWSCredentials); err != nil {
		m.Log.WithError(err).Error("AWS signature verification failed.")
		rw.WriteHeader(http.StatusForbidden)
		return true
	}
	return false
}

func (m *AWSAccessMiddleware) handleRequestByAssumedRole(rw http.ResponseWriter, req *http.Request, assumedRole *sts.AssumeRoleOutput) bool {
	credentials := credentials.NewStaticCredentials(
		aws.ToString(assumedRole.Credentials.AccessKeyId),
		aws.ToString(assumedRole.Credentials.SecretAccessKey),
		aws.ToString(assumedRole.Credentials.SessionToken),
	)

	if err := awsutils.VerifyAWSSignature(req, credentials); err != nil {
		m.Log.WithError(err).Error("AWS signature verification failed.")
		rw.WriteHeader(http.StatusForbidden)
		return true
	}

	m.Log.Debugf("Rewriting headers for AWS request by assumed role %q.", aws.ToString(assumedRole.AssumedRoleUser.Arn))

	// Add a custom header for marking the special request.
	req.Header.Add(appcommon.TeleportAWSAssumedRole, aws.ToString(assumedRole.AssumedRoleUser.Arn))

	// Rename the original authorization header to ensure older app agents
	// (that don't support the requests by assumed roles) will fail.
	utils.RenameHeader(req.Header, awsutils.AuthorizationHeader, appcommon.TeleportAWSAssumedRoleAuthorization)
	return false
}

func (m *AWSAccessMiddleware) HandleResponse(response *http.Response) error {
	if response == nil || response.Request == nil {
		return nil
	}

	authHeader := utils.GetAnyHeader(response.Request.Header,
		awsutils.AuthorizationHeader,
		appcommon.TeleportAWSAssumedRoleAuthorization,
	)

	sigV4, err := awsutils.ParseSigV4(authHeader)
	if err != nil {
		m.Log.WithError(err).Error("Failed to parse AWS request authorization header.")
		return nil
	}

	if strings.EqualFold(sigV4.Service, sts.ServiceID) {
		return trace.Wrap(m.handleSTSResponse(response))
	}
	return nil
}

func (m *AWSAccessMiddleware) handleSTSResponse(response *http.Response) error {
	// Only looking for successful sts:AssumeRole calls.
	if response.Request.Method != http.MethodPost ||
		response.StatusCode != http.StatusOK {
		return nil
	}

	// In case something goes wrong when draining the body, return an error.
	body, err := utils.GetAndReplaceResponseBody(response)
	if err != nil {
		return trace.Wrap(err)
	}

	// Save the credentials if valid AssumeRoleOutput is found.
	type AssumeRoleResponse struct {
		AssumeRoleResult sts.AssumeRoleOutput
	}
	var resp AssumeRoleResponse
	if err = xml.Unmarshal(body, &resp); err == nil {
		if resp.AssumeRoleResult.AssumedRoleUser != nil && resp.AssumeRoleResult.Credentials != nil {
			m.addAssumedRole(&resp.AssumeRoleResult)
			m.Log.Debugf("Saved credentials for assumed role %q.", aws.ToString(resp.AssumeRoleResult.AssumedRoleUser.Arn))
		}
	}
	return nil
}

func (m *AWSAccessMiddleware) addAssumedRole(assumedRole *sts.AssumeRoleOutput) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.assumedRoles == nil {
		m.assumedRoles = make(map[string]*sts.AssumeRoleOutput)
	}
	m.assumedRoles[aws.ToString(assumedRole.Credentials.AccessKeyId)] = assumedRole
}

func (m *AWSAccessMiddleware) findAssumedRole(accessKeyID string) (*sts.AssumeRoleOutput, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.assumedRoles == nil {
		return nil, false
	}

	assumedRole, found := m.assumedRoles[accessKeyID]
	return assumedRole, found
}
