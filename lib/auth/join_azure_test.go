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

package auth

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth/testauthority"
	"github.com/gravitational/teleport/lib/fixtures"
	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"
	"go.mozilla.org/pkcs7"
)

type azureChallengeResponseConfig struct {
	Challenge string
}

type azureChallengeResponseOption func(*azureChallengeResponseConfig)

func withChallengeAzure(challenge string) azureChallengeResponseOption {
	return func(cfg *azureChallengeResponseConfig) {
		cfg.Challenge = challenge
	}
}

func TestAuth_RegisterUsingAzureMethod(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	p, err := newTestPack(ctx, t.TempDir())
	require.NoError(t, err)
	a := p.a

	sshPrivateKey, sshPublicKey, err := testauthority.New().GenerateKeyPair()
	require.NoError(t, err)

	tlsConfig, err := fixtures.LocalTLSConfig()
	require.NoError(t, err)

	block, _ := pem.Decode(fixtures.LocalhostKey)
	pkey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)

	tlsPublicKey, err := PrivateKeyToPublicKeyTLS(sshPrivateKey)
	require.NoError(t, err)

	isAccessDenied := func(t require.TestingT, err error, _ ...interface{}) {
		require.True(t, trace.IsAccessDenied(err), "expected Access Denied error, actual error: %v", err)
	}
	isBadParameter := func(t require.TestingT, err error, _ ...interface{}) {
		require.True(t, trace.IsBadParameter(err), "expected Bad Parameter error, actual error: %v", err)
	}

	subID := uuid.NewString()
	vmID := uuid.NewString()

	tests := []struct {
		name                     string
		tokenName                string
		requestTokenName         string
		tokenSpec                types.ProvisionTokenSpecV2
		challengeResponseOptions []azureChallengeResponseOption
		challengeResponseErr     error
		useSystemCertPool        bool
		assertError              require.ErrorAssertionFunc
	}{
		{
			name:             "basic passing case",
			tokenName:        "test-token",
			requestTokenName: "test-token",
			tokenSpec: types.ProvisionTokenSpecV2{
				Roles: []types.SystemRole{types.RoleNode},
				Azure: &types.ProvisionTokenSpecV2Azure{
					Allow: []*types.ProvisionTokenSpecV2Azure_Rule{
						{
							Subscription: subID,
						},
					},
				},
				JoinMethod: types.JoinMethodAzure,
			},
			assertError: require.NoError,
		},
		{
			name:             "wrong token",
			tokenName:        "test-token",
			requestTokenName: "wrong-token",
			tokenSpec: types.ProvisionTokenSpecV2{
				Roles: []types.SystemRole{types.RoleNode},
				Azure: &types.ProvisionTokenSpecV2Azure{
					Allow: []*types.ProvisionTokenSpecV2Azure_Rule{
						{
							Subscription: subID,
						},
					},
				},
				JoinMethod: types.JoinMethodAzure,
			},
			assertError: isAccessDenied,
		},
		{
			name:             "challenge response error",
			tokenName:        "test-token",
			requestTokenName: "test-token",
			tokenSpec: types.ProvisionTokenSpecV2{
				Roles: []types.SystemRole{types.RoleNode},
				Azure: &types.ProvisionTokenSpecV2Azure{
					Allow: []*types.ProvisionTokenSpecV2Azure_Rule{
						{
							Subscription: subID,
						},
					},
				},
				JoinMethod: types.JoinMethodAzure,
			},
			challengeResponseErr: trace.BadParameter("test error"),
			assertError:          isBadParameter,
		},
		{
			name:             "wrong subscription",
			tokenName:        "test-token",
			requestTokenName: "test-token",
			tokenSpec: types.ProvisionTokenSpecV2{
				Roles: []types.SystemRole{types.RoleNode},
				Azure: &types.ProvisionTokenSpecV2Azure{
					Allow: []*types.ProvisionTokenSpecV2Azure_Rule{
						{
							Subscription: "some-junk",
						},
					},
				},
				JoinMethod: types.JoinMethodAzure,
			},
			assertError: isAccessDenied,
		},
		{
			name:             "wrong challenge",
			tokenName:        "test-token",
			requestTokenName: "test-token",
			tokenSpec: types.ProvisionTokenSpecV2{
				Roles: []types.SystemRole{types.RoleNode},
				Azure: &types.ProvisionTokenSpecV2Azure{
					Allow: []*types.ProvisionTokenSpecV2Azure_Rule{
						{
							Subscription: subID,
						},
					},
				},
				JoinMethod: types.JoinMethodAzure,
			},
			challengeResponseOptions: []azureChallengeResponseOption{
				withChallengeAzure("wrong-challenge"),
			},
			assertError: isAccessDenied,
		},
		{
			name:             "invalid signature",
			tokenName:        "test-token",
			requestTokenName: "test-token",
			tokenSpec: types.ProvisionTokenSpecV2{
				Roles: []types.SystemRole{types.RoleNode},
				Azure: &types.ProvisionTokenSpecV2Azure{
					Allow: []*types.ProvisionTokenSpecV2Azure_Rule{
						{
							Subscription: subID,
						},
					},
				},
				JoinMethod: types.JoinMethodAzure,
			},
			useSystemCertPool: true,
			assertError:       require.Error,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token, err := types.NewProvisionTokenFromSpec(
				tc.tokenName,
				time.Now().Add(time.Minute),
				tc.tokenSpec)
			require.NoError(t, err)
			require.NoError(t, a.UpsertToken(ctx, token))
			t.Cleanup(func() {
				require.NoError(t, a.DeleteToken(ctx, token.GetName()))
			})

			reqCtx := context.Background()
			reqCtx = context.WithValue(reqCtx, ContextClientAddr, &net.IPAddr{})

			var certPool *x509.CertPool
			if !tc.useSystemCertPool {
				certPool = tlsConfig.CertPool
			}

			_, err = a.RegisterUsingAzureMethod(reqCtx, func(challenge string) (*proto.RegisterUsingAzureMethodRequest, error) {
				cfg := &azureChallengeResponseConfig{Challenge: challenge}
				for _, opt := range tc.challengeResponseOptions {
					opt(cfg)
				}

				ad := attestedData{
					Nonce:          cfg.Challenge,
					SubscriptionID: subID,
					ID:             vmID,
				}
				adBytes, err := json.Marshal(&ad)
				require.NoError(t, err)
				s, err := pkcs7.NewSignedData(adBytes)
				require.NoError(t, err)
				require.NoError(t, s.AddSigner(tlsConfig.Certificate, pkey, pkcs7.SignerInfoConfig{}))
				signature, err := s.Finish()
				require.NoError(t, err)
				signedAD := signedAttestedData{
					Encoding:  "pkcs7",
					Signature: base64.StdEncoding.EncodeToString(signature),
				}
				signedADBytes, err := json.Marshal(&signedAD)
				require.NoError(t, err)

				req := &proto.RegisterUsingAzureMethodRequest{
					RegisterUsingTokenRequest: &types.RegisterUsingTokenRequest{
						Token:        tc.requestTokenName,
						HostID:       "test-node",
						Role:         types.RoleNode,
						PublicSSHKey: sshPublicKey,
						PublicTLSKey: tlsPublicKey,
					},
					AttestedData: signedADBytes,
				}
				return req, tc.challengeResponseErr
			}, withCertPool(certPool))
			tc.assertError(t, err)
		})
	}
}
