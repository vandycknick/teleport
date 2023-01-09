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
	"errors"
	"testing"
	"time"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth/testauthority"
	"github.com/gravitational/teleport/lib/githubactions"
	"github.com/gravitational/teleport/lib/modules"
)

type mockIDTokenValidator struct {
	tokens             map[string]githubactions.IDTokenClaims
	lastCalledGHESHost string
}

var errMockInvalidToken = errors.New("invalid token")

func (m *mockIDTokenValidator) Validate(_ context.Context, ghes string, token string) (*githubactions.IDTokenClaims, error) {
	m.lastCalledGHESHost = ghes

	claims, ok := m.tokens[token]
	if !ok {
		return nil, errMockInvalidToken
	}

	return &claims, nil
}

func TestAuth_RegisterUsingToken_GHA(t *testing.T) {
	validIDToken := "test.fake.jwt"
	idTokenValidator := &mockIDTokenValidator{
		tokens: map[string]githubactions.IDTokenClaims{
			validIDToken: {
				Sub:             "repo:octo-org/octo-repo:environment:prod",
				Repository:      "octo-org/octo-repo",
				RepositoryOwner: "octo-org",
				Workflow:        "example-workflow",
				Environment:     "prod",
				Actor:           "octocat",
				Ref:             "refs/heads/main",
				RefType:         "branch",
			},
		},
	}
	var withTokenValidator ServerOption = func(server *Server) error {
		server.ghaIDTokenValidator = idTokenValidator
		return nil
	}
	ctx := context.Background()
	p, err := newTestPack(ctx, t.TempDir(), withTokenValidator)
	require.NoError(t, err)
	auth := p.a

	// helper for creating RegisterUsingTokenRequest
	sshPrivateKey, sshPublicKey, err := testauthority.New().GenerateKeyPair()
	require.NoError(t, err)
	tlsPublicKey, err := PrivateKeyToPublicKeyTLS(sshPrivateKey)
	require.NoError(t, err)
	newRequest := func(idToken string) *types.RegisterUsingTokenRequest {
		return &types.RegisterUsingTokenRequest{
			HostID:       "host-id",
			Role:         types.RoleNode,
			IDToken:      idToken,
			PublicTLSKey: tlsPublicKey,
			PublicSSHKey: sshPublicKey,
		}
	}

	allowRule := func(modifier func(*types.ProvisionTokenSpecV2GitHub_Rule)) *types.ProvisionTokenSpecV2GitHub_Rule {
		rule := &types.ProvisionTokenSpecV2GitHub_Rule{
			Sub:             "repo:octo-org/octo-repo:environment:prod",
			Repository:      "octo-org/octo-repo",
			RepositoryOwner: "octo-org",
			Workflow:        "example-workflow",
			Environment:     "prod",
			Actor:           "octocat",
			Ref:             "refs/heads/main",
			RefType:         "branch",
		}
		if modifier != nil {
			modifier(rule)
		}
		return rule
	}

	allowRulesNotMatched := require.ErrorAssertionFunc(func(t require.TestingT, err error, i ...interface{}) {
		require.ErrorContains(t, err, "id token claims did not match any allow rules")
		require.True(t, trace.IsAccessDenied(err))
	})
	tests := []struct {
		name          string
		request       *types.RegisterUsingTokenRequest
		tokenSpec     types.ProvisionTokenSpecV2
		assertError   require.ErrorAssertionFunc
		setEnterprise bool
	}{
		{
			name: "success",
			tokenSpec: types.ProvisionTokenSpecV2{
				JoinMethod: types.JoinMethodGitHub,
				Roles:      []types.SystemRole{types.RoleNode},
				GitHub: &types.ProvisionTokenSpecV2GitHub{
					Allow: []*types.ProvisionTokenSpecV2GitHub_Rule{
						allowRule(nil),
					},
				},
			},
			request:     newRequest(validIDToken),
			assertError: require.NoError,
		},
		{
			name: "ghes override",
			tokenSpec: types.ProvisionTokenSpecV2{
				JoinMethod: types.JoinMethodGitHub,
				Roles:      []types.SystemRole{types.RoleNode},
				GitHub: &types.ProvisionTokenSpecV2GitHub{
					EnterpriseServerHost: "my.ghes.instance",
					Allow: []*types.ProvisionTokenSpecV2GitHub_Rule{
						allowRule(nil),
					},
				},
			},
			request:       newRequest(validIDToken),
			assertError:   require.NoError,
			setEnterprise: true,
		},
		{
			name: "ghes override requires enterprise license",
			tokenSpec: types.ProvisionTokenSpecV2{
				JoinMethod: types.JoinMethodGitHub,
				Roles:      []types.SystemRole{types.RoleNode},
				GitHub: &types.ProvisionTokenSpecV2GitHub{
					EnterpriseServerHost: "my.ghes.instance",
					Allow: []*types.ProvisionTokenSpecV2GitHub_Rule{
						allowRule(nil),
					},
				},
			},
			request: newRequest(validIDToken),
			assertError: require.ErrorAssertionFunc(func(t require.TestingT, err error, i ...interface{}) {
				require.ErrorIs(t, err, ErrRequiresEnterprise)
			}),
		},
		{
			name: "multiple allow rules",
			tokenSpec: types.ProvisionTokenSpecV2{
				JoinMethod: types.JoinMethodGitHub,
				Roles:      []types.SystemRole{types.RoleNode},
				GitHub: &types.ProvisionTokenSpecV2GitHub{
					Allow: []*types.ProvisionTokenSpecV2GitHub_Rule{
						allowRule(func(rule *types.ProvisionTokenSpecV2GitHub_Rule) {
							rule.Sub = "not matching"
						}),
						allowRule(nil),
					},
				},
			},
			request:     newRequest(validIDToken),
			assertError: require.NoError,
		},
		{
			name: "incorrect sub",
			tokenSpec: types.ProvisionTokenSpecV2{
				JoinMethod: types.JoinMethodGitHub,
				Roles:      []types.SystemRole{types.RoleNode},
				GitHub: &types.ProvisionTokenSpecV2GitHub{
					Allow: []*types.ProvisionTokenSpecV2GitHub_Rule{
						allowRule(func(rule *types.ProvisionTokenSpecV2GitHub_Rule) {
							rule.Sub = "not matching"
						}),
					},
				},
			},
			request:     newRequest(validIDToken),
			assertError: allowRulesNotMatched,
		},
		{
			name: "incorrect repository",
			tokenSpec: types.ProvisionTokenSpecV2{
				JoinMethod: types.JoinMethodGitHub,
				Roles:      []types.SystemRole{types.RoleNode},
				GitHub: &types.ProvisionTokenSpecV2GitHub{
					Allow: []*types.ProvisionTokenSpecV2GitHub_Rule{
						allowRule(func(rule *types.ProvisionTokenSpecV2GitHub_Rule) {
							rule.Repository = "not matching"
						}),
					},
				},
			},
			request:     newRequest(validIDToken),
			assertError: allowRulesNotMatched,
		},
		{
			name: "incorrect repository owner",
			tokenSpec: types.ProvisionTokenSpecV2{
				JoinMethod: types.JoinMethodGitHub,
				Roles:      []types.SystemRole{types.RoleNode},
				GitHub: &types.ProvisionTokenSpecV2GitHub{
					Allow: []*types.ProvisionTokenSpecV2GitHub_Rule{
						allowRule(func(rule *types.ProvisionTokenSpecV2GitHub_Rule) {
							rule.RepositoryOwner = "not matching"
						}),
					},
				},
			},
			request:     newRequest(validIDToken),
			assertError: allowRulesNotMatched,
		},
		{
			name: "incorrect workflow",
			tokenSpec: types.ProvisionTokenSpecV2{
				JoinMethod: types.JoinMethodGitHub,
				Roles:      []types.SystemRole{types.RoleNode},
				GitHub: &types.ProvisionTokenSpecV2GitHub{
					Allow: []*types.ProvisionTokenSpecV2GitHub_Rule{
						allowRule(func(rule *types.ProvisionTokenSpecV2GitHub_Rule) {
							rule.Workflow = "not matching"
						}),
					},
				},
			},
			request:     newRequest(validIDToken),
			assertError: allowRulesNotMatched,
		},
		{
			name: "incorrect environment",
			tokenSpec: types.ProvisionTokenSpecV2{
				JoinMethod: types.JoinMethodGitHub,
				Roles:      []types.SystemRole{types.RoleNode},
				GitHub: &types.ProvisionTokenSpecV2GitHub{
					Allow: []*types.ProvisionTokenSpecV2GitHub_Rule{
						allowRule(func(rule *types.ProvisionTokenSpecV2GitHub_Rule) {
							rule.Environment = "not matching"
						}),
					},
				},
			},
			request:     newRequest(validIDToken),
			assertError: allowRulesNotMatched,
		},
		{
			name: "incorrect actor",
			tokenSpec: types.ProvisionTokenSpecV2{
				JoinMethod: types.JoinMethodGitHub,
				Roles:      []types.SystemRole{types.RoleNode},
				GitHub: &types.ProvisionTokenSpecV2GitHub{
					Allow: []*types.ProvisionTokenSpecV2GitHub_Rule{
						allowRule(func(rule *types.ProvisionTokenSpecV2GitHub_Rule) {
							rule.Actor = "not matching"
						}),
					},
				},
			},
			request:     newRequest(validIDToken),
			assertError: allowRulesNotMatched,
		},
		{
			name: "incorrect ref",
			tokenSpec: types.ProvisionTokenSpecV2{
				JoinMethod: types.JoinMethodGitHub,
				Roles:      []types.SystemRole{types.RoleNode},
				GitHub: &types.ProvisionTokenSpecV2GitHub{
					Allow: []*types.ProvisionTokenSpecV2GitHub_Rule{
						allowRule(func(rule *types.ProvisionTokenSpecV2GitHub_Rule) {
							rule.Ref = "not matching"
						}),
					},
				},
			},
			request:     newRequest(validIDToken),
			assertError: allowRulesNotMatched,
		},
		{
			name: "incorrect ref type",
			tokenSpec: types.ProvisionTokenSpecV2{
				JoinMethod: types.JoinMethodGitHub,
				Roles:      []types.SystemRole{types.RoleNode},
				GitHub: &types.ProvisionTokenSpecV2GitHub{
					Allow: []*types.ProvisionTokenSpecV2GitHub_Rule{
						allowRule(func(rule *types.ProvisionTokenSpecV2GitHub_Rule) {
							rule.RefType = "not matching"
						}),
					},
				},
			},
			request:     newRequest(validIDToken),
			assertError: allowRulesNotMatched,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setEnterprise {
				modules.SetTestModules(
					t,
					&modules.TestModules{TestBuildType: modules.BuildEnterprise},
				)
			}
			token, err := types.NewProvisionTokenFromSpec(
				tt.name, time.Now().Add(time.Minute), tt.tokenSpec,
			)
			require.NoError(t, err)
			require.NoError(t, auth.CreateToken(ctx, token))
			tt.request.Token = tt.name

			_, err = auth.RegisterUsingToken(ctx, tt.request)
			tt.assertError(t, err)

			if tt.tokenSpec.GitHub.EnterpriseServerHost != "" {
				require.Equal(
					t,
					tt.tokenSpec.GitHub.EnterpriseServerHost,
					idTokenValidator.lastCalledGHESHost,
				)
			}
		})
	}
}
