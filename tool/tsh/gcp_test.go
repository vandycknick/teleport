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

package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/tlsca"
)

func Test_getGCPServiceAccountFromFlags(t *testing.T) {
	tests := []struct {
		name                    string
		requestedServiceAccount string
		profileAccounts         []string
		want                    string
		wantErr                 require.ErrorAssertionFunc
	}{
		{
			name:                    "no flag, use default service account",
			requestedServiceAccount: "",
			profileAccounts:         []string{"default@example-123456.iam.gserviceaccount.com"},
			want:                    "default@example-123456.iam.gserviceaccount.com",
			wantErr:                 require.NoError,
		},
		{
			name:                    "no flag, multiple possible service accounts",
			requestedServiceAccount: "",
			profileAccounts:         []string{"id1", "id2"},
			wantErr: func(t require.TestingT, err error, i ...interface{}) {
				require.ErrorContains(t, err, "multiple GCP service accounts available, choose one with --gcp-service-account flag")
			},
		},
		{
			name:                    "no flag, no service accounts",
			requestedServiceAccount: "",
			profileAccounts:         []string{},
			wantErr: func(t require.TestingT, err error, i ...interface{}) {
				require.ErrorContains(t, err, "no GCP service accounts available, check your permissions")
			},
		},
		{
			name:                    "exact match, one option",
			requestedServiceAccount: "id1@example-123456.iam.gserviceaccount.com",
			profileAccounts:         []string{"id1@example-123456.iam.gserviceaccount.com"},
			want:                    "id1@example-123456.iam.gserviceaccount.com",
			wantErr:                 require.NoError,
		},
		{
			name:                    "exact match, multiple options",
			requestedServiceAccount: "id1@example-123456.iam.gserviceaccount.com",
			profileAccounts:         []string{"id1@example-123456.iam.gserviceaccount.com", "id2@example-123456.iam.gserviceaccount.com"},
			want:                    "id1@example-123456.iam.gserviceaccount.com",
			wantErr:                 require.NoError,
		},
		{
			name:                    "no match, multiple options",
			requestedServiceAccount: "id3@example-123456.iam.gserviceaccount.com",
			profileAccounts:         []string{"id1@example-123456.iam.gserviceaccount.com", "id2@example-123456.iam.gserviceaccount.com"},
			wantErr: func(t require.TestingT, err error, i ...interface{}) {
				require.ErrorContains(t, err, "failed to find the service account matching \"id3@example-123456.iam.gserviceaccount.com\"")
			},
		},
		{
			name:                    "prefix match, one option",
			requestedServiceAccount: "id1",
			profileAccounts:         []string{"id1@example-123456.iam.gserviceaccount.com"},
			want:                    "id1@example-123456.iam.gserviceaccount.com",
			wantErr:                 require.NoError,
		},
		{
			name:                    "prefix match, multiple options",
			requestedServiceAccount: "id1",
			profileAccounts: []string{
				"id1@example-123456.iam.gserviceaccount.com",
				"id2@example-123456.iam.gserviceaccount.com",
			},
			want:    "id1@example-123456.iam.gserviceaccount.com",
			wantErr: require.NoError,
		},
		{
			name:                    "ambiguous prefix match",
			requestedServiceAccount: "id1",
			profileAccounts: []string{
				"id1@example-123456.iam.gserviceaccount.com",
				"id1@example-777777.iam.gserviceaccount.com",
			},
			wantErr: func(t require.TestingT, err error, i ...interface{}) {
				require.ErrorContains(t, err, "provided service account \"id1\" is ambiguous, please specify full service account name")
			},
		},
		{
			name:                    "no match, multiple options",
			requestedServiceAccount: "id3@example-123456.iam.gserviceaccount.com",
			profileAccounts: []string{
				"id1@example-123456.iam.gserviceaccount.com",
				"id2@example-123456.iam.gserviceaccount.com",
				"idX@example-777777.iam.gserviceaccount.com",
			},
			wantErr: func(t require.TestingT, err error, i ...interface{}) {
				require.ErrorContains(t, err, "failed to find the service account matching \"id3@example-123456.iam.gserviceaccount.com\"")
			},
		},
		{
			name:                    "service account name is validated",
			requestedServiceAccount: "",
			profileAccounts:         []string{"default"},
			wantErr: func(t require.TestingT, err error, i ...interface{}) {
				require.ErrorContains(t, err, "chosen GCP service account \"default\" is invalid")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := getGCPServiceAccountFromFlags(&CLIConf{GCPServiceAccount: tt.requestedServiceAccount}, &client.ProfileStatus{GCPServiceAccounts: tt.profileAccounts})
			tt.wantErr(t, err)
			require.Equal(t, tt.want, result)
		})
	}
}

func Test_formatGCPServiceAccounts(t *testing.T) {
	tests := []struct {
		name     string
		accounts []string
		want     string
	}{
		{
			name:     "empty",
			accounts: nil,
			want:     "",
		},
		{
			name: "multiple, unsorted",
			accounts: []string{
				"test-3@example-123456.iam.gserviceaccount.com",
				"test-2@example-123456.iam.gserviceaccount.com",
				"test-1@example-123456.iam.gserviceaccount.com",
				"test-0@example-100200.iam.gserviceaccount.com",
				"test-0@other-999999.iam.gserviceaccount.com",
			},
			want: `Available GCP service accounts                
--------------------------------------------- 
test-0@example-100200.iam.gserviceaccount.com 
test-1@example-123456.iam.gserviceaccount.com 
test-2@example-123456.iam.gserviceaccount.com 
test-3@example-123456.iam.gserviceaccount.com 
test-0@other-999999.iam.gserviceaccount.com   
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, formatGCPServiceAccounts(tt.accounts))
		})
	}
}

func Test_gcpApp_Config(t *testing.T) {
	cf := &CLIConf{HomePath: t.TempDir()}
	profile := &client.ProfileStatus{}
	route := tlsca.RouteToApp{
		ClusterName:       "test.teleport.io",
		Name:              "myapp",
		GCPServiceAccount: "test@myproject-123456.iam.gserviceaccount.com",
	}

	t.Setenv("TELEPORT_GCLOUD_SECRET", "my_secret")

	app, err := newGCPApp(cf, profile, route)
	require.NoError(t, err)
	require.NotNil(t, app)

	require.Equal(t, "my_secret", app.secret)
	require.Equal(t, cf.HomePath+"/gcp/test.teleport.io/myapp/gcloud", app.getGcloudConfigPath())

	require.Equal(t, "c45b4408", app.prefix)

	require.NoError(t, app.writeBotoConfig())

	require.Equal(t, cf.HomePath+"/gcp/test.teleport.io/myapp", app.getBotoConfigDir())

	require.Equal(t, cf.HomePath+"/gcp/test.teleport.io/myapp/c45b4408_boto.cfg", app.getBotoConfigPath())
	expectedBotoConfig := fmt.Sprintf(`[Credentials]
gs_external_account_authorized_user_file = %v/gcp/test.teleport.io/myapp/c45b4408_external.json
`, cf.HomePath)
	require.Equal(t, expectedBotoConfig, app.getBotoConfig())
	out, err := os.ReadFile(app.getBotoConfigPath())
	require.NoError(t, err)
	require.Equal(t, expectedBotoConfig, string(out))

	expectedExternalAccountFile := `{ "type": "external_account_authorized_user","token": "my_secret" }`
	require.Equal(t, cf.HomePath+"/gcp/test.teleport.io/myapp/c45b4408_external.json", app.getExternalAccountFilePath())
	require.Equal(t, expectedExternalAccountFile, app.getExternalAccountFile())
	out, err = os.ReadFile(app.getExternalAccountFilePath())
	require.NoError(t, err)
	require.Equal(t, expectedExternalAccountFile, string(out))

	require.NoError(t, trace.NewAggregate(app.removeBotoConfig()...))

	env, err := app.GetEnvVars()
	require.NoError(t, err)
	require.Equal(t, map[string]string{
		"CLOUDSDK_AUTH_ACCESS_TOKEN":         "my_secret",
		"CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE": "keys/-app/myapp-localca.pem",
		"CLOUDSDK_CORE_PROJECT":              "myproject-123456",
		"CLOUDSDK_CONFIG":                    app.getGcloudConfigPath(),
		"BOTO_CONFIG":                        app.getBotoConfigPath(),
	}, env)
}
