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

package sqlserver

import (
	"context"
	_ "embed"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/srv/db/common"
	"github.com/gravitational/teleport/lib/srv/db/sqlserver/protocol"
)

//go:embed kinit/testdata/kinit.cache
var cacheData []byte

// TestConnectorSelection given a database session, choose correctly which
// connector to use. This test doesn't cover the connection flow, only the
// selection logic.
func TestConnectorSelection(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	connector := &connector{DBAuth: &mockDBAuth{}}

	for _, tt := range []struct {
		desc         string
		databaseSpec types.DatabaseSpecV3
		errAssertion require.ErrorAssertionFunc
	}{
		{
			desc: "Non-Azure database",
			databaseSpec: types.DatabaseSpecV3{
				Protocol: defaults.ProtocolSQLServer,
				URI:      "sqlserver:1443",
			},
			// When using a non-Azure database, the connector should fail
			// loading Kerberos credentials.
			errAssertion: func(t require.TestingT, err error, _ ...interface{}) {
				require.Error(t, err)
				require.ErrorIs(t, err, errBadKerberosConfig)
			},
		},
		{
			desc: "Azure database with AD configured",
			databaseSpec: types.DatabaseSpecV3{
				Protocol: defaults.ProtocolSQLServer,
				URI:      "name.database.windows.net:1443",
				AD: types.AD{
					// Domain is required for AD authentication.
					Domain: "EXAMPLE.COM",
				},
			},
			// When using a Azure database with AD configuration, the connector
			// should fail loading Kerberos credentials.
			errAssertion: func(t require.TestingT, err error, _ ...interface{}) {
				require.Error(t, err)
				require.ErrorIs(t, err, errBadKerberosConfig)
			},
		},
		{
			desc: "Azure database without AD configured",
			databaseSpec: types.DatabaseSpecV3{
				Protocol: defaults.ProtocolSQLServer,
				URI:      "random.database.windows.net:1443",
			},
			// When using a Azure database without AD configuration, the
			// connector should fail because it could not connect to the
			// database.
			errAssertion: func(t require.TestingT, err error, _ ...interface{}) {
				require.Error(t, err)
				require.Contains(t, err.Error(), "unable to open tcp connection with host")
			},
		},
	} {
		t.Run(tt.desc, func(t *testing.T) {
			database, err := types.NewDatabaseV3(types.Metadata{
				Name: uuid.NewString(),
			}, tt.databaseSpec)
			require.NoError(t, err)

			connectorCtx, cancel := context.WithCancel(ctx)
			defer cancel()

			resChan := make(chan error, 1)
			go func() {
				_, _, err = connector.Connect(connectorCtx, &common.Session{Database: database}, &protocol.Login7Packet{})
				resChan <- err
			}()

			// Cancel the context to avoid dialing databases.
			cancel()

			select {
			case err := <-resChan:
				tt.errAssertion(t, err)
			case <-ctx.Done():
				require.Fail(t, "timed out waiting for connector to return")
			}
		})
	}
}

type staticCache struct {
	t    *testing.T
	pass bool
}

func (s *staticCache) CommandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	cachePath := args[len(args)-1]
	require.NotEmpty(s.t, cachePath)
	err := os.WriteFile(cachePath, cacheData, 0664)
	require.NoError(s.t, err)

	if s.pass {
		return exec.Command("echo")
	}
	cmd := exec.Command("")
	cmd.Err = errors.New("bad command")
	return cmd
}

const (
	mockCA = `-----BEGIN CERTIFICATE-----
MIIECzCCAvOgAwIBAgIRAPEVuzVonTAvpOMyNii7nOAwDQYJKoZIhvcNAQELBQAw
gZ4xNDAyBgNVBAoTK2NlcmVicm8uYWxpc3RhbmlzLmdpdGh1Yi5iZXRhLnRhaWxz
Y2FsZS5uZXQxNDAyBgNVBAMTK2NlcmVicm8uYWxpc3RhbmlzLmdpdGh1Yi5iZXRh
LnRhaWxzY2FsZS5uZXQxMDAuBgNVBAUTJzMyMDQ1Njc4MjI2MDI1ODkyMjc5NTk2
NDc0MTEyOTU0ODMwNzY4MDAeFw0yMjA2MDcwNDQ4MzhaFw0zMjA2MDQwNDQ4Mzha
MIGeMTQwMgYDVQQKEytjZXJlYnJvLmFsaXN0YW5pcy5naXRodWIuYmV0YS50YWls
c2NhbGUubmV0MTQwMgYDVQQDEytjZXJlYnJvLmFsaXN0YW5pcy5naXRodWIuYmV0
YS50YWlsc2NhbGUubmV0MTAwLgYDVQQFEyczMjA0NTY3ODIyNjAyNTg5MjI3OTU5
NjQ3NDExMjk1NDgzMDc2ODAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQDJVqHTgx9pdPHCrDJ0UtbZMVL/xhihuR44AY8aqSebJbKc/WrYLIJxqO1q8L4c
B+sfblIMMz/Em1IZ3ZF7AajiJFSn8VfGx5xtxC06YWPY3HfflcuY5kGVWtYl8ReD
7j3FJjNq4Rvv+NoYwmQXYw6Nwu90cWHerDY3G0fQOsjgUAipnTS4+/H36pBakNoK
9pipl3Kb6YVtjdxY6KY0gSy0k8NiRUx8sCpxJOwfUSAvtsGd1tw1388ZfWr2Bl2d
st2H+q1ozLZ3IQXSgSl6s63JmvWpsElg8+nXZKB3CNTIhrOvvyV33Ok5uAQ44nel
vLy5r3o2OguPjvC+SrkHn1avAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBpjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR0fa5/2sVguUfn8MHmC7DoFl58fzANBgkq
hkiG9w0BAQsFAAOCAQEAAOEBowwaigoFG3rxM5euIyfax2gWPXN63YF3vd5IN75C
gzimkq9c6MRsvaS053xbRF5NncectmBzTY3WQscJ30+tHD84fA5VQCt//lA+G9gi
g8Co+YPraQe8kbZEcAFceGpWrKjCEwiWlrlM56VfmKmGws21N/PBIb5aO0aEHuWs
HOhXH/n0dKrb7IJcpUh0/w02qiUQ6I0usjGwRlE3xkPyWgEkKUcy+eBrfVVV++8e
HDKyflZ05nt/zvM6W/WIeMI7VMPw/Ryr7iynMqAYAhJhTFKdSwuNLDY8eFbOUnbw
21sZcc/b5g+C9N+0lbFxUUF99bt6jLOVUwpR7LRP2g==
-----END CERTIFICATE-----`

	krb5Conf = `[libdefaults]
 default_realm = example.com
 rdns = false


[realms]
 example.com = {
  kdc = host.example.com
  admin_server = host.example.com
  pkinit_eku_checking = kpServerAuth
  pkinit_kdc_hostname = host.example.com
 }`
)

type mockAuth struct{}

func (m *mockAuth) GenerateWindowsDesktopCert(ctx context.Context, request *proto.WindowsDesktopCertRequest) (*proto.WindowsDesktopCertResponse, error) {
	return nil, nil
}

func (m *mockAuth) GetCertAuthority(ctx context.Context, id types.CertAuthID, loadKeys bool, opts ...services.MarshalOption) (types.CertAuthority, error) {
	return nil, nil
}

func (m *mockAuth) GetClusterName(opts ...services.MarshalOption) (types.ClusterName, error) {
	return types.NewClusterName(types.ClusterNameSpecV2{
		ClusterName: "TestCluster",
		ClusterID:   "TestClusterID",
	})
}

func (m *mockAuth) GenerateDatabaseCert(context.Context, *proto.DatabaseCertRequest) (*proto.DatabaseCertResponse, error) {
	return &proto.DatabaseCertResponse{Cert: []byte(mockCA)}, nil
}

func TestConnectorKInitClient(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	connector := &connector{
		DBAuth:                &mockDBAuth{},
		AuthClient:            &mockAuth{},
		kinitCommandGenerator: &staticCache{t: t, pass: true},
		caFunc: func(ctx context.Context, clusterName string) ([]byte, error) {
			return []byte(mockCA), nil
		},
	}

	krbConfPath := filepath.Join(dir, "krb5.conf")
	err := os.WriteFile(krbConfPath, []byte(krb5Conf), 0664)
	require.NoError(t, err)

	for _, tt := range []struct {
		desc         string
		databaseSpec types.DatabaseSpecV3
		errAssertion require.ErrorAssertionFunc
	}{
		{
			desc: "AD-x509-Loads_and_fails_with_expired_cache",
			databaseSpec: types.DatabaseSpecV3{
				Protocol: defaults.ProtocolSQLServer,
				URI:      "sqlserver:1443",
				AD: types.AD{
					LDAPCert:    mockCA,
					KDCHostName: "kdc.example.com",
					Krb5File:    krbConfPath,
				},
			},
			// When using a non-Azure database, the connector should attempt to get a kinit client
			errAssertion: func(t require.TestingT, err error, _ ...interface{}) {
				require.Error(t, err)
				// we can't get a new TGT without an actual kerberos implementation, so we are relying on the existing
				// credentials cache being expired
				require.ErrorContains(t, err, "cannot login, no user credentials available and no valid existing session")
			},
		},
		{
			desc: "AD-x509-Fails_to_load_with_bad_config",
			databaseSpec: types.DatabaseSpecV3{
				Protocol: defaults.ProtocolSQLServer,
				URI:      "sqlserver:1443",
				AD:       types.AD{},
			},
			// When using a non-Azure database, the connector should attempt to get a kinit client
			errAssertion: func(t require.TestingT, err error, _ ...interface{}) {
				require.Error(t, err)
				// we can't get a new TGT without an actual kerberos implementation, so we are relying on the existing
				// credentials cache being expired
				require.ErrorIs(t, err, errBadKerberosConfig)
			},
		},
		{
			desc: "AD-x509-Fails_with_invalid_certificate",
			databaseSpec: types.DatabaseSpecV3{
				Protocol: defaults.ProtocolSQLServer,
				URI:      "sqlserver:1443",
				AD: types.AD{
					LDAPCert:    "BEGIN CERTIFICATE",
					KDCHostName: "kdc.example.com",
					Krb5File:    krbConfPath,
				},
			},
			// When using a non-Azure database, the connector should attempt to get a kinit client
			errAssertion: func(t require.TestingT, err error, _ ...interface{}) {
				require.Error(t, err)
				// we can't get a new TGT without an actual kerberos implementation, so we are relying on the existing
				// credentials cache being expired
				require.ErrorIs(t, err, errBadCertificate)
			},
		},
	} {
		t.Run(tt.desc, func(t *testing.T) {
			database, err := types.NewDatabaseV3(types.Metadata{
				Name: uuid.NewString(),
			}, tt.databaseSpec)
			require.NoError(t, err)

			databaseUser := "alice"
			databaseName := database.GetName()
			connector.DataDir = dir

			connectorCtx, cancel := context.WithCancel(ctx)
			// we want to pass the canceled context
			// because we don't actually initiate a real login,
			// and the context will get checked in the SQLServer connector
			// logic
			cancel()

			resChan := make(chan error, 1)
			go func() {
				_, _, err = connector.Connect(connectorCtx,
					&common.Session{
						Database:     database,
						DatabaseUser: databaseUser,
						DatabaseName: databaseName},
					&protocol.Login7Packet{})
				resChan <- err
			}()

			select {
			case err := <-resChan:
				tt.errAssertion(t, err)
			case <-ctx.Done():
				require.Fail(t, "timed out waiting for connector to return")
			}
		})
	}
}
