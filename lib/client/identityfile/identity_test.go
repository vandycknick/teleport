// Copyright 2021 Gravitational, Inc
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

package identityfile

import (
	"bytes"
	"crypto"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport/api/profile"
	"github.com/gravitational/teleport/api/utils/keypaths"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/testauthority"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/kube/kubeconfig"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/sshutils"
	"github.com/gravitational/teleport/lib/tlsca"
)

func newSelfSignedCA(priv crypto.Signer) (*tlsca.CertAuthority, auth.TrustedCerts, error) {
	cert, err := tlsca.GenerateSelfSignedCAWithSigner(priv, pkix.Name{
		CommonName:   "root",
		Organization: []string{"localhost"},
	}, nil, defaults.CATTL)
	if err != nil {
		return nil, auth.TrustedCerts{}, trace.Wrap(err)
	}
	ca, err := tlsca.FromCertAndSigner(cert, priv)
	if err != nil {
		return nil, auth.TrustedCerts{}, trace.Wrap(err)
	}
	sshPub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		return nil, auth.TrustedCerts{}, trace.Wrap(err)
	}
	return ca, auth.TrustedCerts{
		ClusterName:     "root",
		TLSCertificates: [][]byte{cert},
		AuthorizedKeys:  [][]byte{ssh.MarshalAuthorizedKey(sshPub)},
	}, nil
}

func newClientKey(t *testing.T) *client.Key {
	privateKey, err := testauthority.New().GeneratePrivateKey()
	require.NoError(t, err)

	ff, tc, err := newSelfSignedCA(privateKey)
	require.NoError(t, err)
	keygen := testauthority.New()

	clock := clockwork.NewRealClock()
	identity := tlsca.Identity{
		Username: "testuser",
		Groups:   []string{"groups"},
	}

	subject, err := identity.Subject()
	require.NoError(t, err)

	tlsCert, err := ff.GenerateCertificate(tlsca.CertificateRequest{
		Clock:     clock,
		PublicKey: privateKey.Public(),
		Subject:   subject,
		NotAfter:  clock.Now().UTC().Add(defaults.CATTL),
	})
	require.NoError(t, err)

	ta := testauthority.New()
	signer, err := ta.GeneratePrivateKey()
	require.NoError(t, err)
	caSigner, err := ssh.NewSignerFromKey(signer)
	require.NoError(t, err)

	certificate, err := keygen.GenerateUserCert(services.UserCertParams{
		CASigner:      caSigner,
		PublicUserKey: ssh.MarshalAuthorizedKey(privateKey.SSHPublicKey()),
		Username:      "testuser",
		AllowedLogins: []string{"testuser"},
	})
	require.NoError(t, err)

	key := client.NewKey(privateKey)
	key.KeyIndex = client.KeyIndex{
		ProxyHost:   "localhost",
		Username:    "testuser",
		ClusterName: "root",
	}
	key.Cert = certificate
	key.TLSCert = tlsCert
	key.TrustedCerts = []auth.TrustedCerts{tc}

	return key
}

func TestWrite(t *testing.T) {
	key := newClientKey(t)

	outputDir := t.TempDir()
	cfg := WriteConfig{Key: key}

	// test OpenSSH-compatible identity file creation:
	cfg.OutputPath = filepath.Join(outputDir, "openssh")
	cfg.Format = FormatOpenSSH
	_, err := Write(cfg)
	require.NoError(t, err)

	// key is OK:
	out, err := os.ReadFile(cfg.OutputPath)
	require.NoError(t, err)
	require.Equal(t, string(out), string(key.PrivateKeyPEM()))

	// cert is OK:
	out, err = os.ReadFile(keypaths.IdentitySSHCertPath(cfg.OutputPath))
	require.NoError(t, err)
	require.Equal(t, string(out), string(key.Cert))

	// test standard Teleport identity file creation:
	cfg.OutputPath = filepath.Join(outputDir, "file")
	cfg.Format = FormatFile
	_, err = Write(cfg)
	require.NoError(t, err)

	// key+cert are OK:
	out, err = os.ReadFile(cfg.OutputPath)
	require.NoError(t, err)

	knownHosts, err := sshutils.MarshalKnownHost(sshutils.KnownHost{
		Hostname:      key.ClusterName,
		ProxyHost:     key.ProxyHost,
		AuthorizedKey: key.TrustedCerts[0].AuthorizedKeys[0],
	})
	require.NoError(t, err)

	wantArr := [][]byte{
		key.PrivateKeyPEM(),
		key.Cert,
		key.TLSCert,
		[]byte(knownHosts),
		bytes.Join(key.TrustedCerts[0].TLSCertificates, []byte{}),
	}
	want := string(bytes.Join(wantArr, nil))
	require.Equal(t, want, string(out))

	// Test kubeconfig creation.
	cfg.OutputPath = filepath.Join(outputDir, "kubeconfig")
	cfg.Format = FormatKubernetes
	cfg.KubeProxyAddr = "far.away.cluster"
	cfg.KubeTLSServerName = "kube.far.away.cluster"
	_, err = Write(cfg)
	require.NoError(t, err)
	assertKubeconfigContents(t, cfg.OutputPath, key.ClusterName, "far.away.cluster", cfg.KubeTLSServerName)
}

func TestWriteAllFormats(t *testing.T) {
	for _, format := range KnownFileFormats {
		t.Run(string(format), func(t *testing.T) {
			key := newClientKey(t)

			cfg := WriteConfig{
				OutputPath: path.Join(t.TempDir(), "identity"),
				Key:        key,
				Format:     format,
			}

			// extra fields for kubernetes
			if format == FormatKubernetes {
				cfg.KubeProxyAddr = "far.away.cluster"
				cfg.KubeTLSServerName = "kube.far.away.cluster"
			}

			// for cockroach, output path should be a directory
			if format == FormatCockroach {
				cfg.OutputPath = t.TempDir()
			}

			files, err := Write(cfg)
			require.NoError(t, err)
			for _, file := range files {
				require.True(t, strings.HasPrefix(file, cfg.OutputPath))
			}
			require.True(t, len(files) > 0)
		})
	}
}

func TestKubeconfigOverwrite(t *testing.T) {
	key := newClientKey(t)

	// First write an ssh key to the file.
	cfg := WriteConfig{
		OutputPath:           filepath.Join(t.TempDir(), "out"),
		Format:               FormatFile,
		Key:                  key,
		OverwriteDestination: true,
	}
	_, err := Write(cfg)
	require.NoError(t, err)

	// Write a kubeconfig to the same file path. It should be overwritten.
	cfg.Format = FormatKubernetes
	cfg.KubeProxyAddr = "far.away.cluster"
	_, err = Write(cfg)
	require.NoError(t, err)
	assertKubeconfigContents(t, cfg.OutputPath, key.ClusterName, "far.away.cluster", "")

	// Write a kubeconfig for a different cluster to the same file path. It
	// should be overwritten.
	cfg.KubeProxyAddr = "other.cluster"
	cfg.KubeTLSServerName = "kube.other.cluster"
	_, err = Write(cfg)
	require.NoError(t, err)
	assertKubeconfigContents(t, cfg.OutputPath, key.ClusterName, "other.cluster", cfg.KubeTLSServerName)
}

func assertKubeconfigContents(t *testing.T, path, clusterName, serverAddr, kubeTLSName string) {
	t.Helper()

	kc, err := kubeconfig.Load(path)
	require.NoError(t, err)

	require.Len(t, kc.AuthInfos, 1)
	require.Len(t, kc.Contexts, 1)
	require.Len(t, kc.Clusters, 1)
	require.Equal(t, kc.Clusters[clusterName].Server, serverAddr)
	require.Equal(t, kc.Clusters[clusterName].TLSServerName, kubeTLSName)
}

func TestIdentityRead(t *testing.T) {
	t.Parallel()

	// 3 different types of identities
	ids := []string{
		"cert-key.pem", // cert + key concatenated together, cert first
		"key-cert.pem", // cert + key concatenated together, key first
		"key",          // two separate files: key and key-cert.pub
	}
	for _, id := range ids {
		// test reading:
		k, err := KeyFromIdentityFile(fixturePath(fmt.Sprintf("certs/identities/%s", id)), "proxy.example.com", "")
		require.NoError(t, err)
		require.NotNil(t, k)

		// test creating an auth method from the key:
		am, err := k.AsAuthMethod()
		require.NoError(t, err)
		require.NotNil(t, am)
	}
	k, err := KeyFromIdentityFile(fixturePath("certs/identities/lonekey"), "proxy.example.com", "")
	require.Nil(t, k)
	require.Error(t, err)

	// lets read an identity which includes a CA cert
	k, err = KeyFromIdentityFile(fixturePath("certs/identities/key-cert-ca.pem"), "proxy.example.com", "")
	require.NoError(t, err)
	require.NotNil(t, k)

	// prepare the cluster CA separately
	certBytes, err := os.ReadFile(fixturePath("certs/identities/ca.pem"))
	require.NoError(t, err)

	_, hosts, cert, _, _, err := ssh.ParseKnownHosts(certBytes)
	require.NoError(t, err)

	var a net.Addr
	// host auth callback must succeed
	cb := k.HostKeyCallback("proxy.example.com")
	require.NoError(t, cb(hosts[0], a, cert))

	// load an identity which include TLS certificates
	k, err = KeyFromIdentityFile(fixturePath("certs/identities/tls.pem"), "proxy.example.com", "")
	require.NoError(t, err)
	require.NotNil(t, k)
	require.NotNil(t, k.TLSCert)

	// generate a TLS client config
	conf, err := k.TeleportClientTLSConfig(nil, []string{"one"})
	require.NoError(t, err)
	require.NotNil(t, conf)
}

func fixturePath(path string) string {
	return "../../../fixtures/" + path
}

func TestKeyFromIdentityFile(t *testing.T) {
	t.Parallel()
	key := newClientKey(t)
	key.ProxyHost = "proxy.example.com"
	key.ClusterName = "cluster"

	identityFilePath := filepath.Join(t.TempDir(), "out")

	// First write an ssh key to the file.
	_, err := Write(WriteConfig{
		OutputPath:           identityFilePath,
		Format:               FormatFile,
		Key:                  key,
		OverwriteDestination: true,
	})
	require.NoError(t, err)

	// parsed key is unchanged from original with proxy and cluster provided.
	parsedKey, err := KeyFromIdentityFile(identityFilePath, key.ProxyHost, key.ClusterName)
	require.NoError(t, err)
	require.Equal(t, key, parsedKey)

	// Identity file's cluster name defaults to root cluster name.
	parsedKey, err = KeyFromIdentityFile(identityFilePath, key.ProxyHost, "")
	key.ClusterName = "root"
	require.NoError(t, err)
	require.Equal(t, key, parsedKey)

	// Returns error if proxy host is not provided.
	_, err = KeyFromIdentityFile(identityFilePath, "", "")
	require.Error(t, err)
	require.True(t, trace.IsBadParameter(err))
}

func TestNewClientStoreFromIdentityFile(t *testing.T) {
	t.Parallel()
	key := newClientKey(t)
	key.ProxyHost = "proxy.example.com"
	key.ClusterName = "cluster"

	identityFilePath := filepath.Join(t.TempDir(), "out")

	// First write an ssh key to the file.
	_, err := Write(WriteConfig{
		OutputPath:           identityFilePath,
		Format:               FormatFile,
		Key:                  key,
		OverwriteDestination: true,
	})
	require.NoError(t, err)

	clientStore, err := NewClientStoreFromIdentityFile(identityFilePath, key.ProxyHost+":3080", key.ClusterName)
	require.NoError(t, err)

	currentProfile, err := clientStore.CurrentProfile()
	require.NoError(t, err)
	require.Equal(t, key.ProxyHost, currentProfile)

	retrievedProfile, err := clientStore.GetProfile(currentProfile)
	require.NoError(t, err)
	require.Equal(t, &profile.Profile{
		WebProxyAddr: key.ProxyHost + ":3080",
		SiteName:     key.ClusterName,
		Username:     key.Username,
	}, retrievedProfile)

	retrievedKey, err := clientStore.GetKey(key.KeyIndex, client.WithAllCerts...)
	require.NoError(t, err)
	require.Equal(t, key, retrievedKey)
}
