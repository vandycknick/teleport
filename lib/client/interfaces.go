/*
Copyright 2015-2021 Gravitational, Inc.

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

package client

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/gravitational/trace"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/constants"
	apiutils "github.com/gravitational/teleport/api/utils"
	"github.com/gravitational/teleport/api/utils/keys"
	apisshutils "github.com/gravitational/teleport/api/utils/sshutils"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/native"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"
)

// KeyIndex helps to identify a key in the store.
type KeyIndex struct {
	// ProxyHost is the root proxy hostname that a key is associated with.
	ProxyHost string
	// Username is the username that a key is associated with.
	Username string
	// ClusterName is the cluster name that a key is associated with.
	ClusterName string
}

// Check verifies the KeyIndex is fully specified.
func (idx KeyIndex) Check() error {
	missingField := "key index field %s is not set"
	if idx.ProxyHost == "" {
		return trace.BadParameter(missingField, "ProxyHost")
	}
	if idx.Username == "" {
		return trace.BadParameter(missingField, "Username")
	}
	if idx.ClusterName == "" {
		return trace.BadParameter(missingField, "ClusterName")
	}
	return nil
}

// Match compares this key index to the given matchKey index.
// It will be considered a match if all non-zero elements of
// the matchKey are matched by this key index.
func (idx KeyIndex) Match(matchKey KeyIndex) bool {
	return (matchKey.ProxyHost == "" || matchKey.ProxyHost == idx.ProxyHost) &&
		(matchKey.ClusterName == "" || matchKey.ClusterName == idx.ClusterName) &&
		(matchKey.Username == "" || matchKey.Username == idx.Username)
}

// Key describes a complete (signed) client key
type Key struct {
	KeyIndex

	// PrivateKey is a private key used for cryptographical operations.
	*keys.PrivateKey

	// Cert is an SSH client certificate
	Cert []byte `json:"Cert,omitempty"`
	// TLSCert is a PEM encoded client TLS x509 certificate.
	// It's used to authenticate to the Teleport APIs.
	TLSCert []byte `json:"TLSCert,omitempty"`
	// KubeTLSCerts are TLS certificates (PEM-encoded) for individual
	// kubernetes clusters. Map key is a kubernetes cluster name.
	KubeTLSCerts map[string][]byte `json:"KubeCerts,omitempty"`
	// DBTLSCerts are PEM-encoded TLS certificates for database access.
	// Map key is the database service name.
	DBTLSCerts map[string][]byte `json:"DBCerts,omitempty"`
	// AppTLSCerts are TLS certificates for application access.
	// Map key is the application name.
	AppTLSCerts map[string][]byte `json:"AppCerts,omitempty"`
	// WindowsDesktopCerts are TLS certificates for Windows Desktop access.
	// Map key is the desktop server name.
	WindowsDesktopCerts map[string][]byte `json:"WindowsDesktopCerts,omitempty"`
	// TrustedCerts is a list of trusted certificate authorities
	TrustedCerts []auth.TrustedCerts
}

// Copy returns a shallow copy of k, or nil if k is nil.
func (k *Key) Copy() *Key {
	if k == nil {
		return nil
	}
	copy := *k
	return &copy
}

// GenerateRSAKey generates a new unsigned key.
func GenerateRSAKey() (*Key, error) {
	priv, err := native.GeneratePrivateKey()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return NewKey(priv), nil
}

// NewKey creates a new Key for the given private key.
func NewKey(priv *keys.PrivateKey) *Key {
	return &Key{
		PrivateKey:          priv,
		KubeTLSCerts:        make(map[string][]byte),
		DBTLSCerts:          make(map[string][]byte),
		AppTLSCerts:         make(map[string][]byte),
		WindowsDesktopCerts: make(map[string][]byte),
	}
}

// RootClusterCAs returns root cluster CAs.
func (k *Key) RootClusterCAs() ([][]byte, error) {
	rootClusterName, err := k.RootClusterName()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var out [][]byte
	for _, cas := range k.TrustedCerts {
		for _, v := range cas.TLSCertificates {
			cert, err := tlsca.ParseCertificatePEM(v)
			if err != nil {
				return nil, trace.Wrap(err)
			}
			if cert.Subject.CommonName == rootClusterName {
				out = append(out, v)
			}
		}
	}
	if len(out) > 0 {
		return out, nil
	}
	return nil, trace.NotFound("failed to find TLS CA for %q root cluster", rootClusterName)
}

// TLSCAs returns all TLS CA certificates from this key
func (k *Key) TLSCAs() (result [][]byte) {
	for _, ca := range k.TrustedCerts {
		result = append(result, ca.TLSCertificates...)
	}
	return result
}

func (k *Key) KubeClientTLSConfig(cipherSuites []uint16, kubeClusterName string) (*tls.Config, error) {
	rootCluster, err := k.RootClusterName()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	tlsCert, ok := k.KubeTLSCerts[kubeClusterName]
	if !ok {
		return nil, trace.NotFound("TLS certificate for kubernetes cluster %q not found", kubeClusterName)
	}

	tlsConfig, err := k.clientTLSConfig(cipherSuites, tlsCert, []string{rootCluster})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	tlsConfig.ServerName = fmt.Sprintf("%s%s", constants.KubeSNIPrefix, constants.APIDomain)
	return tlsConfig, nil
}

// HostKeyCallback returns a host key callback that checks if the given host key was signed
// by a Teleport certificate authority (CA) or a host certificate the user has seen before.
func (k *Key) HostKeyCallback(hostname string) ssh.HostKeyCallback {
	return func(addr string, remote net.Addr, key ssh.PublicKey) error {
		certChecker := apisshutils.CertChecker{
			CertChecker: ssh.CertChecker{
				IsHostAuthority: func(key ssh.PublicKey, addr string) bool {
					for _, ak := range k.AuthorizedHostKeys(hostname) {
						authorizedKey, _, _, _, err := ssh.ParseAuthorizedKey(ak)
						if err != nil {
							log.Errorf("Failed to parse authorized key: %v; raw key: %s", err, string(ak))
							return false
						}
						if apisshutils.KeysEqual(authorizedKey, key) {
							return true
						}
					}
					return false
				},
				HostKeyFallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
					for _, ak := range k.AuthorizedHostKeys(hostname) {
						authorizedKey, _, _, _, err := ssh.ParseAuthorizedKey(ak)
						if err != nil {
							return trace.Wrap(err)
						}
						if apisshutils.KeysEqual(authorizedKey, key) {
							return nil
						}
					}
					return trace.BadParameter("host %s presented a public key not signed by Teleport", hostname)
				},
			},
			FIPS: isFIPS(),
		}
		err := certChecker.CheckHostKey(addr, remote, key)
		if err != nil {
			log.Debugf("Host validation failed: %v.", err)
			return trace.Wrap(err)
		}
		log.Debugf("Validated host %v.", addr)
		return nil
	}
}

// AuthorizedHostKeys returns all authorized host keys from this key. If any host
// names are provided, only matching host keys will be returned.
func (k *Key) AuthorizedHostKeys(hostnames ...string) (result [][]byte) {
	for _, ca := range k.TrustedCerts {
		// Mirror the hosts we would find in a known_hosts entry.
		hosts := []string{k.ProxyHost, ca.ClusterName, "*." + ca.ClusterName}

		if len(hostnames) == 0 || apisshutils.HostNameMatch(hostnames, hosts) {
			result = append(result, ca.AuthorizedKeys...)
		}
	}
	return result
}

// TeleportClientTLSConfig returns client TLS configuration used
// to authenticate against API servers.
func (k *Key) TeleportClientTLSConfig(cipherSuites []uint16, clusters []string) (*tls.Config, error) {
	return k.clientTLSConfig(cipherSuites, k.TLSCert, clusters)
}

func (k *Key) clientTLSConfig(cipherSuites []uint16, tlsCertRaw []byte, clusters []string) (*tls.Config, error) {
	tlsCert, err := k.TLSCertificate(tlsCertRaw)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	pool, err := k.clientCertPool(clusters...)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	tlsConfig := utils.TLSConfig(cipherSuites)
	tlsConfig.RootCAs = pool
	tlsConfig.Certificates = append(tlsConfig.Certificates, tlsCert)
	// Use Issuer CN from the certificate to populate the correct SNI in
	// requests.
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, trace.Wrap(err, "failed to parse TLS cert")
	}
	tlsConfig.ServerName = apiutils.EncodeClusterName(leaf.Issuer.CommonName)
	return tlsConfig, nil
}

// ClientCertPool returns x509.CertPool containing trusted CA.
func (k *Key) clientCertPool(clusters ...string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	for _, caPEM := range k.TLSCAs() {
		cert, err := tlsca.ParseCertificatePEM(caPEM)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		for _, k := range clusters {
			if cert.Subject.CommonName == k {
				if !pool.AppendCertsFromPEM(caPEM) {
					return nil, trace.BadParameter("failed to parse TLS CA certificate")
				}
			}
		}
	}
	return pool, nil
}

// ProxyClientSSHConfig returns an ssh.ClientConfig with SSH credentials from this
// Key and HostKeyCallback matching SSH CAs in the Key.
//
// The config is set up to authenticate to proxy with the first available principal
// and ( if keyStore != nil ) trust local SSH CAs without asking for public keys.
func (k *Key) ProxyClientSSHConfig(hostname string) (*ssh.ClientConfig, error) {
	sshCert, err := k.SSHCert()
	if err != nil {
		return nil, trace.Wrap(err, "failed to extract username from SSH certificate")
	}

	sshConfig, err := apisshutils.ProxyClientSSHConfig(sshCert, k)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	sshConfig.HostKeyCallback = k.HostKeyCallback(hostname)

	return sshConfig, nil
}

// CertUsername returns the name of the Teleport user encoded in the SSH certificate.
func (k *Key) CertUsername() (string, error) {
	cert, err := k.SSHCert()
	if err != nil {
		return "", trace.Wrap(err)
	}
	return cert.KeyId, nil
}

// CertPrincipals returns the principals listed on the SSH certificate.
func (k *Key) CertPrincipals() ([]string, error) {
	cert, err := k.SSHCert()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return cert.ValidPrincipals, nil
}

func (k *Key) CertRoles() ([]string, error) {
	cert, err := k.SSHCert()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	// Extract roles from certificate. Note, if the certificate is in old format,
	// this will be empty.
	var roles []string
	rawRoles, ok := cert.Extensions[teleport.CertExtensionTeleportRoles]
	if ok {
		roles, err = services.UnmarshalCertRoles(rawRoles)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return roles, nil
}

const (
	agentKeyCommentPrefix    = "teleport"
	agentKeyCommentSeparator = ":"
)

// teleportAgentKeyComment returns a teleport agent key comment
// like "teleport:<proxyHost>:<userName>:<clusterName>".
func teleportAgentKeyComment(k KeyIndex) string {
	return strings.Join([]string{
		agentKeyCommentPrefix,
		k.ProxyHost,
		k.ClusterName,
		k.Username,
	}, agentKeyCommentSeparator)
}

// parseTeleportAgentKeyComment parses an agent key comment into
// its associated KeyIndex.
func parseTeleportAgentKeyComment(comment string) (KeyIndex, bool) {
	parts := strings.Split(comment, agentKeyCommentSeparator)
	if len(parts) != 4 || parts[0] != agentKeyCommentPrefix {
		return KeyIndex{}, false
	}

	return KeyIndex{
		ProxyHost:   parts[1],
		ClusterName: parts[2],
		Username:    parts[3],
	}, true
}

// isTeleportAgentKey returns whether the given agent key was added
// by Teleport by checking the key's comment.
func isTeleportAgentKey(key *agent.Key) bool {
	return strings.HasPrefix(key.Comment, agentKeyCommentPrefix+agentKeyCommentSeparator)
}

// AsAgentKey converts PrivateKey to a agent.AddedKey. If the given PrivateKey is not
// supported as an agent key, a trace.NotImplemented error is returned.
func (k *Key) AsAgentKey() (agent.AddedKey, error) {
	sshCert, err := k.SSHCert()
	if err != nil {
		return agent.AddedKey{}, trace.Wrap(err)
	}

	switch k.Signer.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
		return agent.AddedKey{
			PrivateKey:       k.Signer,
			Certificate:      sshCert,
			Comment:          teleportAgentKeyComment(k.KeyIndex),
			LifetimeSecs:     0,
			ConfirmBeforeUse: false,
		}, nil
	default:
		// We return a not implemented error because agent.AddedKey only
		// supports plain RSA, ECDSA, and ED25519 keys. Non-standard private
		// keys, like hardware-based private keys, will require custom solutions
		// which may not be included in their initial implementation. This will
		// only affect functionality related to agent forwarding, so we give the
		// caller the ability to handle the error gracefully.
		return agent.AddedKey{}, trace.NotImplemented("cannot create an agent key using private key signer of type %T", k.Signer)
	}
}

// TeleportTLSCertificate returns the parsed x509 certificate for
// authentication against Teleport APIs.
func (k *Key) TeleportTLSCertificate() (*x509.Certificate, error) {
	return tlsca.ParseCertificatePEM(k.TLSCert)
}

// KubeTLSCertificate returns the parsed x509 certificate for
// authentication against a named kubernetes cluster.
func (k *Key) KubeTLSCertificate(kubeClusterName string) (*x509.Certificate, error) {
	tlsCert, ok := k.KubeTLSCerts[kubeClusterName]
	if !ok {
		return nil, trace.NotFound("TLS certificate for kubernetes cluster %q not found", kubeClusterName)
	}
	return tlsca.ParseCertificatePEM(tlsCert)
}

// DBTLSCertificates returns all parsed x509 database access certificates.
func (k *Key) DBTLSCertificates() (certs []x509.Certificate, err error) {
	for _, bytes := range k.DBTLSCerts {
		cert, err := tlsca.ParseCertificatePEM(bytes)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		certs = append(certs, *cert)
	}
	return certs, nil
}

// AppTLSCertificates returns all parsed x509 app access certificates.
func (k *Key) AppTLSCertificates() (certs []x509.Certificate, err error) {
	for _, bytes := range k.AppTLSCerts {
		cert, err := tlsca.ParseCertificatePEM(bytes)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		certs = append(certs, *cert)
	}
	return certs, nil
}

// TeleportTLSCertValidBefore returns the time of the TLS cert expiration
func (k *Key) TeleportTLSCertValidBefore() (t time.Time, err error) {
	cert, err := k.TeleportTLSCertificate()
	if err != nil {
		return t, trace.Wrap(err)
	}
	return cert.NotAfter, nil
}

// CertValidBefore returns the time of the cert expiration
func (k *Key) CertValidBefore() (t time.Time, err error) {
	cert, err := k.SSHCert()
	if err != nil {
		return t, trace.Wrap(err)
	}
	return time.Unix(int64(cert.ValidBefore), 0), nil
}

// AsAuthMethod returns an "auth method" interface, a common abstraction
// used by Golang SSH library. This is how you actually use a Key to feed
// it into the SSH lib.
func (k *Key) AsAuthMethod() (ssh.AuthMethod, error) {
	cert, err := k.SSHCert()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return apisshutils.AsAuthMethod(cert, k)
}

// SSHSigner returns an ssh.Signer using the SSH certificate in this key.
func (k *Key) SSHSigner() (ssh.Signer, error) {
	cert, err := k.SSHCert()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return apisshutils.SSHSigner(cert, k)
}

// SSHCert returns parsed SSH certificate
func (k *Key) SSHCert() (*ssh.Certificate, error) {
	if k.Cert == nil {
		return nil, trace.NotFound("SSH cert not available")
	}
	return apisshutils.ParseCertificate(k.Cert)
}

// ActiveRequests gets the active requests associated with this key.
func (k *Key) ActiveRequests() (services.RequestIDs, error) {
	var activeRequests services.RequestIDs
	sshCert, err := k.SSHCert()
	if err != nil {
		return activeRequests, trace.Wrap(err)
	}
	rawRequests, ok := sshCert.Extensions[teleport.CertExtensionTeleportActiveRequests]
	if ok {
		if err := activeRequests.Unmarshal([]byte(rawRequests)); err != nil {
			return activeRequests, trace.Wrap(err)
		}
	}
	return activeRequests, nil
}

// CheckCert makes sure the key's SSH certificate is valid.
func (k *Key) CheckCert() error {
	cert, err := k.SSHCert()
	if err != nil {
		return trace.Wrap(err)
	}

	if err := k.checkCert(cert); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// checkCert makes sure the given SSH certificate is valid.
func (k *Key) checkCert(sshCert *ssh.Certificate) error {
	// Check that the certificate was for the current public key. If not, the
	// public/private key pair may have been rotated.
	if !apisshutils.KeysEqual(sshCert.Key, k.SSHPublicKey()) {
		return trace.CompareFailed("public key in profile does not match the public key in SSH certificate")
	}

	// A valid principal is always passed in because the principals are not being
	// checked here, but rather the validity period, signature, and algorithms.
	certChecker := apisshutils.CertChecker{
		FIPS: isFIPS(),
	}
	if len(sshCert.ValidPrincipals) == 0 {
		return trace.BadParameter("cert is not valid for any principles")
	}
	if err := certChecker.CheckCert(sshCert.ValidPrincipals[0], sshCert); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// RootClusterName extracts the root cluster name from the issuer
// of the Teleport TLS certificate.
func (k *Key) RootClusterName() (string, error) {
	cert, err := k.TeleportTLSCertificate()
	if err != nil {
		return "", trace.Wrap(err)
	}
	clusterName := cert.Issuer.CommonName
	if clusterName == "" {
		return "", trace.NotFound("failed to extract root cluster name from Teleport TLS cert")
	}
	return clusterName, nil
}

// EqualPrivateKey returns whether this key and the given key have the same PrivateKey.
func (k *Key) EqualPrivateKey(other *Key) bool {
	// Compare both private and public key PEM, since hardware keys
	// may not be uniquely identifiable by their private key PEM alone.
	// For example, for PIV keys, the private key PEM only uniquely
	// identifies a PIV slot, so we can use the public key to verify
	// that the private key on the slot hasn't changed.
	return subtle.ConstantTimeCompare(k.PrivateKeyPEM(), other.PrivateKeyPEM()) == 1 &&
		bytes.Equal(k.MarshalSSHPublicKey(), other.MarshalSSHPublicKey())
}
