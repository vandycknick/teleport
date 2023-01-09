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

package client

import (
	"crypto"
	"io"
	"net/url"
	"time"

	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/profile"
	"github.com/gravitational/teleport/api/utils/keys"
	apisshutils "github.com/gravitational/teleport/api/utils/sshutils"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/teleport/lib/utils/agentconn"
)

// Store is a storage interface for client data. Store is made up of three
// partial data stores; KeyStore, TrustedCertsStore, and ProfileStore.
//
// A Store can be made up of partial data stores with different backends. For example,
// when using `tsh --add-keys-to-agent=only`, Store will be made up of an in-memory
// key store and an FS (~/.tsh) profile and trusted certs store.
type Store struct {
	log *logrus.Entry

	KeyStore
	TrustedCertsStore
	ProfileStore
}

// NewMemClientStore initializes an FS backed client store with the given base dir.
func NewFSClientStore(dirPath string) *Store {
	dirPath = profile.FullProfilePath(dirPath)
	return &Store{
		log:               logrus.WithField(trace.Component, teleport.ComponentKeyStore),
		KeyStore:          NewFSKeyStore(dirPath),
		TrustedCertsStore: NewFSTrustedCertsStore(dirPath),
		ProfileStore:      NewFSProfileStore(dirPath),
	}
}

// NewMemClientStore initializes a new in-memory client store.
func NewMemClientStore() *Store {
	return &Store{
		log:               logrus.WithField(trace.Component, teleport.ComponentKeyStore),
		KeyStore:          NewMemKeyStore(),
		TrustedCertsStore: NewMemTrustedCertsStore(),
		ProfileStore:      NewMemProfileStore(),
	}
}

// NewClientStoreFromAgent initializes a new in-memory client store and
// loads any keys found in the ssh agent found at the given socket. If the
// ssh agent does not support the key@goteleport.com and sign@goteleport.com
// extensions, an unsupported agent extension error is returned.
func NewClientStoreFromAgent(sshAuthSocket string) (*Store, error) {
	conn, err := agentconn.Dial(sshAuthSocket)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer conn.Close()
	agentClient := agent.NewClient(conn)

	supportedExtensions, err := callQueryExtension(agentClient)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if !supportedExtensions[keyAgentExtension] || !supportedExtensions[signAgentExtension] {
		return nil, agent.ErrExtensionUnsupported
	}

	profile, forwardedKey, err := callKeyExtension(agentClient)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Create an agent signer using the forwarded ssh certificate.
	sshCert, err := apisshutils.ParseCertificate(forwardedKey.SSHCertificate)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	priv, err := keys.NewPrivateKey(newAgentSigner(sshAuthSocket, sshCert), nil)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	key := NewKey(priv)
	key.KeyIndex = forwardedKey.KeyIndex
	key.Cert = forwardedKey.SSHCertificate
	key.TLSCert = forwardedKey.TLSCertificate
	key.TrustedCerts = forwardedKey.TrustedCerts

	// Preload the client key and profile from the agent.
	clientStore := NewMemClientStore()
	if err := clientStore.AddKey(key); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := clientStore.SaveProfile(profile, true); err != nil {
		return nil, trace.Wrap(err)
	}

	return clientStore, nil
}

// agentSigner is a crypto.Signer backed by an ssh agent with the sign@goteleport.com extension.
// We use a custom signer because it can be used to perform various signature algorithms, while
// ssh.Signer can only perform ssh signatures which does not hash signature messages.
type agentSigner struct {
	sshAuthSock string
	sshCert     *ssh.Certificate
}

func newAgentSigner(sshAuthSock string, sshCert *ssh.Certificate) crypto.Signer {
	return &agentSigner{
		sshAuthSock: sshAuthSock,
		sshCert:     sshCert,
	}
}

func (as *agentSigner) Public() crypto.PublicKey {
	if pubGetter, ok := as.sshCert.Key.(ssh.CryptoPublicKey); ok {
		return pubGetter.CryptoPublicKey()
	}
	return nil
}

func (as *agentSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	conn, err := agentconn.Dial(as.sshAuthSock)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer conn.Close()

	agentClient := agent.NewClient(conn)
	return callSignExtension(agentClient, as.sshCert, digest, opts)
}

// AddKey adds the given key to the key store. The key's trusted certificates are
// added to the trusted certs store.
func (s *Store) AddKey(key *Key) error {
	if err := s.KeyStore.AddKey(key); err != nil {
		return trace.Wrap(err)
	}
	if err := s.TrustedCertsStore.SaveTrustedCerts(key.ProxyHost, key.TrustedCerts); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// GetKey gets the requested key with trusted the requested certificates. The key's
// trusted certs will be retrieved from the trusted certs store.
func (s *Store) GetKey(idx KeyIndex, opts ...CertOption) (*Key, error) {
	key, err := s.KeyStore.GetKey(idx, opts...)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	tlsCertExpiration, err := key.TeleportTLSCertValidBefore()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	s.log.Debugf("Teleport TLS certificate valid until %q.", tlsCertExpiration)

	// Validate the SSH certificate.
	if key.Cert != nil {
		if err := key.CheckCert(); err != nil {
			if !utils.IsCertExpiredError(err) {
				return nil, trace.Wrap(err)
			}
		}
	}

	trustedCerts, err := s.TrustedCertsStore.GetTrustedCerts(idx.ProxyHost)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	key.TrustedCerts = trustedCerts
	return key, nil
}

// AddTrustedHostKeys is a helper function to add ssh host keys directly, rather than through SaveTrustedCerts.
func (s *Store) AddTrustedHostKeys(proxyHost string, clusterName string, hostKeys ...ssh.PublicKey) error {
	var authorizedKeys [][]byte
	for _, hostKey := range hostKeys {
		authorizedKeys = append(authorizedKeys, ssh.MarshalAuthorizedKey(hostKey))
	}
	err := s.SaveTrustedCerts(proxyHost, []auth.TrustedCerts{
		{
			ClusterName:    clusterName,
			AuthorizedKeys: authorizedKeys,
		},
	})
	return trace.Wrap(err)
}

// ReadProfileStatus returns the profile status for the given profile name.
// If no profile name is provided, return the current profile.
func (s *Store) ReadProfileStatus(profileName string) (*ProfileStatus, error) {
	var err error
	if profileName == "" {
		profileName, err = s.CurrentProfile()
		if err != nil {
			return nil, trace.BadParameter("no profile provided and no current profile")
		}
	} else {
		// remove ports from proxy host, because profile name is stored by host name
		profileName, err = utils.Host(profileName)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}

	profile, err := s.GetProfile(profileName)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	idx := KeyIndex{
		ProxyHost:   profileName,
		ClusterName: profile.SiteName,
		Username:    profile.Username,
	}
	key, err := s.GetKey(idx, WithAllCerts...)
	if err != nil {
		if trace.IsNotFound(err) {
			// If we can't find a key to match the profile, return a partial status. This
			// is used for some superficial functions `tsh logout` and `tsh status`.
			return &ProfileStatus{
				Name: profileName,
				Dir:  profile.Dir,
				ProxyURL: url.URL{
					Scheme: "https",
					Host:   profile.WebProxyAddr,
				},
				Username:    profile.Username,
				Cluster:     profile.SiteName,
				KubeEnabled: profile.KubeProxyAddr != "",
				// Set ValidUntil to now to show that the keys are not available.
				ValidUntil: time.Now(),
			}, nil
		}
		return nil, trace.Wrap(err)
	}

	_, onDisk := s.KeyStore.(*FSKeyStore)

	return profileStatusFromKey(key, profileOptions{
		ProfileName:   profileName,
		ProfileDir:    profile.Dir,
		WebProxyAddr:  profile.WebProxyAddr,
		Username:      profile.Username,
		SiteName:      profile.SiteName,
		KubeProxyAddr: profile.KubeProxyAddr,
		IsVirtual:     !onDisk,
	})
}

// FullProfileStatus returns the name of the current profile with a
// a list of all profile statuses.
func (s *Store) FullProfileStatus() (*ProfileStatus, []*ProfileStatus, error) {
	currentProfileName, err := s.CurrentProfile()
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	currentProfile, err := s.ReadProfileStatus(currentProfileName)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	profileNames, err := s.ListProfiles()
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	var profiles []*ProfileStatus
	for _, profileName := range profileNames {
		if profileName == currentProfileName {
			// already loaded this one
			continue
		}
		status, err := s.ReadProfileStatus(profileName)
		if err != nil {
			return nil, nil, trace.Wrap(err)
		}
		profiles = append(profiles, status)
	}

	return currentProfile, profiles, nil
}
