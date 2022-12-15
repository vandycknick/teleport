/*
Copyright 2016 Gravitational, Inc.
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
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"

	"github.com/gravitational/teleport"

	"github.com/gravitational/teleport/api/profile"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/types/wrappers"
	"github.com/gravitational/teleport/api/utils/keypaths"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"
)

type ProfileStore interface {
	// CurrentProfile returns the current active profile.
	CurrentProfile() (string, error)

	// ListProfiles returns a list of all active profiles.
	ListProfiles() ([]string, error)

	// GetProfile returns the requested profile.
	GetProfile(profileName string) (*profile.Profile, error)

	// SaveProfile saves the given profile
	SaveProfile(profile *profile.Profile, setCurrent bool) error
}

// ReadProfileStatus returns the profile status for the given profile name.
// If no profile name is provided, return the current profile.
func ReadProfileStatus(ks ClientStore, profileName string) (*ProfileStatus, error) {
	var err error
	if profileName == "" {
		profileName, err = ks.CurrentProfile()
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

	profile, err := ks.GetProfile(profileName)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	idx := KeyIndex{
		ProxyHost:   profileName,
		ClusterName: profile.SiteName,
		Username:    profile.Username,
	}
	key, err := ks.GetKey(idx, WithAllCerts...)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	_, onDisk := ks.(*FSClientStore)

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
// a list of all active profile statuses.
func FullProfileStatus(ks ClientStore) (*ProfileStatus, []*ProfileStatus, error) {
	currentProfileName, err := ks.CurrentProfile()
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	currentProfile, err := ReadProfileStatus(ks, currentProfileName)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	profileNames, err := ks.ListProfiles()
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	var profiles []*ProfileStatus
	for _, profileName := range profileNames {
		if profileName == currentProfileName {
			// already loaded this one
			continue
		}
		status, err := ReadProfileStatus(ks, profileName)
		if err != nil {
			return nil, nil, trace.Wrap(err)
		}
		profiles = append(profiles, status)
	}

	return currentProfile, profiles, nil
}

// ProfileStatus combines metadata from the logged in profile and associated
// SSH certificate.
type ProfileStatus struct {
	// Name is the profile name.
	Name string

	// Dir is the directory where profile is located.
	Dir string

	// ProxyURL is the URL the web client is accessible at.
	ProxyURL url.URL

	// Username is the Teleport username.
	Username string

	// Roles is a list of Teleport Roles this user has been assigned.
	Roles []string

	// Logins are the Linux accounts, also known as principals in OpenSSH terminology.
	Logins []string

	// KubeEnabled is true when this profile is configured to connect to a
	// kubernetes cluster.
	KubeEnabled bool

	// KubeUsers are the kubernetes users used by this profile.
	KubeUsers []string

	// KubeGroups are the kubernetes groups used by this profile.
	KubeGroups []string

	// Databases is a list of database services this profile is logged into.
	Databases []tlsca.RouteToDatabase

	// Apps is a list of apps this profile is logged into.
	Apps []tlsca.RouteToApp

	// ValidUntil is the time at which this SSH certificate will expire.
	ValidUntil time.Time

	// Extensions is a list of enabled SSH features for the certificate.
	Extensions []string

	// CriticalOptions is a map of SSH critical options for the certificate.
	CriticalOptions map[string]string

	// Cluster is a selected cluster
	Cluster string

	// Traits hold claim data used to populate a role at runtime.
	Traits wrappers.Traits

	// ActiveRequests tracks the privilege escalation requests applied
	// during certificate construction.
	ActiveRequests services.RequestIDs

	// AWSRoleARNs is a list of allowed AWS role ARNs user can assume.
	AWSRolesARNs []string

	// AzureIdentities is a list of allowed Azure identities user can assume.
	AzureIdentities []string

	// AllowedResourceIDs is a list of resources the user can access. An empty
	// list means there are no resource-specific restrictions.
	AllowedResourceIDs []types.ResourceID

	// IsVirtual is set when this profile does not actually exist on disk,
	// probably because it was constructed from an identity file. When set,
	// certain profile functions - particularly those that return paths to
	// files on disk - must be accompanied by fallback logic when those paths
	// do not exist.
	IsVirtual bool
}

// profileOptions contains fields needed to initialize a profile beyond those
// derived directly from a Key.
type profileOptions struct {
	ProfileName   string
	ProfileDir    string
	WebProxyAddr  string
	Username      string
	SiteName      string
	KubeProxyAddr string
	IsVirtual     bool
}

// profileFromkey returns a ProfileStatus for the given key and options.
func profileStatusFromKey(key *Key, opts profileOptions) (*ProfileStatus, error) {
	sshCert, err := key.SSHCert()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Extract from the certificate how much longer it will be valid for.
	validUntil := time.Unix(int64(sshCert.ValidBefore), 0)

	// Extract roles from certificate. Note, if the certificate is in old format,
	// this will be empty.
	var roles []string
	rawRoles, ok := sshCert.Extensions[teleport.CertExtensionTeleportRoles]
	if ok {
		roles, err = services.UnmarshalCertRoles(rawRoles)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}
	sort.Strings(roles)

	// Extract traits from the certificate. Note if the certificate is in the
	// old format, this will be empty.
	var traits wrappers.Traits
	rawTraits, ok := sshCert.Extensions[teleport.CertExtensionTeleportTraits]
	if ok {
		err = wrappers.UnmarshalTraits([]byte(rawTraits), &traits)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}

	var activeRequests services.RequestIDs
	rawRequests, ok := sshCert.Extensions[teleport.CertExtensionTeleportActiveRequests]
	if ok {
		if err := activeRequests.Unmarshal([]byte(rawRequests)); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	allowedResourcesStr := sshCert.Extensions[teleport.CertExtensionAllowedResources]
	allowedResourceIDs, err := types.ResourceIDsFromString(allowedResourcesStr)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Extract extensions from certificate. This lists the abilities of the
	// certificate (like can the user request a PTY, port forwarding, etc.)
	var extensions []string
	for ext := range sshCert.Extensions {
		if ext == teleport.CertExtensionTeleportRoles ||
			ext == teleport.CertExtensionTeleportTraits ||
			ext == teleport.CertExtensionTeleportRouteToCluster ||
			ext == teleport.CertExtensionTeleportActiveRequests ||
			ext == teleport.CertExtensionAllowedResources {
			continue
		}
		extensions = append(extensions, ext)
	}
	sort.Strings(extensions)

	tlsCert, err := key.TeleportTLSCertificate()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	tlsID, err := tlsca.FromSubject(tlsCert.Subject, time.Time{})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	databases, err := findActiveDatabases(key)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	appCerts, err := key.AppTLSCertificates()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var apps []tlsca.RouteToApp
	for _, cert := range appCerts {
		tlsID, err := tlsca.FromSubject(cert.Subject, time.Time{})
		if err != nil {
			return nil, trace.Wrap(err)
		}
		if tlsID.RouteToApp.PublicAddr != "" {
			apps = append(apps, tlsID.RouteToApp)
		}
	}

	return &ProfileStatus{
		Name: opts.ProfileName,
		Dir:  opts.ProfileDir,
		ProxyURL: url.URL{
			Scheme: "https",
			Host:   opts.WebProxyAddr,
		},
		Username:           opts.Username,
		Logins:             sshCert.ValidPrincipals,
		ValidUntil:         validUntil,
		Extensions:         extensions,
		CriticalOptions:    sshCert.CriticalOptions,
		Roles:              roles,
		Cluster:            opts.SiteName,
		Traits:             traits,
		ActiveRequests:     activeRequests,
		KubeEnabled:        opts.KubeProxyAddr != "",
		KubeUsers:          tlsID.KubernetesUsers,
		KubeGroups:         tlsID.KubernetesGroups,
		Databases:          databases,
		Apps:               apps,
		AWSRolesARNs:       tlsID.AWSRoleARNs,
		AzureIdentities:    tlsID.AzureIdentities,
		IsVirtual:          opts.IsVirtual,
		AllowedResourceIDs: allowedResourceIDs,
	}, nil
}

// IsExpired returns true if profile is not expired yet
func (p *ProfileStatus) IsExpired(clock clockwork.Clock) bool {
	return p.ValidUntil.Sub(clock.Now()) <= 0
}

// virtualPathWarnOnce is used to ensure warnings about missing virtual path
// environment variables are consolidated into a single message and not spammed
// to the console.
var virtualPathWarnOnce sync.Once

// virtualPathFromEnv attempts to retrieve the path as defined by the given
// formatter from the environment.
func (p *ProfileStatus) virtualPathFromEnv(kind VirtualPathKind, params VirtualPathParams) (string, bool) {
	if !p.IsVirtual {
		return "", false
	}

	for _, envName := range VirtualPathEnvNames(kind, params) {
		if val, ok := os.LookupEnv(envName); ok {
			return val, true
		}
	}

	// If we can't resolve any env vars, this will return garbage which we
	// should at least warn about. As ugly as this is, arguably making every
	// profile path lookup fallible is even uglier.
	log.Debugf("Could not resolve path to virtual profile entry of type %s "+
		"with parameters %+v.", kind, params)

	virtualPathWarnOnce.Do(func() {
		log.Errorf("A virtual profile is in use due to an identity file " +
			"(`-i ...`) but this functionality requires additional files on " +
			"disk and may fail. Consider using a compatible wrapper " +
			"application (e.g. Machine ID) for this command.")
	})

	return "", false
}

// CACertPathForCluster returns path to the cluster CA certificate for this profile.
//
// It's stored in  <profile-dir>/keys/<proxy>/cas/<cluster>.pem by default.
func (p *ProfileStatus) CACertPathForCluster(cluster string) string {
	// Return an env var override if both valid and present for this identity.
	if path, ok := p.virtualPathFromEnv(VirtualPathCA, VirtualPathCAParams(types.HostCA)); ok {
		return path
	}

	return filepath.Join(keypaths.ProxyKeyDir(p.Dir, p.Name), "cas", cluster+".pem")
}

// KeyPath returns path to the private key for this profile.
//
// It's kept in <profile-dir>/keys/<proxy>/<user>.
func (p *ProfileStatus) KeyPath() string {
	// Return an env var override if both valid and present for this identity.
	if path, ok := p.virtualPathFromEnv(VirtualPathKey, nil); ok {
		return path
	}

	return keypaths.UserKeyPath(p.Dir, p.Name, p.Username)
}

// DatabaseCertPathForCluster returns path to the specified database access
// certificate for this profile, for the specified cluster.
//
// It's kept in <profile-dir>/keys/<proxy>/<user>-db/<cluster>/<name>-x509.pem
//
// If the input cluster name is an empty string, the selected cluster in the
// profile will be used.
func (p *ProfileStatus) DatabaseCertPathForCluster(clusterName string, databaseName string) string {
	if clusterName == "" {
		clusterName = p.Cluster
	}

	if path, ok := p.virtualPathFromEnv(VirtualPathDatabase, VirtualPathDatabaseParams(databaseName)); ok {
		return path
	}

	return keypaths.DatabaseCertPath(p.Dir, p.Name, p.Username, clusterName, databaseName)
}

// AppCertPath returns path to the specified app access certificate
// for this profile.
//
// It's kept in <profile-dir>/keys/<proxy>/<user>-app/<cluster>/<name>-x509.pem
func (p *ProfileStatus) AppCertPath(name string) string {
	if path, ok := p.virtualPathFromEnv(VirtualPathApp, VirtualPathAppParams(name)); ok {
		return path
	}

	return keypaths.AppCertPath(p.Dir, p.Name, p.Username, p.Cluster, name)
}

// AppLocalCAPath returns the specified app's self-signed localhost CA path for
// this profile.
//
// It's kept in <profile-dir>/keys/<proxy>/<user>-app/<cluster>/<name>-localca.pem
func (p *ProfileStatus) AppLocalCAPath(name string) string {
	return keypaths.AppLocalCAPath(p.Dir, p.Name, p.Username, p.Cluster, name)
}

// KubeConfigPath returns path to the specified kubeconfig for this profile.
//
// It's kept in <profile-dir>/keys/<proxy>/<user>-kube/<cluster>/<name>-kubeconfig
func (p *ProfileStatus) KubeConfigPath(name string) string {
	if path, ok := p.virtualPathFromEnv(VirtualPathKubernetes, VirtualPathKubernetesParams(name)); ok {
		return path
	}

	return keypaths.KubeConfigPath(p.Dir, p.Name, p.Username, p.Cluster, name)
}

// DatabaseServices returns a list of database service names for this profile.
func (p *ProfileStatus) DatabaseServices() (result []string) {
	for _, db := range p.Databases {
		result = append(result, db.ServiceName)
	}
	return result
}

// DatabasesForCluster returns a list of databases for this profile, for the
// specified cluster name.
func (p *ProfileStatus) DatabasesForCluster(clusterName string) ([]tlsca.RouteToDatabase, error) {
	if clusterName == "" || clusterName == p.Cluster {
		return p.Databases, nil
	}

	idx := KeyIndex{
		ProxyHost:   p.Name,
		Username:    p.Username,
		ClusterName: clusterName,
	}

	store, err := NewFSClientStore(p.Dir)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	key, err := store.GetKey(idx, WithDBCerts{})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return findActiveDatabases(key)
}

// AppNames returns a list of app names this profile is logged into.
func (p *ProfileStatus) AppNames() (result []string) {
	for _, app := range p.Apps {
		result = append(result, app.Name)
	}
	return result
}
