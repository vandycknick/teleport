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

package proxy

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/gravitational/teleport/api/types"
	dbhelpers "github.com/gravitational/teleport/integration/db"
	"github.com/gravitational/teleport/integration/helpers"
	libclient "github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/srv/db/mysql"
	api "github.com/gravitational/teleport/lib/teleterm/api/protogen/golang/v1"
	"github.com/gravitational/teleport/lib/teleterm/api/uri"
	"github.com/gravitational/teleport/lib/teleterm/apiserver/handler"
	"github.com/gravitational/teleport/lib/teleterm/clusters"
	"github.com/gravitational/teleport/lib/teleterm/daemon"
)

// testTeletermGatewaysCertRenewal is run from within TestALPNSNIProxyDatabaseAccess to amortize the
// cost of setting up clusters in tests.
func testTeletermGatewaysCertRenewal(t *testing.T, pack *dbhelpers.DatabasePack) {
	rootClusterName, _, err := net.SplitHostPort(pack.Root.Cluster.Web)
	require.NoError(t, err)

	creds, err := helpers.GenerateUserCreds(helpers.UserCredsRequest{
		Process:  pack.Root.Cluster.Process,
		Username: pack.Root.User.GetName(),
	})
	require.NoError(t, err)

	t.Run("root cluster", func(t *testing.T) {
		t.Parallel()

		databaseURI := uri.NewClusterURI(rootClusterName).
			AppendDB(pack.Root.MysqlService.Name)

		testGatewayCertRenewal(t, pack, creds, databaseURI)
	})
	t.Run("leaf cluster", func(t *testing.T) {
		t.Parallel()

		leafClusterName := pack.Leaf.Cluster.Secrets.SiteName
		databaseURI := uri.NewClusterURI(rootClusterName).
			AppendLeafCluster(leafClusterName).
			AppendDB(pack.Leaf.MysqlService.Name)

		testGatewayCertRenewal(t, pack, creds, databaseURI)
	})
	t.Run("adding root cluster", func(t *testing.T) {
		t.Parallel()

		testAddingRootCluster(t, pack, creds)
	})
	t.Run("list root clusters", func(t *testing.T) {
		t.Parallel()

		testListRootClusters(t, pack, creds)
	})
	t.Run("get cluster", func(t *testing.T) {
		t.Parallel()

		testGetCluster(t, pack)
	})
}

func testGatewayCertRenewal(t *testing.T, pack *dbhelpers.DatabasePack, creds *helpers.UserCreds, databaseURI uri.ResourceURI) {
	tc, err := pack.Root.Cluster.NewClientWithCreds(helpers.ClientConfig{
		Login:   pack.Root.User.GetName(),
		Cluster: pack.Root.Cluster.Secrets.SiteName,
	}, *creds)
	require.NoError(t, err)
	// The profile on disk created by NewClientWithCreds doesn't have WebProxyAddr set.
	tc.WebProxyAddr = pack.Root.Cluster.Web
	tc.SaveProfile(false /* makeCurrent */)

	fakeClock := clockwork.NewFakeClockAt(time.Now())

	storage, err := clusters.NewStorage(clusters.Config{
		Dir:                tc.KeysDir,
		InsecureSkipVerify: tc.InsecureSkipVerify,
		// Inject a fake clock into clusters.Storage so we can control when the middleware thinks the
		// db cert has expired.
		Clock: fakeClock,
	})
	require.NoError(t, err)

	tshdEventsClient := &mockTSHDEventsClient{
		tc:         tc,
		pack:       pack,
		callCounts: make(map[string]int),
	}

	gatewayCertReissuer := &daemon.GatewayCertReissuer{
		Log:              logrus.NewEntry(logrus.StandardLogger()).WithField(trace.Component, "reissuer"),
		TSHDEventsClient: tshdEventsClient,
	}

	daemonService, err := daemon.New(daemon.Config{
		Storage: storage,
		CreateTshdEventsClientCredsFunc: func() (grpc.DialOption, error) {
			return grpc.WithTransportCredentials(insecure.NewCredentials()), nil
		},
		GatewayCertReissuer: gatewayCertReissuer,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		daemonService.Stop()
	})

	// Here the test setup ends and actual test code starts.

	gateway, err := daemonService.CreateGateway(context.Background(), daemon.CreateGatewayParams{
		TargetURI:  databaseURI.String(),
		TargetUser: "root",
	})
	require.NoError(t, err)

	// Open a new connection.
	client, err := mysql.MakeTestClientWithoutTLS(
		net.JoinHostPort(gateway.LocalAddress(), gateway.LocalPort()),
		gateway.RouteToDatabase())
	require.NoError(t, err)

	// Execute a query.
	result, err := client.Execute("select 1")
	require.NoError(t, err)
	require.Equal(t, mysql.TestQueryResponse, result)

	// Disconnect.
	require.NoError(t, client.Close())

	// Advance the fake clock to simulate the db cert expiry inside the middleware.
	fakeClock.Advance(time.Hour * 48)
	// Overwrite user certs with expired ones to simulate the user cert expiry.
	expiredCreds, err := helpers.GenerateUserCreds(helpers.UserCredsRequest{
		Process:  pack.Root.Cluster.Process,
		Username: pack.Root.User.GetName(),
		TTL:      -time.Hour,
	})
	require.NoError(t, err)
	err = helpers.SetupUserCreds(tc, pack.Root.Cluster.Config.Proxy.SSHAddr.Addr, *expiredCreds)
	require.NoError(t, err)

	// Open a new connection.
	// This should trigger the relogin flow. The middleware will notice that the db cert has expired
	// and then it will attempt to reissue the db cert using an expired user cert.
	// The mocked tshdEventsClient will issue a valid user cert, save it to disk, and the middleware
	// will let the connection through.
	client, err = mysql.MakeTestClientWithoutTLS(
		net.JoinHostPort(gateway.LocalAddress(), gateway.LocalPort()),
		gateway.RouteToDatabase())
	require.NoError(t, err)

	// Execute a query.
	result, err = client.Execute("select 1")
	require.NoError(t, err)
	require.Equal(t, mysql.TestQueryResponse, result)

	// Disconnect.
	require.NoError(t, client.Close())

	require.Equal(t, 1, tshdEventsClient.callCounts["Relogin"],
		"Unexpected number of calls to TSHDEventsClient.Relogin")
	require.Equal(t, 0, tshdEventsClient.callCounts["SendNotification"],
		"Unexpected number of calls to TSHDEventsClient.SendNotification")
}

type mockTSHDEventsClient struct {
	tc         *libclient.TeleportClient
	pack       *dbhelpers.DatabasePack
	callCounts map[string]int
}

// Relogin simulates the act of the user logging in again in the Electron app by replacing the user
// cert on disk with a valid one.
func (c *mockTSHDEventsClient) Relogin(context.Context, *api.ReloginRequest, ...grpc.CallOption) (*api.ReloginResponse, error) {
	c.callCounts["Relogin"]++
	creds, err := helpers.GenerateUserCreds(helpers.UserCredsRequest{
		Process:  c.pack.Root.Cluster.Process,
		Username: c.pack.Root.User.GetName(),
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	err = helpers.SetupUserCreds(c.tc, c.pack.Root.Cluster.Config.Proxy.SSHAddr.Addr, *creds)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &api.ReloginResponse{}, nil
}

func (c *mockTSHDEventsClient) SendNotification(context.Context, *api.SendNotificationRequest, ...grpc.CallOption) (*api.SendNotificationResponse, error) {
	c.callCounts["SendNotification"]++
	return &api.SendNotificationResponse{}, nil
}

// testAddingRootCluster is not related to testing gateways cert renewal. However, setting up
// integration tests is expensive, so until we have enough Connect tests to warrant setting up a
// separate Teleport instance for them, let's reuse the existing one.
//
// This is fine as long as the tests don't perform side effects on the cluster and operate merely
// within a new temporary dir for tsh profiles.
func testAddingRootCluster(t *testing.T, pack *dbhelpers.DatabasePack, creds *helpers.UserCreds) {
	storage, err := clusters.NewStorage(clusters.Config{
		Dir:                t.TempDir(),
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)

	daemonService, err := daemon.New(daemon.Config{
		Storage: storage,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		daemonService.Stop()
	})

	addedCluster, err := daemonService.AddCluster(context.Background(), pack.Root.Cluster.Web)
	require.NoError(t, err)

	clusters, err := daemonService.ListRootClusters(context.Background())
	require.NoError(t, err)

	clusterURIs := make([]uri.ResourceURI, 0, len(clusters))
	for _, cluster := range clusters {
		clusterURIs = append(clusterURIs, cluster.URI)
	}
	require.ElementsMatch(t, clusterURIs, []uri.ResourceURI{addedCluster.URI})
}

// TODO: Rename test name and function name to point at what we actually test.
func testListRootClusters(t *testing.T, pack *dbhelpers.DatabasePack, creds *helpers.UserCreds) {
	//TODO extract to helper function (simulate login)
	tc, err := pack.Root.Cluster.NewClientWithCreds(helpers.ClientConfig{
		Login:   pack.Root.User.GetName(),
		Cluster: pack.Root.Cluster.Secrets.SiteName,
	}, *creds)
	require.NoError(t, err)
	// The profile on disk created by NewClientWithCreds doesn't have WebProxyAddr set.
	tc.WebProxyAddr = pack.Root.Cluster.Web
	tc.SaveProfile(false /* makeCurrent */)

	storage, err := clusters.NewStorage(clusters.Config{
		Dir:                tc.KeysDir,
		InsecureSkipVerify: tc.InsecureSkipVerify,
	})
	require.NoError(t, err)

	daemonService, err := daemon.New(daemon.Config{
		Storage: storage,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		daemonService.Stop()
	})

	handler, err := handler.New(
		handler.Config{
			DaemonService: daemonService,
		},
	)
	require.NoError(t, err)

	response, err := handler.ListRootClusters(context.Background(), &api.ListClustersRequest{})
	require.NoError(t, err)

	require.Equal(t, 1, len(response.Clusters))
	require.Equal(t, pack.Root.User.GetName(), response.Clusters[0].LoggedInUser.Name)
}

// TODO: Rename test name and function name to point at what we actually test.
func testGetCluster(t *testing.T, pack *dbhelpers.DatabasePack) {
	authServer := pack.Root.Cluster.Process.GetAuthServer()

	// Use random names to not collide with other tests.
	uuid := uuid.NewString()
	suggestedReviewer := "suggested-reviewer"
	requestedRoleName := fmt.Sprintf("%s-%s", "requested-role", uuid)
	userName := fmt.Sprintf("%s-%s", "user", uuid)
	roleName := fmt.Sprintf("%s-%s", "get-cluster-role", uuid)

	requestedRole, err := types.NewRole(requestedRoleName, types.RoleSpecV6{})
	require.NoError(t, err)

	// Create user role with ability to request role
	userRole, err := types.NewRole(roleName, types.RoleSpecV6{
		Options: types.RoleOptions{},
		Allow: types.RoleConditions{
			Logins: []string{
				userName,
			},
			NodeLabels: types.Labels{types.Wildcard: []string{types.Wildcard}},
			Request: &types.AccessRequestConditions{
				Roles:              []string{requestedRoleName},
				SuggestedReviewers: []string{suggestedReviewer},
			},
		},
	})
	require.NoError(t, err)

	err = authServer.UpsertRole(context.Background(), requestedRole)
	require.NoError(t, err)

	err = authServer.UpsertRole(context.Background(), userRole)
	require.NoError(t, err)

	user, err := types.NewUser(userName)
	user.AddRole(userRole.GetName())
	require.NoError(t, err)

	watcher, err := authServer.NewWatcher(context.Background(), types.Watch{
		Kinds: []types.WatchKind{
			{Kind: types.KindUser},
		},
	})
	require.NoError(t, err)
	defer watcher.Close()

	select {
	case <-time.After(time.Second * 30):
		t.Fatalf("Timeout waiting for OpInit event.")
	case event := <-watcher.Events():
		if event.Type != types.OpInit {
			t.Fatalf("Unexpected event type.")
		}
		require.Equal(t, event.Type, types.OpInit)
	case <-watcher.Done():
		// TODO: Can we use t.Fatal in a subtest?
		t.Fatal(watcher.Error())
	}

	t.Logf("%#v", user)
	err = authServer.UpsertUser(user)
	require.NoError(t, err)

	WaitForResource(t, watcher, user.GetKind(), user.GetName())

	creds, err := helpers.GenerateUserCreds(helpers.UserCredsRequest{
		Process:  pack.Root.Cluster.Process,
		Username: userName,
	})
	require.NoError(t, err)

	//TODO extract to helper function (simulate login)
	tc, err := pack.Root.Cluster.NewClientWithCreds(helpers.ClientConfig{
		Login:   userName,
		Cluster: pack.Root.Cluster.Secrets.SiteName,
	}, *creds)
	require.NoError(t, err)
	// The profile on disk created by NewClientWithCreds doesn't have WebProxyAddr set.
	tc.WebProxyAddr = pack.Root.Cluster.Web
	tc.SaveProfile(false /* makeCurrent */)

	storage, err := clusters.NewStorage(clusters.Config{
		Dir:                tc.KeysDir,
		InsecureSkipVerify: tc.InsecureSkipVerify,
	})
	require.NoError(t, err)

	daemonService, err := daemon.New(daemon.Config{
		Storage: storage,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		daemonService.Stop()
	})

	handler, err := handler.New(
		handler.Config{
			DaemonService: daemonService,
		},
	)
	require.NoError(t, err)

	rootClusterName, _, err := net.SplitHostPort(pack.Root.Cluster.Web)
	require.NoError(t, err)

	response, err := handler.GetCluster(context.Background(), &api.GetClusterRequest{
		ClusterUri: uri.NewClusterURI(rootClusterName).String(),
	})
	require.NoError(t, err)

	t.Logf("%#v", response.LoggedInUser)
	require.Equal(t, userName, response.LoggedInUser.Name)
	require.ElementsMatch(t, []string{requestedRoleName}, response.LoggedInUser.RequestableRoles)
	require.ElementsMatch(t, []string{suggestedReviewer}, response.LoggedInUser.SuggestedReviewers)
}

func WaitForResource(t *testing.T, watcher types.Watcher, kind, name string) {
	timeout := time.After(time.Second * 15)
	for {
		select {
		case <-timeout:
			t.Fatalf("Timeout waiting for event.")
		case event := <-watcher.Events():
			if event.Type != types.OpPut {
				continue
			}
			if event.Resource.GetKind() == kind && event.Resource.GetMetadata().Name == name {
				return
			}
		case <-watcher.Done():
			t.Fatalf("Watcher error %s.", watcher.Error())
		}
	}
}
