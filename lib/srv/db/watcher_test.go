/*
Copyright 2021 Gravitational, Inc.

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

package db

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
	"github.com/aws/aws-sdk-go/service/redshiftserverless"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/types"
	clients "github.com/gravitational/teleport/lib/cloud"
	"github.com/gravitational/teleport/lib/cloud/azure"
	"github.com/gravitational/teleport/lib/cloud/mocks"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/services"
)

// TestWatcher verifies that database server properly detects and applies
// changes to database resources.
func TestWatcher(t *testing.T) {
	ctx := context.Background()
	testCtx := setupTestContext(ctx, t)

	// Make a static configuration database.
	db0, err := makeStaticDatabase("db0", nil)
	require.NoError(t, err)

	// This channel will receive new set of databases the server proxies
	// after each reconciliation.
	reconcileCh := make(chan types.Databases)

	// Create database server that proxies one static database and
	// watches for databases with label group=a.
	testCtx.setupDatabaseServer(ctx, t, agentParams{
		Databases: []types.Database{db0},
		ResourceMatchers: []services.ResourceMatcher{
			{Labels: types.Labels{
				"group": []string{"a"},
			}},
		},
		OnReconcile: func(d types.Databases) {
			reconcileCh <- d
		},
	})

	// Only db0 should be registered initially.
	assertReconciledResource(t, reconcileCh, types.Databases{db0})

	// Create database with label group=a.
	db1, err := makeDynamicDatabase("db1", map[string]string{"group": "a"})
	require.NoError(t, err)
	err = testCtx.authServer.CreateDatabase(ctx, db1)
	require.NoError(t, err)

	// It should be registered.
	assertReconciledResource(t, reconcileCh, types.Databases{db0, db1})

	// Try to update db0 which is registered statically.
	db0Updated, err := makeDynamicDatabase("db0", map[string]string{"group": "a", types.OriginLabel: types.OriginDynamic})
	require.NoError(t, err)
	err = testCtx.authServer.CreateDatabase(ctx, db0Updated)
	require.NoError(t, err)

	// It should not be registered, old db0 should remain.
	assertReconciledResource(t, reconcileCh, types.Databases{db0, db1})

	// Create database with label group=b.
	db2, err := makeDynamicDatabase("db2", map[string]string{"group": "b"})
	require.NoError(t, err)
	err = testCtx.authServer.CreateDatabase(ctx, db2)
	require.NoError(t, err)

	// It shouldn't be registered.
	assertReconciledResource(t, reconcileCh, types.Databases{db0, db1})

	// Update db2 labels so it matches.
	db2.SetStaticLabels(map[string]string{"group": "a", types.OriginLabel: types.OriginDynamic})
	err = testCtx.authServer.UpdateDatabase(ctx, db2)
	require.NoError(t, err)

	// Both should be registered now.
	assertReconciledResource(t, reconcileCh, types.Databases{db0, db1, db2})

	// Update db2 URI so it gets re-registered.
	db2.SetURI("localhost:2345")
	err = testCtx.authServer.UpdateDatabase(ctx, db2)
	require.NoError(t, err)

	// db2 should get updated.
	assertReconciledResource(t, reconcileCh, types.Databases{db0, db1, db2})

	// Update db1 labels so it doesn't match.
	db1.SetStaticLabels(map[string]string{"group": "c", types.OriginLabel: types.OriginDynamic})
	err = testCtx.authServer.UpdateDatabase(ctx, db1)
	require.NoError(t, err)

	// Only db0 and db2 should remain registered.

	assertReconciledResource(t, reconcileCh, types.Databases{db0, db2})

	// Remove db2.
	err = testCtx.authServer.DeleteDatabase(ctx, db2.GetName())
	require.NoError(t, err)

	// Only static database should remain.
	assertReconciledResource(t, reconcileCh, types.Databases{db0})
}

// TestWatcherDynamicResource tests dynamic resource registration where the
// ResourceMatchers should be always evaluated for the dynamic registered
// resources.
func TestWatcherDynamicResource(t *testing.T) {
	var db1, db2, db3, db4 *types.DatabaseV3
	ctx := context.Background()
	testCtx := setupTestContext(ctx, t)

	db0, err := makeStaticDatabase("db0", nil)
	require.NoError(t, err)

	reconcileCh := make(chan types.Databases)
	testCtx.setupDatabaseServer(ctx, t, agentParams{
		Databases: []types.Database{db0},
		ResourceMatchers: []services.ResourceMatcher{
			{Labels: types.Labels{
				"group": []string{"a"},
			}},
		},
		OnReconcile: func(d types.Databases) {
			reconcileCh <- d
		},
	})
	assertReconciledResource(t, reconcileCh, types.Databases{db0})

	withRDSURL := func(v3 *types.DatabaseSpecV3) {
		v3.URI = "mypostgresql.c6c8mwvfdgv0.us-west-2.rds.amazonaws.com:5432"
	}

	t.Run("dynamic resource - no match", func(t *testing.T) {
		// Created an RDS db dynamic resource that doesn't match any db service ResourceMatchers.
		db1, err = makeDynamicDatabase("db1", map[string]string{"group": "z"}, withRDSURL)
		require.NoError(t, err)
		require.True(t, db1.IsRDS())
		err = testCtx.authServer.CreateDatabase(ctx, db1)
		require.NoError(t, err)
		// The db1 should not be registered by the agent due to ResourceMatchers mismatch:
		assertReconciledResource(t, reconcileCh, types.Databases{db0})
	})

	t.Run("dynamic resource - match", func(t *testing.T) {
		// Create an RDS dynamic resource with labels that matches ResourceMatchers.
		db2, err = makeDynamicDatabase("db2", map[string]string{"group": "a"}, withRDSURL)
		require.NoError(t, err)
		require.True(t, db2.IsRDS())

		err = testCtx.authServer.CreateDatabase(ctx, db2)
		require.NoError(t, err)
		// The db2 service should be properly registered by the agent.
		assertReconciledResource(t, reconcileCh, types.Databases{db0, db2})
	})

	t.Run("discovery resource - no match", func(t *testing.T) {
		// Created a discovery service created database resource that doesn't
		// match any db service ResourceMatchers.
		db3, err = makeDiscoveryDatabase("db3", map[string]string{"group": "z"}, withRDSURL)
		require.NoError(t, err)
		require.True(t, db3.IsRDS())
		err = testCtx.authServer.CreateDatabase(ctx, db3)
		require.NoError(t, err)
		// The db3 should not be registered by the agent due to ResourceMatchers mismatch:
		assertReconciledResource(t, reconcileCh, types.Databases{db0, db2})
	})

	t.Run("discovery resource - match", func(t *testing.T) {
		// Created a discovery service created database resource that matches
		// ResourceMatchers.
		db4, err = makeDiscoveryDatabase("db4", map[string]string{"group": "a"}, withRDSURL)
		require.NoError(t, err)
		require.True(t, db4.IsRDS())

		err = testCtx.authServer.CreateDatabase(ctx, db4)
		require.NoError(t, err)
		// The db4 service should be properly registered by the agent.
		assertReconciledResource(t, reconcileCh, types.Databases{db0, db2, db4})
	})
}

// TestWatcherCloudFetchers tests usage of discovery database fetchers by the
// database service.
func TestWatcherCloudFetchers(t *testing.T) {
	// Test an AWS fetcher. Note that status AWS can be set by Metadata
	// service.
	redshiftServerlessWorkgroup := mocks.RedshiftServerlessWorkgroup("discovery-aws", "us-east-1")
	redshiftServerlessDatabase, err := services.NewDatabaseFromRedshiftServerlessWorkgroup(redshiftServerlessWorkgroup, nil)
	require.NoError(t, err)
	redshiftServerlessDatabase.SetStatusAWS(redshiftServerlessDatabase.GetAWS())

	// Test an Azure fetcher.
	azSQLServer, azSQLServerDatabase := makeAzureSQLServer(t, "discovery-azure", "group")

	ctx := context.Background()
	testCtx := setupTestContext(ctx, t)

	reconcileCh := make(chan types.Databases)
	testCtx.setupDatabaseServer(ctx, t, agentParams{
		// Keep ResourceMatchers as nil to disable resource matchers.
		OnReconcile: func(d types.Databases) {
			reconcileCh <- d
		},
		CloudClients: &clients.TestCloudClients{
			RDS: &mocks.RDSMockUnauth{}, // Access denied error should not affect other fetchers.
			RedshiftServerless: &mocks.RedshiftServerlessMock{
				Workgroups: []*redshiftserverless.Workgroup{redshiftServerlessWorkgroup},
			},
			AzureSQLServer: azure.NewSQLClientByAPI(&azure.ARMSQLServerMock{
				AllServers: []*armsql.Server{azSQLServer},
			}),
			AzureManagedSQLServer: azure.NewManagedSQLClientByAPI(&azure.ARMSQLManagedServerMock{}),
		},
		AzureMatchers: []services.AzureMatcher{{
			Subscriptions: []string{"sub"},
			Types:         []string{services.AzureMatcherSQLServer},
			ResourceTags:  types.Labels{types.Wildcard: []string{types.Wildcard}},
		}},
		AWSMatchers: []services.AWSMatcher{{
			Types:   []string{services.AWSMatcherRDS, services.AWSMatcherRedshiftServerless},
			Regions: []string{"us-east-1"},
			Tags:    types.Labels{types.Wildcard: []string{types.Wildcard}},
		}},
	})

	wantDatabases := types.Databases{azSQLServerDatabase, redshiftServerlessDatabase}
	sort.Sort(wantDatabases)

	assertReconciledResource(t, reconcileCh, wantDatabases)
}

func assertReconciledResource(t *testing.T, ch chan types.Databases, databases types.Databases) {
	t.Helper()
	select {
	case d := <-ch:
		sort.Sort(d)
		require.Equal(t, len(d), len(databases))
		require.Empty(t, cmp.Diff(databases, d,
			cmpopts.IgnoreFields(types.Metadata{}, "ID"),
			cmpopts.IgnoreFields(types.DatabaseStatusV3{}, "CACert"),
		))
	case <-time.After(time.Second):
		t.Fatal("Didn't receive reconcile event after 1s.")
	}

}

func makeStaticDatabase(name string, labels map[string]string, opts ...makeDatabaseOpt) (*types.DatabaseV3, error) {
	return makeDatabase(name, labels, map[string]string{
		types.OriginLabel: types.OriginConfigFile,
	}, opts...)
}

func makeDynamicDatabase(name string, labels map[string]string, opts ...makeDatabaseOpt) (*types.DatabaseV3, error) {
	return makeDatabase(name, labels, map[string]string{
		types.OriginLabel: types.OriginDynamic,
	}, opts...)
}

func makeDiscoveryDatabase(name string, labels map[string]string, opts ...makeDatabaseOpt) (*types.DatabaseV3, error) {
	return makeDatabase(name, labels, map[string]string{
		types.OriginLabel: types.OriginCloud,
	}, opts...)
}

type makeDatabaseOpt func(*types.DatabaseSpecV3)

func makeDatabase(name string, labels map[string]string, additionalLabels map[string]string, opts ...makeDatabaseOpt) (*types.DatabaseV3, error) {
	if labels == nil {
		labels = make(map[string]string)
	}

	for k, v := range additionalLabels {
		labels[k] = v
	}

	ds := types.DatabaseSpecV3{
		Protocol: defaults.ProtocolPostgres,
		URI:      "localhost:5432",
	}

	for _, o := range opts {
		o(&ds)
	}

	return types.NewDatabaseV3(types.Metadata{
		Name:   name,
		Labels: labels,
	}, ds)
}

func makeAzureSQLServer(t *testing.T, name, group string) (*armsql.Server, types.Database) {
	t.Helper()

	server := &armsql.Server{
		ID:   to.Ptr(fmt.Sprintf("/subscriptions/sub-id/resourceGroups/%v/providers/Microsoft.Sql/servers/%v", group, name)),
		Name: to.Ptr(fmt.Sprintf("%s.database.windows.net", name)),
		Properties: &armsql.ServerProperties{
			FullyQualifiedDomainName: to.Ptr("localhost"),
		},
	}
	database, err := services.NewDatabaseFromAzureSQLServer(server)
	require.NoError(t, err)
	return server, database
}
