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

package db

import (
	"fmt"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/mysql/armmysqlflexibleservers"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/subscription/armsubscription"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/types"
	azureutils "github.com/gravitational/teleport/api/utils/azure"
	"github.com/gravitational/teleport/lib/cloud"
	"github.com/gravitational/teleport/lib/cloud/azure"
	"github.com/gravitational/teleport/lib/services"
)

// TestAzureMySQLFlexFetchers tests Azure MySQL Flexible server fetchers.
func TestAzureMySQLFlexFetchers(t *testing.T) {
	t.Parallel()

	azureSub := makeAzureSubscription(t, "sub123")
	azMySQLFlexServer, azMySQLFlexDB := makeAzureMySQLFlexServer(t, "mysql-flex", "sub123", "group 1", "East US", map[string]string{"env": "prod"})
	azureMatchers := []services.AzureMatcher{{
		Types:        []string{services.AzureMatcherMySQL},
		ResourceTags: types.Labels{"env": []string{"prod"}},
		Regions:      []string{"eastus"},
	}}

	clients := &cloud.TestCloudClients{
		AzureSubscriptionClient: azure.NewSubscriptionClient(&azure.ARMSubscriptionsMock{
			Subscriptions: []*armsubscription.Subscription{azureSub},
		}),
		AzureMySQL: azure.NewMySQLServersClient(&azure.ARMMySQLMock{
			NoAuth: true,
		}),
		AzureMySQLFlex: azure.NewMySQLFlexServersClientByAPI(&azure.ARMMySQLFlexServerMock{
			Servers: []*armmysqlflexibleservers.Server{azMySQLFlexServer},
		}),
	}

	fetchers := mustMakeAzureFetchers(t, clients, azureMatchers)
	require.ElementsMatch(t, types.Databases{azMySQLFlexDB}, mustGetDatabases(t, fetchers))
}

func makeAzureMySQLFlexServer(t *testing.T, name, subscription, group, region string, labels map[string]string, opts ...func(*armmysqlflexibleservers.Server)) (*armmysqlflexibleservers.Server, types.Database) {
	resourceType := "Microsoft.DBforMySQL/flexibleServers"
	id := fmt.Sprintf("/subscriptions/%v/resourceGroups/%v/providers/%v/%v",
		subscription,
		group,
		resourceType,
		name,
	)

	fqdn := name + ".mysql" + azureutils.DatabaseEndpointSuffix
	state := armmysqlflexibleservers.ServerStateReady
	version := armmysqlflexibleservers.ServerVersionEight021
	server := &armmysqlflexibleservers.Server{
		Location: &region,
		Properties: &armmysqlflexibleservers.ServerProperties{
			FullyQualifiedDomainName: &fqdn,
			State:                    &state,
			Version:                  &version,
		},
		Tags: labelsToAzureTags(labels),
		ID:   &id,
		Name: &name,
		Type: &resourceType,
	}
	for _, opt := range opts {
		opt(server)
	}
	database, err := services.NewDatabaseFromAzureMySQLFlexServer(server)
	require.NoError(t, err)
	return server, database
}
