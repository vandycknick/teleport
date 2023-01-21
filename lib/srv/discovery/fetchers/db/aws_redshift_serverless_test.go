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

package db

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/redshiftserverless"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/cloud"
	libcloudaws "github.com/gravitational/teleport/lib/cloud/aws"
	"github.com/gravitational/teleport/lib/cloud/mocks"
	"github.com/gravitational/teleport/lib/services"
)

func TestRedshiftServerlessFetcher(t *testing.T) {
	t.Parallel()

	workgroupProd, workgroupProdDB := makeRedshiftServerlessWorkgroup(t, "wg1", "us-east-1", envProdLabels)
	workgroupDev, workgroupDevDB := makeRedshiftServerlessWorkgroup(t, "wg2", "us-east-1", envDevLabels)
	endpointProd, endpointProdDB := makeRedshiftServerlessEndpoint(t, workgroupProd, "endpoint1", "us-east-1", envProdLabels)
	endpointDev, endpointProdDev := makeRedshiftServerlessEndpoint(t, workgroupDev, "endpoint2", "us-east-1", envDevLabels)
	tagsByARN := map[string][]*redshiftserverless.Tag{
		aws.StringValue(workgroupProd.WorkgroupArn): libcloudaws.LabelsToTags[redshiftserverless.Tag](envProdLabels),
		aws.StringValue(workgroupDev.WorkgroupArn):  libcloudaws.LabelsToTags[redshiftserverless.Tag](envDevLabels),
	}

	workgroupNotAvailable := mocks.RedshiftServerlessWorkgroup("wg-creating", "us-east-1")
	workgroupNotAvailable.Status = aws.String("creating")
	endpointNotAvailable := mocks.RedshiftServerlessEndpointAccess(workgroupNotAvailable, "endpoint-creating", "us-east-1")
	endpointNotAvailable.EndpointStatus = aws.String("creating")

	tests := []struct {
		name          string
		inputClients  cloud.AWSClients
		inputLabels   map[string]string
		wantDatabases types.Databases
	}{
		{
			name: "fetch all",
			inputClients: &cloud.TestCloudClients{
				RedshiftServerless: &mocks.RedshiftServerlessMock{
					Workgroups: []*redshiftserverless.Workgroup{workgroupProd, workgroupDev},
					Endpoints:  []*redshiftserverless.EndpointAccess{endpointProd, endpointDev},
					TagsByARN:  tagsByARN,
				},
			},
			inputLabels:   wildcardLabels,
			wantDatabases: types.Databases{workgroupProdDB, workgroupDevDB, endpointProdDB, endpointProdDev},
		},
		{
			name: "fetch prod",
			inputClients: &cloud.TestCloudClients{
				RedshiftServerless: &mocks.RedshiftServerlessMock{
					Workgroups: []*redshiftserverless.Workgroup{workgroupProd, workgroupDev},
					Endpoints:  []*redshiftserverless.EndpointAccess{endpointProd, endpointDev},
					TagsByARN:  tagsByARN,
				},
			},
			inputLabels:   envProdLabels,
			wantDatabases: types.Databases{workgroupProdDB, endpointProdDB},
		},
		{
			name: "skip unavailable",
			inputClients: &cloud.TestCloudClients{
				RedshiftServerless: &mocks.RedshiftServerlessMock{
					Workgroups: []*redshiftserverless.Workgroup{workgroupProd, workgroupNotAvailable},
					Endpoints:  []*redshiftserverless.EndpointAccess{endpointNotAvailable},
					TagsByARN:  tagsByARN,
				},
			},
			inputLabels:   wildcardLabels,
			wantDatabases: types.Databases{workgroupProdDB},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fetchers := mustMakeAWSFetchersForMatcher(t, test.inputClients, services.AWSMatcherRedshiftServerless, "us-east-2", toTypeLabels(test.inputLabels))
			require.ElementsMatch(t, test.wantDatabases, mustGetDatabases(t, fetchers))
		})
	}
}

func makeRedshiftServerlessWorkgroup(t *testing.T, name, region string, labels map[string]string) (*redshiftserverless.Workgroup, types.Database) {
	workgroup := mocks.RedshiftServerlessWorkgroup(name, region)
	tags := libcloudaws.LabelsToTags[redshiftserverless.Tag](labels)
	database, err := services.NewDatabaseFromRedshiftServerlessWorkgroup(workgroup, tags)
	require.NoError(t, err)
	return workgroup, database
}

func makeRedshiftServerlessEndpoint(t *testing.T, workgroup *redshiftserverless.Workgroup, name, region string, labels map[string]string) (*redshiftserverless.EndpointAccess, types.Database) {
	endpoint := mocks.RedshiftServerlessEndpointAccess(workgroup, name, region)
	tags := libcloudaws.LabelsToTags[redshiftserverless.Tag](labels)
	database, err := services.NewDatabaseFromRedshiftServerlessVPCEndpoint(endpoint, workgroup, tags)
	require.NoError(t, err)
	return endpoint, database
}
