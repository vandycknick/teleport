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

package discovery

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/container/apiv1/containerpb"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/redis/armredis/v2"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/eks"
	"github.com/aws/aws-sdk-go/service/eks/eksiface"
	"github.com/aws/aws-sdk-go/service/redshift"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/aws-sdk-go/service/ssm/ssmiface"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/api/utils"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/cloud"
	"github.com/gravitational/teleport/lib/cloud/azure"
	"github.com/gravitational/teleport/lib/cloud/gcp"
	"github.com/gravitational/teleport/lib/cloud/mocks"
	libevents "github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/services"
)

type mockSSMClient struct {
	ssmiface.SSMAPI
	commandOutput *ssm.SendCommandOutput
	invokeOutput  *ssm.GetCommandInvocationOutput
}

func (sm *mockSSMClient) SendCommandWithContext(_ context.Context, input *ssm.SendCommandInput, _ ...request.Option) (*ssm.SendCommandOutput, error) {
	return sm.commandOutput, nil
}

func (sm *mockSSMClient) GetCommandInvocationWithContext(_ context.Context, input *ssm.GetCommandInvocationInput, _ ...request.Option) (*ssm.GetCommandInvocationOutput, error) {
	return sm.invokeOutput, nil
}

func (sm *mockSSMClient) WaitUntilCommandExecutedWithContext(aws.Context, *ssm.GetCommandInvocationInput, ...request.WaiterOption) error {
	if aws.StringValue(sm.commandOutput.Command.Status) == ssm.CommandStatusFailed {
		return awserr.New(request.WaiterResourceNotReadyErrorCode, "err", nil)
	}
	return nil
}

type mockEmitter struct {
	eventHandler func(*testing.T, events.AuditEvent, *Server)
	server       *Server
	t            *testing.T
}

func (me *mockEmitter) EmitAuditEvent(ctx context.Context, event events.AuditEvent) error {
	if me.eventHandler != nil {
		me.eventHandler(me.t, event, me.server)
	}
	return nil
}

type mockEC2Client struct {
	ec2iface.EC2API
	output *ec2.DescribeInstancesOutput
}

func (m *mockEC2Client) DescribeInstancesPagesWithContext(
	ctx context.Context, input *ec2.DescribeInstancesInput,
	f func(dio *ec2.DescribeInstancesOutput, b bool) bool, opts ...request.Option,
) error {
	f(m.output, true)
	return nil
}

func genEC2Instances(n int) []*ec2.Instance {
	var ec2Instances []*ec2.Instance
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("instance-id-%d", i)
		ec2Instances = append(ec2Instances, &ec2.Instance{
			InstanceId: aws.String(id),
			Tags: []*ec2.Tag{{
				Key:   aws.String("env"),
				Value: aws.String("dev"),
			}},
			State: &ec2.InstanceState{
				Name: aws.String(ec2.InstanceStateNameRunning),
			},
		})
	}
	return ec2Instances
}

func TestDiscoveryServer(t *testing.T) {
	t.Parallel()
	tcs := []struct {
		name string
		// presentInstances is a list of servers already present in teleport
		presentInstances  []types.Server
		foundEC2Instances []*ec2.Instance
		ssm               *mockSSMClient
		emitter           *mockEmitter
		logHandler        func(*testing.T, io.Reader, chan struct{})
	}{
		{
			name:             "no nodes present, 1 found ",
			presentInstances: []types.Server{},
			foundEC2Instances: []*ec2.Instance{
				{
					InstanceId: aws.String("instance-id-1"),
					Tags: []*ec2.Tag{{
						Key:   aws.String("env"),
						Value: aws.String("dev"),
					}},
					State: &ec2.InstanceState{
						Name: aws.String(ec2.InstanceStateNameRunning),
					},
				},
			},
			ssm: &mockSSMClient{
				commandOutput: &ssm.SendCommandOutput{
					Command: &ssm.Command{
						CommandId: aws.String("command-id-1"),
					},
				},
				invokeOutput: &ssm.GetCommandInvocationOutput{
					Status:       aws.String(ssm.CommandStatusSuccess),
					ResponseCode: aws.Int64(0),
				},
			},
			emitter: &mockEmitter{
				eventHandler: func(t *testing.T, ae events.AuditEvent, server *Server) {
					t.Helper()
					defer server.Stop()
					require.Equal(t, ae, &events.SSMRun{
						Metadata: events.Metadata{
							Type: libevents.SSMRunEvent,
							Code: libevents.SSMRunSuccessCode,
						},
						CommandID:  "command-id-1",
						AccountID:  "owner",
						InstanceID: "instance-id-1",
						Region:     "eu-central-1",
						ExitCode:   0,
						Status:     ssm.CommandStatusSuccess,
					})
				},
			},
		},
		{
			name: "nodes present, instance filtered",
			presentInstances: []types.Server{
				&types.ServerV2{
					Kind: types.KindNode,
					Metadata: types.Metadata{
						Name: "name",
						Labels: map[string]string{
							types.AWSAccountIDLabel:  "owner",
							types.AWSInstanceIDLabel: "instance-id-1",
						},
						Namespace: defaults.Namespace,
					},
				},
			},
			foundEC2Instances: []*ec2.Instance{
				{
					InstanceId: aws.String("instance-id-1"),
					Tags: []*ec2.Tag{{
						Key:   aws.String("env"),
						Value: aws.String("dev"),
					}},
					State: &ec2.InstanceState{
						Name: aws.String(ec2.InstanceStateNameRunning),
					},
				},
			},
			ssm: &mockSSMClient{
				commandOutput: &ssm.SendCommandOutput{
					Command: &ssm.Command{
						CommandId: aws.String("command-id-1"),
					},
				},
				invokeOutput: &ssm.GetCommandInvocationOutput{
					Status:       aws.String(ssm.CommandStatusSuccess),
					ResponseCode: aws.Int64(0),
				},
			},
			emitter: &mockEmitter{},
			logHandler: func(t *testing.T, logs io.Reader, done chan struct{}) {
				scanner := bufio.NewScanner(logs)
				for scanner.Scan() {
					if strings.Contains(scanner.Text(),
						"All discovered EC2 instances are already part of the cluster.") {
						done <- struct{}{}
						return
					}
				}
			},
		},
		{
			name: "nodes present, instance not filtered",
			presentInstances: []types.Server{
				&types.ServerV2{
					Kind: types.KindNode,
					Metadata: types.Metadata{
						Name: "name",
						Labels: map[string]string{
							types.AWSAccountIDLabel:  "owner",
							types.AWSInstanceIDLabel: "wow-its-a-different-instance",
						},
						Namespace: defaults.Namespace,
					},
				},
			},
			foundEC2Instances: []*ec2.Instance{
				{
					InstanceId: aws.String("instance-id-1"),
					Tags: []*ec2.Tag{{
						Key:   aws.String("env"),
						Value: aws.String("dev"),
					}},
					State: &ec2.InstanceState{
						Name: aws.String(ec2.InstanceStateNameRunning),
					},
				},
			},
			ssm: &mockSSMClient{
				commandOutput: &ssm.SendCommandOutput{
					Command: &ssm.Command{
						CommandId: aws.String("command-id-1"),
					},
				},
				invokeOutput: &ssm.GetCommandInvocationOutput{
					Status:       aws.String(ssm.CommandStatusSuccess),
					ResponseCode: aws.Int64(0),
				},
			},
			emitter: &mockEmitter{},
			logHandler: func(t *testing.T, logs io.Reader, done chan struct{}) {
				scanner := bufio.NewScanner(logs)
				for scanner.Scan() {
					if strings.Contains(scanner.Text(),
						"Running Teleport installation on these instances: AccountID: owner, Instances: [instance-id-1]") {
						done <- struct{}{}
						return
					}
				}
			},
		},
		{
			name:              "chunked nodes get 2 log messages",
			presentInstances:  []types.Server{},
			foundEC2Instances: genEC2Instances(58),
			ssm: &mockSSMClient{
				commandOutput: &ssm.SendCommandOutput{
					Command: &ssm.Command{
						CommandId: aws.String("command-id-1"),
					},
				},
				invokeOutput: &ssm.GetCommandInvocationOutput{
					Status:       aws.String(ssm.CommandStatusSuccess),
					ResponseCode: aws.Int64(0),
				},
			},
			emitter: &mockEmitter{},
			logHandler: func(t *testing.T, logs io.Reader, done chan struct{}) {
				scanner := bufio.NewScanner(logs)
				instances := genEC2Instances(58)
				findAll := []string{genEC2InstancesLogStr(instances[:50]), genEC2InstancesLogStr(instances[50:])}
				index := 0
				for scanner.Scan() {
					if index == len(findAll) {
						done <- struct{}{}
						return
					}
					if strings.Contains(scanner.Text(), findAll[index]) {
						index++
					}
				}
			},
		},
	}

	for _, tc := range tcs {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			testClients := cloud.TestCloudClients{
				EC2: &mockEC2Client{
					output: &ec2.DescribeInstancesOutput{
						Reservations: []*ec2.Reservation{
							{
								OwnerId:   aws.String("owner"),
								Instances: tc.foundEC2Instances,
							},
						},
					},
				},
				SSM: tc.ssm,
			}

			ctx := context.Background()
			// Create and start test auth server.
			testAuthServer, err := auth.NewTestAuthServer(auth.TestAuthServerConfig{
				Dir: t.TempDir(),
			})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, testAuthServer.Close()) })

			tlsServer, err := testAuthServer.NewTestTLSServer()
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, tlsServer.Close()) })

			// Auth client for discovery service.
			authClient, err := tlsServer.NewClient(auth.TestServerID(types.RoleDiscovery, "hostID"))
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, authClient.Close()) })

			for _, instance := range tc.presentInstances {
				_, err := tlsServer.Auth().UpsertNode(ctx, instance)
				require.NoError(t, err)
			}

			logger := logrus.New()
			server, err := New(context.Background(), &Config{
				Clients:     &testClients,
				AccessPoint: tlsServer.Auth(),
				AWSMatchers: []services.AWSMatcher{{
					Types:   []string{"ec2"},
					Regions: []string{"eu-central-1"},
					Tags:    map[string]utils.Strings{"teleport": {"yes"}},
					SSM:     &services.AWSSSM{DocumentName: "document"},
				}},
				Emitter: tc.emitter,
				Log:     logger,
			})
			require.NoError(t, err)
			tc.emitter.server = server
			tc.emitter.t = t

			r, w := io.Pipe()
			t.Cleanup(func() {
				require.NoError(t, r.Close())
				require.NoError(t, w.Close())
			})
			if tc.logHandler != nil {
				logger.SetOutput(w)
				logger.SetLevel(logrus.DebugLevel)
			}

			go server.Start()

			if tc.logHandler != nil {
				done := make(chan struct{})
				go tc.logHandler(t, r, done)
				timeoutCtx, cancelfn := context.WithTimeout(ctx, time.Second*5)
				defer cancelfn()
				select {
				case <-timeoutCtx.Done():
					t.Fatal("Timeout waiting for log entries")
					return
				case <-done:
					server.Stop()
					return
				}
			}

			server.Wait()
		})
	}
}

func TestDiscoveryKube(t *testing.T) {
	t.Parallel()
	tcs := []struct {
		name                          string
		existingKubeClusters          []types.KubeCluster
		awsMatchers                   []services.AWSMatcher
		azureMatchers                 []services.AzureMatcher
		gcpMatchers                   []services.GCPMatcher
		expectedClustersToExistInAuth []types.KubeCluster
		clustersNotUpdated            []string
	}{
		{
			name:                 "no clusters in auth server, import 2 prod clusters from EKS",
			existingKubeClusters: []types.KubeCluster{},
			awsMatchers: []services.AWSMatcher{
				{
					Types:   []string{"eks"},
					Regions: []string{"eu-west-1"},
					Tags:    map[string]utils.Strings{"env": {"prod"}},
				},
			},
			expectedClustersToExistInAuth: []types.KubeCluster{
				mustConvertEKSToKubeCluster(t, eksMockClusters[0]),
				mustConvertEKSToKubeCluster(t, eksMockClusters[1]),
			},
		},
		{
			name:                 "no clusters in auth server, import 2 stg clusters from EKS",
			existingKubeClusters: []types.KubeCluster{},
			awsMatchers: []services.AWSMatcher{
				{
					Types:   []string{"eks"},
					Regions: []string{"eu-west-1"},
					Tags:    map[string]utils.Strings{"env": {"stg"}},
				},
			},
			expectedClustersToExistInAuth: []types.KubeCluster{
				mustConvertEKSToKubeCluster(t, eksMockClusters[2]),
				mustConvertEKSToKubeCluster(t, eksMockClusters[3]),
			},
		},
		{
			name: "1 cluster in auth server not updated + import 1 prod cluster from EKS",
			existingKubeClusters: []types.KubeCluster{
				mustConvertEKSToKubeCluster(t, eksMockClusters[0]),
			},
			awsMatchers: []services.AWSMatcher{
				{
					Types:   []string{"eks"},
					Regions: []string{"eu-west-1"},
					Tags:    map[string]utils.Strings{"env": {"prod"}},
				},
			},
			expectedClustersToExistInAuth: []types.KubeCluster{
				mustConvertEKSToKubeCluster(t, eksMockClusters[0]),
				mustConvertEKSToKubeCluster(t, eksMockClusters[1]),
			},
			clustersNotUpdated: []string{"eks-cluster1"},
		},
		{
			name: "1 cluster in auth that no longer matches (deleted) + import 2 prod clusters from EKS",
			existingKubeClusters: []types.KubeCluster{
				mustConvertEKSToKubeCluster(t, eksMockClusters[3]),
			},
			awsMatchers: []services.AWSMatcher{
				{
					Types:   []string{"eks"},
					Regions: []string{"eu-west-1"},
					Tags:    map[string]utils.Strings{"env": {"prod"}},
				},
			},
			expectedClustersToExistInAuth: []types.KubeCluster{
				mustConvertEKSToKubeCluster(t, eksMockClusters[0]),
				mustConvertEKSToKubeCluster(t, eksMockClusters[1]),
			},
			clustersNotUpdated: []string{},
		},
		{
			name: "1 cluster in auth that matches but must be updated + import 1 prod clusters from EKS",
			existingKubeClusters: []types.KubeCluster{
				// add an extra static label to force update in auth server
				modifyKubeCluster(mustConvertEKSToKubeCluster(t, eksMockClusters[1])),
			},
			awsMatchers: []services.AWSMatcher{
				{
					Types:   []string{"eks"},
					Regions: []string{"eu-west-1"},
					Tags:    map[string]utils.Strings{"env": {"prod"}},
				},
			},
			expectedClustersToExistInAuth: []types.KubeCluster{
				mustConvertEKSToKubeCluster(t, eksMockClusters[0]),
				mustConvertEKSToKubeCluster(t, eksMockClusters[1]),
			},
			clustersNotUpdated: []string{},
		},
		{
			name: "2 clusters in auth that matches but one must be updated +  import 2 prod clusters, 1 from EKS and other from AKS",
			existingKubeClusters: []types.KubeCluster{
				// add an extra static label to force update in auth server
				modifyKubeCluster(mustConvertEKSToKubeCluster(t, eksMockClusters[1])),
				mustConvertAKSToKubeCluster(t, aksMockClusters["group1"][0]),
			},
			awsMatchers: []services.AWSMatcher{
				{
					Types:   []string{"eks"},
					Regions: []string{"eu-west-1"},
					Tags:    map[string]utils.Strings{"env": {"prod"}},
				},
			},
			azureMatchers: []services.AzureMatcher{
				{
					Types:          []string{"aks"},
					ResourceTags:   map[string]utils.Strings{"env": {"prod"}},
					Regions:        []string{types.Wildcard},
					ResourceGroups: []string{types.Wildcard},
					Subscriptions:  []string{"sub1"},
				},
			},
			expectedClustersToExistInAuth: []types.KubeCluster{
				mustConvertEKSToKubeCluster(t, eksMockClusters[0]),
				mustConvertEKSToKubeCluster(t, eksMockClusters[1]),
				mustConvertAKSToKubeCluster(t, aksMockClusters["group1"][0]),
				mustConvertAKSToKubeCluster(t, aksMockClusters["group1"][1]),
			},
			clustersNotUpdated: []string{"aks-cluster1"},
		},
		{
			name:                 "no clusters in auth server, import 2 prod clusters from GKE",
			existingKubeClusters: []types.KubeCluster{},
			gcpMatchers: []services.GCPMatcher{
				{
					Types:      []string{"gke"},
					Locations:  []string{"*"},
					ProjectIDs: []string{"p1"},
					Tags:       map[string]utils.Strings{"env": {"prod"}},
				},
			},
			expectedClustersToExistInAuth: []types.KubeCluster{
				mustConvertGKEToKubeCluster(t, gkeMockClusters[0]),
				mustConvertGKEToKubeCluster(t, gkeMockClusters[1]),
			},
		},
	}

	for _, tc := range tcs {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			testClients := cloud.TestCloudClients{
				AzureAKSClient: newPopulatedAKSMock(),
				EKS:            newPopulatedEKSMock(),
				GCPGKE:         newPopulatedGCPMock(),
			}

			ctx := context.Background()
			// Create and start test auth server.
			testAuthServer, err := auth.NewTestAuthServer(auth.TestAuthServerConfig{
				Dir: t.TempDir(),
			})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, testAuthServer.Close()) })

			tlsServer, err := testAuthServer.NewTestTLSServer()
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, tlsServer.Close()) })

			// Auth client for discovery service.
			authClient, err := tlsServer.NewClient(auth.TestServerID(types.RoleDiscovery, "hostID"))
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, authClient.Close()) })

			for _, kubeCluster := range tc.existingKubeClusters {
				err := tlsServer.Auth().CreateKubernetesCluster(ctx, kubeCluster)
				require.NoError(t, err)
			}
			// we analyze the logs emitted by discovery service to detect clusters that were not updated
			// because their state didn't change.
			r, w := io.Pipe()
			t.Cleanup(func() {
				require.NoError(t, r.Close())
				require.NoError(t, w.Close())
			})

			logger := logrus.New()
			logger.SetOutput(w)
			logger.SetLevel(logrus.DebugLevel)
			clustersNotUpdated := make(chan string, 10)
			go func() {
				// reconcileRegexp is the regex extractor of a log message emitted by reconciler when
				// the current state of the cluster is equal to the previous.
				// [r.log.Debugf("%v %v is already registered.", new.GetKind(), new.GetName())]
				// lib/services/reconciler.go
				reconcileRegexp := regexp.MustCompile("kube_cluster (.*) is already registered")

				scanner := bufio.NewScanner(r)
				for scanner.Scan() {
					text := scanner.Text()
					// we analyze the logs emitted by discovery service to detect clusters that were not updated
					// because their state didn't change.
					if reconcileRegexp.MatchString(text) {
						result := reconcileRegexp.FindStringSubmatch(text)
						if len(result) != 2 {
							continue
						}
						clustersNotUpdated <- result[1]
					}
				}
			}()

			discServer, err := New(
				ctx,
				&Config{
					Clients:       &testClients,
					AccessPoint:   tlsServer.Auth(),
					AWSMatchers:   tc.awsMatchers,
					AzureMatchers: tc.azureMatchers,
					GCPMatchers:   tc.gcpMatchers,
					Emitter:       authClient,
					Log:           logger,
				})

			require.NoError(t, err)

			t.Cleanup(func() {
				discServer.Stop()
			})
			go discServer.Start()

			clustersNotUpdatedMap := sliceToSet(tc.clustersNotUpdated)
			clustersFoundInAuth := false
			require.Eventually(t, func() bool {
			loop:
				for {
					select {
					case cluster := <-clustersNotUpdated:
						if _, ok := clustersNotUpdatedMap[cluster]; !ok {
							require.Failf(t, "expected Action for cluster %s but got no action from reconciler", cluster)
						}
						delete(clustersNotUpdatedMap, cluster)
					default:
						kubeClusters, err := tlsServer.Auth().GetKubernetesClusters(ctx)
						require.NoError(t, err)
						if len(kubeClusters) == len(tc.expectedClustersToExistInAuth) {
							c1 := types.KubeClusters(kubeClusters).ToMap()
							c2 := types.KubeClusters(tc.expectedClustersToExistInAuth).ToMap()
							for k := range c1 {
								if services.CompareResources(c1[k], c2[k]) != services.Equal {
									return false
								}
							}
							clustersFoundInAuth = true
						}
						break loop
					}
				}
				return len(clustersNotUpdated) == 0 && clustersFoundInAuth
			}, 5*time.Second, 200*time.Millisecond)
		})
	}
}

type mockAKSAPI struct {
	azure.AKSClient
	group map[string][]*azure.AKSCluster
}

func (m *mockAKSAPI) ListAll(ctx context.Context) ([]*azure.AKSCluster, error) {
	result := make([]*azure.AKSCluster, 0, 10)
	for _, v := range m.group {
		result = append(result, v...)
	}
	return result, nil
}

func (m *mockAKSAPI) ListWithinGroup(ctx context.Context, group string) ([]*azure.AKSCluster, error) {
	return m.group[group], nil
}

func newPopulatedAKSMock() *mockAKSAPI {
	return &mockAKSAPI{
		group: aksMockClusters,
	}
}

var aksMockClusters = map[string][]*azure.AKSCluster{
	"group1": {
		{
			Name:           "aks-cluster1",
			GroupName:      "group1",
			TenantID:       "tenantID",
			Location:       "uswest1",
			SubscriptionID: "subID",
			Tags: map[string]string{
				"env":      "prod",
				"location": "uswest1",
			},
			Properties: azure.AKSClusterProperties{},
		},
		{
			Name:           "aks-cluster2",
			GroupName:      "group1",
			TenantID:       "tenantID",
			Location:       "uswest2",
			SubscriptionID: "subID",
			Tags: map[string]string{
				"env":      "prod",
				"location": "uswest1",
			},
			Properties: azure.AKSClusterProperties{},
		},
	},
	"group2": {
		{
			Name:           "aks-cluster3",
			GroupName:      "group1",
			TenantID:       "tenantID",
			Location:       "uswest1",
			SubscriptionID: "subID",
			Tags: map[string]string{
				"env":      "stg",
				"location": "uswest1",
			},
			Properties: azure.AKSClusterProperties{},
		},
		{
			Name:           "aks-cluster4",
			GroupName:      "group1",
			TenantID:       "tenantID",
			Location:       "uswest2",
			SubscriptionID: "subID",
			Tags: map[string]string{
				"env":      "stg",
				"location": "uswest1",
			},
			Properties: azure.AKSClusterProperties{},
		},
	},
}

type mockEKSAPI struct {
	eksiface.EKSAPI
	clusters []*eks.Cluster
}

func (m *mockEKSAPI) ListClustersPagesWithContext(ctx aws.Context, req *eks.ListClustersInput, f func(*eks.ListClustersOutput, bool) bool, _ ...request.Option) error {
	var names []*string
	for _, cluster := range m.clusters {
		names = append(names, cluster.Name)
	}
	f(&eks.ListClustersOutput{
		Clusters: names[:len(names)/2],
	}, false)

	f(&eks.ListClustersOutput{
		Clusters: names[len(names)/2:],
	}, true)
	return nil
}

func (m *mockEKSAPI) DescribeClusterWithContext(_ aws.Context, req *eks.DescribeClusterInput, _ ...request.Option) (*eks.DescribeClusterOutput, error) {
	for _, cluster := range m.clusters {
		if aws.StringValue(cluster.Name) == aws.StringValue(req.Name) {
			return &eks.DescribeClusterOutput{
				Cluster: cluster,
			}, nil
		}
	}
	return nil, errors.New("cluster not found")
}

func newPopulatedEKSMock() *mockEKSAPI {
	return &mockEKSAPI{
		clusters: eksMockClusters,
	}
}

var eksMockClusters = []*eks.Cluster{
	{
		Name:   aws.String("eks-cluster1"),
		Arn:    aws.String("arn:aws:eks:eu-west-1:accountID:cluster/cluster1"),
		Status: aws.String(eks.ClusterStatusActive),
		Tags: map[string]*string{
			"env":      aws.String("prod"),
			"location": aws.String("eu-west-1"),
		},
	},
	{
		Name:   aws.String("eks-cluster2"),
		Arn:    aws.String("arn:aws:eks:eu-west-1:accountID:cluster/cluster2"),
		Status: aws.String(eks.ClusterStatusActive),
		Tags: map[string]*string{
			"env":      aws.String("prod"),
			"location": aws.String("eu-west-1"),
		},
	},

	{
		Name:   aws.String("eks-cluster3"),
		Arn:    aws.String("arn:aws:eks:eu-west-1:accountID:cluster/cluster3"),
		Status: aws.String(eks.ClusterStatusActive),
		Tags: map[string]*string{
			"env":      aws.String("stg"),
			"location": aws.String("eu-west-1"),
		},
	},
	{
		Name:   aws.String("eks-cluster4"),
		Arn:    aws.String("arn:aws:eks:eu-west-1:accountID:cluster/cluster1"),
		Status: aws.String(eks.ClusterStatusActive),
		Tags: map[string]*string{
			"env":      aws.String("stg"),
			"location": aws.String("eu-west-1"),
		},
	},
}

func mustConvertEKSToKubeCluster(t *testing.T, eksCluster *eks.Cluster) types.KubeCluster {
	cluster, err := services.NewKubeClusterFromAWSEKS(eksCluster)
	require.NoError(t, err)
	return cluster
}

func mustConvertAKSToKubeCluster(t *testing.T, azureCluster *azure.AKSCluster) types.KubeCluster {
	cluster, err := services.NewKubeClusterFromAzureAKS(azureCluster)
	require.NoError(t, err)
	return cluster
}

func modifyKubeCluster(cluster types.KubeCluster) types.KubeCluster {
	cluster.GetStaticLabels()["test"] = "test"
	return cluster
}

func sliceToSet[T comparable](slice []T) map[T]struct{} {
	set := map[T]struct{}{}
	for _, v := range slice {
		set[v] = struct{}{}
	}
	return set
}

func newPopulatedGCPMock() *mockGKEAPI {
	return &mockGKEAPI{
		clusters: gkeMockClusters,
	}
}

var gkeMockClusters = []gcp.GKECluster{
	{
		Name:   "cluster1",
		Status: containerpb.Cluster_RUNNING,
		Labels: map[string]string{
			"env":      "prod",
			"location": "central-1",
		},
		ProjectID:   "p1",
		Location:    "central-1",
		Description: "desc1",
	},
	{
		Name:   "cluster2",
		Status: containerpb.Cluster_RUNNING,
		Labels: map[string]string{
			"env":      "prod",
			"location": "central-1",
		},
		ProjectID:   "p1",
		Location:    "central-1",
		Description: "desc1",
	},
	{
		Name:   "cluster3",
		Status: containerpb.Cluster_RUNNING,
		Labels: map[string]string{
			"env":      "stg",
			"location": "central-1",
		},
		ProjectID:   "p1",
		Location:    "central-1",
		Description: "desc1",
	},
	{
		Name:   "cluster4",
		Status: containerpb.Cluster_RUNNING,
		Labels: map[string]string{
			"env":      "stg",
			"location": "central-1",
		},
		ProjectID:   "p1",
		Location:    "central-1",
		Description: "desc1",
	},
}

func mustConvertGKEToKubeCluster(t *testing.T, gkeCluster gcp.GKECluster) types.KubeCluster {
	cluster, err := services.NewKubeClusterFromGCPGKE(gkeCluster)
	require.NoError(t, err)
	return cluster
}

type mockGKEAPI struct {
	gcp.GKEClient
	clusters []gcp.GKECluster
}

func (m *mockGKEAPI) ListClusters(ctx context.Context, projectID string, location string) ([]gcp.GKECluster, error) {
	return m.clusters, nil
}

func TestDiscoveryDatabase(t *testing.T) {
	awsRedshiftResource, awsRedshiftDB := makeRedshiftCluster(t, "aws-redshift", "us-east-1")
	azRedisResource, azRedisDB := makeAzureRedisServer(t, "az-redis", "sub1", "group1", "East US")

	testClients := &cloud.TestCloudClients{
		Redshift: &mocks.RedshiftMock{
			Clusters: []*redshift.Cluster{awsRedshiftResource},
		},
		AzureRedis: azure.NewRedisClientByAPI(&azure.ARMRedisMock{
			Servers: []*armredis.ResourceInfo{azRedisResource},
		}),
		AzureRedisEnterprise: azure.NewRedisEnterpriseClientByAPI(
			&azure.ARMRedisEnterpriseClusterMock{},
			&azure.ARMRedisEnterpriseDatabaseMock{},
		),
	}

	tcs := []struct {
		name              string
		existingDatabases []types.Database
		awsMatchers       []services.AWSMatcher
		azureMatchers     []services.AzureMatcher
		expectDatabases   []types.Database
	}{
		{
			name: "discover AWS database",
			awsMatchers: []services.AWSMatcher{{
				Types:   []string{services.AWSMatcherRedshift},
				Tags:    map[string]utils.Strings{types.Wildcard: {types.Wildcard}},
				Regions: []string{"us-east-1"},
			}},
			expectDatabases: []types.Database{awsRedshiftDB},
		},
		{
			name: "discover Azure database",
			azureMatchers: []services.AzureMatcher{{
				Types:          []string{services.AzureMatcherRedis},
				ResourceTags:   map[string]utils.Strings{types.Wildcard: {types.Wildcard}},
				Regions:        []string{types.Wildcard},
				ResourceGroups: []string{types.Wildcard},
				Subscriptions:  []string{"sub1"},
			}},
			expectDatabases: []types.Database{azRedisDB},
		},
		{
			name: "update existing database",
			existingDatabases: []types.Database{
				mustNewDatabase(t, types.Metadata{
					Name:        "aws-redshift",
					Description: "should be updated",
					Labels:      map[string]string{types.OriginLabel: types.OriginCloud},
				}, types.DatabaseSpecV3{
					Protocol: "redis",
					URI:      "should.be.updated.com:12345",
				}),
			},
			awsMatchers: []services.AWSMatcher{{
				Types:   []string{services.AWSMatcherRedshift},
				Tags:    map[string]utils.Strings{types.Wildcard: {types.Wildcard}},
				Regions: []string{"us-east-1"},
			}},
			expectDatabases: []types.Database{awsRedshiftDB},
		},
		{
			name: "delete existing database",
			existingDatabases: []types.Database{
				mustNewDatabase(t, types.Metadata{
					Name:        "aws-redshift",
					Description: "should be deleted",
					Labels:      map[string]string{types.OriginLabel: types.OriginCloud},
				}, types.DatabaseSpecV3{
					Protocol: "redis",
					URI:      "should.be.deleted.com:12345",
				}),
			},
			awsMatchers: []services.AWSMatcher{{
				Types:   []string{services.AWSMatcherRedshift},
				Tags:    map[string]utils.Strings{"do-not-match": {"do-not-match"}},
				Regions: []string{"us-east-1"},
			}},
			expectDatabases: []types.Database{},
		},
		{
			name: "skip self-hosted database",
			existingDatabases: []types.Database{
				mustNewDatabase(t, types.Metadata{
					Name:        "self-hosted",
					Description: "should be ignored (not deleted)",
					Labels:      map[string]string{types.OriginLabel: types.OriginConfigFile},
				}, types.DatabaseSpecV3{
					Protocol: "mysql",
					URI:      "localhost:12345",
				}),
			},
			awsMatchers: []services.AWSMatcher{{
				Types:   []string{services.AWSMatcherRedshift},
				Tags:    map[string]utils.Strings{"do-not-match": {"do-not-match"}},
				Regions: []string{"us-east-1"},
			}},
			expectDatabases: []types.Database{
				mustNewDatabase(t, types.Metadata{
					Name:        "self-hosted",
					Description: "should be ignored (not deleted)",
					Labels:      map[string]string{types.OriginLabel: types.OriginConfigFile},
				}, types.DatabaseSpecV3{
					Protocol: "mysql",
					URI:      "localhost:12345",
				}),
			},
		},
	}

	for _, tc := range tcs {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)

			// Create and start test auth server.
			testAuthServer, err := auth.NewTestAuthServer(auth.TestAuthServerConfig{
				Dir: t.TempDir(),
			})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, testAuthServer.Close()) })

			tlsServer, err := testAuthServer.NewTestTLSServer()
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, tlsServer.Close()) })

			// Auth client for discovery service.
			authClient, err := tlsServer.NewClient(auth.TestServerID(types.RoleDiscovery, "hostID"))
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, authClient.Close()) })

			for _, database := range tc.existingDatabases {
				err := tlsServer.Auth().CreateDatabase(ctx, database)
				require.NoError(t, err)
			}

			waitForReconcile := make(chan struct{})
			srv, err := New(
				ctx,
				&Config{
					Clients:       testClients,
					AccessPoint:   tlsServer.Auth(),
					AWSMatchers:   tc.awsMatchers,
					AzureMatchers: tc.azureMatchers,
					Emitter:       authClient,
					onDatabaseReconcile: func() {
						waitForReconcile <- struct{}{}
					},
				})

			require.NoError(t, err)

			t.Cleanup(srv.Stop)
			go srv.Start()

			select {
			case <-waitForReconcile:
				actualDatabases, err := authClient.GetDatabases(ctx)
				require.NoError(t, err)
				require.Empty(t, cmp.Diff(tc.expectDatabases, actualDatabases,
					cmpopts.IgnoreFields(types.Metadata{}, "ID"),
					cmpopts.IgnoreFields(types.DatabaseStatusV3{}, "CACert"),
				))
			case <-time.After(time.Second):
				t.Fatal("Didn't receive reconcile event after 1s.")
			}
		})
	}
}

func makeRedshiftCluster(t *testing.T, name, region string) (*redshift.Cluster, types.Database) {
	t.Helper()
	cluster := &redshift.Cluster{
		ClusterIdentifier:   aws.String(name),
		ClusterNamespaceArn: aws.String(fmt.Sprintf("arn:aws:redshift:%s:123456789012:namespace:%s", region, name)),
		ClusterStatus:       aws.String("available"),
		Endpoint: &redshift.Endpoint{
			Address: aws.String("localhost"),
			Port:    aws.Int64(5439),
		},
	}

	database, err := services.NewDatabaseFromRedshiftCluster(cluster)
	require.NoError(t, err)
	database.SetOrigin(types.OriginCloud)
	return cluster, database
}

func makeAzureRedisServer(t *testing.T, name, subscription, group, region string) (*armredis.ResourceInfo, types.Database) {
	t.Helper()
	resourceInfo := &armredis.ResourceInfo{
		Name:     to.Ptr(name),
		ID:       to.Ptr(fmt.Sprintf("/subscriptions/%v/resourceGroups/%v/providers/Microsoft.Cache/Redis/%v", subscription, group, name)),
		Location: to.Ptr(region),
		Properties: &armredis.Properties{
			HostName:          to.Ptr(fmt.Sprintf("%v.redis.cache.windows.net", name)),
			SSLPort:           to.Ptr(int32(6380)),
			ProvisioningState: to.Ptr(armredis.ProvisioningStateSucceeded),
		},
	}

	database, err := services.NewDatabaseFromAzureRedis(resourceInfo)
	require.NoError(t, err)
	database.SetOrigin(types.OriginCloud)
	return resourceInfo, database
}

func mustNewDatabase(t *testing.T, meta types.Metadata, spec types.DatabaseSpecV3) types.Database {
	t.Helper()
	database, err := types.NewDatabaseV3(meta, spec)
	require.NoError(t, err)
	return database
}
