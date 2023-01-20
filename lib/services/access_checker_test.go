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

package services

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/types"
)

func TestAccessCheckerKubeResources(t *testing.T) {
	emptySet := []types.KubernetesResource{}
	kubeUsers := []string{"user1"}
	kubeAnyLabels, kubeDevLabels := types.Labels{"*": {"*"}}, types.Labels{"env": {"dev"}}
	devKubeCluster := newKubeCluster(t, "dev", map[string]string{"env": "dev"})
	prodKubeCluster := newKubeCluster(t, "prod", map[string]string{"env": "prod"})
	roleSet := NewRoleSet(
		newRole(func(rv *types.RoleV6) {
			rv.SetName("dev")
			rv.SetKubeResources(types.Allow, []types.KubernetesResource{
				{
					Kind:      types.KindKubePod,
					Name:      "dev",
					Namespace: "dev",
				},
			})
			rv.SetKubernetesLabels(types.Allow, kubeDevLabels)
			rv.SetKubeUsers(types.Allow, kubeUsers)
		}),
		newRole(func(rv *types.RoleV6) {
			rv.SetName("any")
			rv.SetKubeResources(types.Allow, []types.KubernetesResource{
				{
					Kind:      types.KindKubePod,
					Name:      "any1",
					Namespace: "any1",
				},
				{
					Kind:      types.KindKubePod,
					Name:      "any1",
					Namespace: "any2",
				},
			})
			rv.SetKubernetesLabels(types.Allow, kubeAnyLabels)
			rv.SetKubeUsers(types.Allow, kubeUsers)
		}),
	)
	localCluster := "cluster"
	type fields struct {
		info     *AccessInfo
		roleSet  RoleSet
		resource types.KubernetesResource
	}
	tests := []struct {
		name         string
		fields       fields
		kubeCluster  types.KubeCluster
		wantAllowed  []types.KubernetesResource
		wantDenied   []types.KubernetesResource
		assertAccess require.ErrorAssertionFunc
	}{
		{
			name:        "prod cluster",
			kubeCluster: prodKubeCluster,
			fields: fields{
				info: &AccessInfo{
					Roles: []string{"any", "dev"},
				},
				roleSet: roleSet,
				resource: types.KubernetesResource{
					Kind:      types.KindKubePod,
					Name:      "any1",
					Namespace: "any1",
				},
			},
			wantAllowed: []types.KubernetesResource{
				{
					Kind:      types.KindKubePod,
					Name:      "any1",
					Namespace: "any1",
				},
				{
					Kind:      types.KindKubePod,
					Name:      "any1",
					Namespace: "any2",
				},
			},
			wantDenied:   emptySet,
			assertAccess: require.NoError,
		},
		{
			name:        "dev cluster",
			kubeCluster: devKubeCluster,
			fields: fields{
				info: &AccessInfo{
					Roles: []string{"any", "dev"},
				},
				roleSet: roleSet,
				resource: types.KubernetesResource{
					Kind:      types.KindKubePod,
					Name:      "any1",
					Namespace: "rand",
				},
			},
			wantAllowed: []types.KubernetesResource{
				{
					Kind:      types.KindKubePod,
					Name:      "any1",
					Namespace: "any1",
				},
				{
					Kind:      types.KindKubePod,
					Name:      "any1",
					Namespace: "any2",
				},
				{
					Kind:      types.KindKubePod,
					Name:      "dev",
					Namespace: "dev",
				},
			},
			wantDenied:   emptySet,
			assertAccess: require.Error,
		},
		{
			name:        "dev cluster with resource access request",
			kubeCluster: devKubeCluster,
			fields: fields{
				roleSet: roleSet,
				info: &AccessInfo{
					Roles: []string{"any", "dev"},
					AllowedResourceIDs: []types.ResourceID{
						{
							Kind:        types.KindApp,
							ClusterName: localCluster,
							Name:        "devapp",
						},
						{
							Kind:            types.KindKubePod,
							ClusterName:     localCluster,
							Name:            devKubeCluster.GetName(),
							SubResourceName: "dev/dev",
						},
						{
							Kind:            types.KindKubePod,
							ClusterName:     localCluster,
							Name:            devKubeCluster.GetName(),
							SubResourceName: "test/test-3",
						},
						{
							Kind:            types.KindKubePod,
							ClusterName:     localCluster,
							Name:            prodKubeCluster.GetName(),
							SubResourceName: "prod/test-2",
						},
					},
				},
				resource: types.KubernetesResource{
					Kind:      types.KindKubePod,
					Name:      "dev",
					Namespace: "dev",
				},
			},
			wantAllowed: []types.KubernetesResource{
				{
					Kind:      types.KindKubePod,
					Name:      "dev",
					Namespace: "dev",
				},
				{
					Kind:      types.KindKubePod,
					Name:      "test-3",
					Namespace: "test",
				},
			},
			assertAccess: require.NoError,
		},
		{
			name:        "prod cluster with resource access request",
			kubeCluster: prodKubeCluster,
			fields: fields{
				info: &AccessInfo{
					AllowedResourceIDs: []types.ResourceID{
						{
							Kind:        types.KindApp,
							ClusterName: localCluster,
							Name:        "devapp",
						},
						{
							Kind:            types.KindKubePod,
							ClusterName:     localCluster,
							Name:            devKubeCluster.GetName(),
							SubResourceName: "test/test-2",
						},
						{
							Kind:            types.KindKubePod,
							ClusterName:     localCluster,
							Name:            devKubeCluster.GetName(),
							SubResourceName: "test/test-3",
						},
						{
							Kind:            types.KindKubePod,
							ClusterName:     localCluster,
							Name:            prodKubeCluster.GetName(),
							SubResourceName: "prod/test-2",
						},
					},
				},
				resource: types.KubernetesResource{
					Kind:      types.KindKubePod,
					Name:      "any1",
					Namespace: "any1",
				},
			},
			wantAllowed: []types.KubernetesResource{
				{
					Kind:      types.KindKubePod,
					Name:      "test-2",
					Namespace: "prod",
				},
			},
			assertAccess: require.Error,
		},
	}
	for _, tt := range tests[len(tests)-2:] {
		t.Run(tt.name, func(t *testing.T) {
			accessChecker := NewAccessCheckerWithRoleSet(tt.fields.info, localCluster, tt.fields.roleSet)
			gotAllowed, gotDenied := accessChecker.GetKubeResources(tt.kubeCluster)

			err := accessChecker.CheckAccess(
				tt.kubeCluster,
				AccessState{MFARequired: MFARequiredNever},
				// Append a matcher that validates if the Kubernetes resource is allowed
				// by the roles that satisfy the Kubernetes Cluster.
				NewKubernetesResourceMatcher(tt.fields.resource),
			)
			tt.assertAccess(t, err)
			sortKubeResourceSlice(gotAllowed)
			sortKubeResourceSlice(gotDenied)
			require.EqualValues(t, tt.wantAllowed, gotAllowed)
			require.EqualValues(t, tt.wantDenied, gotDenied)
		})
	}
}

func newKubeCluster(t *testing.T, name string, labels map[string]string) types.KubeCluster {
	cluster, err := types.NewKubernetesClusterV3(types.Metadata{
		Name:   name,
		Labels: labels,
	}, types.KubernetesClusterSpecV3{},
	)
	require.NoError(t, err)
	return cluster
}

func sortKubeResourceSlice(resources []types.KubernetesResource) {
	sort.Slice(resources, func(i, j int) bool { return resources[i].Name < resources[j].Name })
}
