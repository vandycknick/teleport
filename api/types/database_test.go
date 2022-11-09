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

package types

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDatabaseRDSEndpoint verifies AWS info is correctly populated
// based on the RDS endpoint.
func TestDatabaseRDSEndpoint(t *testing.T) {
	database, err := NewDatabaseV3(Metadata{
		Name: "rds",
	}, DatabaseSpecV3{
		Protocol: "postgres",
		URI:      "aurora-instance-1.abcdefghijklmnop.us-west-1.rds.amazonaws.com:5432",
	})
	require.NoError(t, err)
	require.Equal(t, AWS{
		Region: "us-west-1",
		RDS: RDS{
			InstanceID: "aurora-instance-1",
		},
	}, database.GetAWS())
}

// TestDatabaseRDSProxyEndpoint verifies AWS info is correctly populated based
// on the RDS Proxy endpoint.
func TestDatabaseRDSProxyEndpoint(t *testing.T) {
	database, err := NewDatabaseV3(Metadata{
		Name: "rdsproxy",
	}, DatabaseSpecV3{
		Protocol: "postgres",
		URI:      "my-proxy.proxy-abcdefghijklmnop.us-west-1.rds.amazonaws.com:5432",
	})
	require.NoError(t, err)
	require.Equal(t, AWS{
		Region: "us-west-1",
		RDSProxy: RDSProxy{
			Name: "my-proxy",
		},
	}, database.GetAWS())
}

// TestDatabaseRedshiftEndpoint verifies AWS info is correctly populated
// based on the Redshift endpoint.
func TestDatabaseRedshiftEndpoint(t *testing.T) {
	database, err := NewDatabaseV3(Metadata{
		Name: "redshift",
	}, DatabaseSpecV3{
		Protocol: "postgres",
		URI:      "redshift-cluster-1.abcdefghijklmnop.us-east-1.redshift.amazonaws.com:5438",
	})
	require.NoError(t, err)
	require.Equal(t, AWS{
		Region: "us-east-1",
		Redshift: Redshift{
			ClusterID: "redshift-cluster-1",
		},
	}, database.GetAWS())
}

// TestDatabaseStatus verifies database resource status field usage.
func TestDatabaseStatus(t *testing.T) {
	database, err := NewDatabaseV3(Metadata{
		Name: "test",
	}, DatabaseSpecV3{
		Protocol: "postgres",
		URI:      "localhost:5432",
	})
	require.NoError(t, err)

	caCert := "test"
	database.SetStatusCA(caCert)
	require.Equal(t, caCert, database.GetCA())

	awsMeta := AWS{AccountID: "account-id"}
	database.SetStatusAWS(awsMeta)
	require.Equal(t, awsMeta, database.GetAWS())
}

func TestDatabaseElastiCacheEndpoint(t *testing.T) {
	t.Run("valid URI", func(t *testing.T) {
		database, err := NewDatabaseV3(Metadata{
			Name: "elasticache",
		}, DatabaseSpecV3{
			Protocol: "redis",
			URI:      "clustercfg.my-redis-cluster.xxxxxx.cac1.cache.amazonaws.com:6379",
		})

		require.NoError(t, err)
		require.Equal(t, AWS{
			Region: "ca-central-1",
			ElastiCache: ElastiCache{
				ReplicationGroupID:       "my-redis-cluster",
				TransitEncryptionEnabled: true,
				EndpointType:             "configuration",
			},
		}, database.GetAWS())
		require.True(t, database.IsElastiCache())
		require.True(t, database.IsAWSHosted())
		require.True(t, database.IsCloudHosted())
	})

	t.Run("invalid URI", func(t *testing.T) {
		database, err := NewDatabaseV3(Metadata{
			Name: "elasticache",
		}, DatabaseSpecV3{
			Protocol: "redis",
			URI:      "some.endpoint.cache.amazonaws.com:6379",
			AWS: AWS{
				Region: "us-east-5",
				ElastiCache: ElastiCache{
					ReplicationGroupID: "some-id",
				},
			},
		})

		// A warning is logged, no error is returned, and AWS metadata is not
		// updated.
		require.NoError(t, err)
		require.Equal(t, AWS{
			Region: "us-east-5",
			ElastiCache: ElastiCache{
				ReplicationGroupID: "some-id",
			},
		}, database.GetAWS())
	})
}

func TestDatabaseMemoryDBEndpoint(t *testing.T) {
	t.Run("valid URI", func(t *testing.T) {
		database, err := NewDatabaseV3(Metadata{
			Name: "memorydb",
		}, DatabaseSpecV3{
			Protocol: "redis",
			URI:      "clustercfg.my-memorydb.xxxxxx.memorydb.us-east-1.amazonaws.com:6379",
		})

		require.NoError(t, err)
		require.Equal(t, AWS{
			Region: "us-east-1",
			MemoryDB: MemoryDB{
				ClusterName:  "my-memorydb",
				TLSEnabled:   true,
				EndpointType: "cluster",
			},
		}, database.GetAWS())
		require.True(t, database.IsMemoryDB())
		require.True(t, database.IsAWSHosted())
		require.True(t, database.IsCloudHosted())
	})

	t.Run("invalid URI", func(t *testing.T) {
		database, err := NewDatabaseV3(Metadata{
			Name: "memorydb",
		}, DatabaseSpecV3{
			Protocol: "redis",
			URI:      "some.endpoint.memorydb.amazonaws.com:6379",
			AWS: AWS{
				Region: "us-east-5",
				MemoryDB: MemoryDB{
					ClusterName: "clustername",
				},
			},
		})

		// A warning is logged, no error is returned, and AWS metadata is not
		// updated.
		require.NoError(t, err)
		require.Equal(t, AWS{
			Region: "us-east-5",
			MemoryDB: MemoryDB{
				ClusterName: "clustername",
			},
		}, database.GetAWS())
	})
}

func TestDatabaseAzureEndpoints(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		spec        DatabaseSpecV3
		expectError bool
		expectAzure Azure
	}{
		{
			name: "valid MySQL",
			spec: DatabaseSpecV3{
				Protocol: "mysql",
				URI:      "example-mysql.mysql.database.azure.com:3306",
			},
			expectAzure: Azure{
				Name: "example-mysql",
			},
		},
		{
			name: "valid PostgresSQL",
			spec: DatabaseSpecV3{
				Protocol: "postgres",
				URI:      "example-postgres.postgres.database.azure.com:5432",
			},
			expectAzure: Azure{
				Name: "example-postgres",
			},
		},
		{
			name: "invalid database endpoint",
			spec: DatabaseSpecV3{
				Protocol: "postgres",
				URI:      "invalid.database.azure.com:5432",
			},
			expectError: true,
		},
		{
			name: "valid Redis",
			spec: DatabaseSpecV3{
				Protocol: "redis",
				URI:      "example-redis.redis.cache.windows.net:6380",
				Azure: Azure{
					ResourceID: "/subscriptions/sub-id/resourceGroups/group-name/providers/Microsoft.Cache/Redis/example-redis",
				},
			},
			expectAzure: Azure{
				Name:       "example-redis",
				ResourceID: "/subscriptions/sub-id/resourceGroups/group-name/providers/Microsoft.Cache/Redis/example-redis",
			},
		},
		{
			name: "valid Redis Enterprise",
			spec: DatabaseSpecV3{
				Protocol: "redis",
				URI:      "rediss://example-redis-enterprise.region.redisenterprise.cache.azure.net?mode=cluster",
				Azure: Azure{
					ResourceID: "/subscriptions/sub-id/resourceGroups/group-name/providers/Microsoft.Cache/redisEnterprise/example-redis-enterprise",
				},
			},
			expectAzure: Azure{
				Name:       "example-redis-enterprise",
				ResourceID: "/subscriptions/sub-id/resourceGroups/group-name/providers/Microsoft.Cache/redisEnterprise/example-redis-enterprise",
			},
		},
		{
			name: "invalid Redis (missing resource ID)",
			spec: DatabaseSpecV3{
				Protocol: "redis",
				URI:      "rediss://example-redis-enterprise.region.redisenterprise.cache.azure.net?mode=cluster",
			},
			expectError: true,
		},
		{
			name: "invalid Redis (unknown format)",
			spec: DatabaseSpecV3{
				Protocol: "redis",
				URI:      "rediss://bad-format.redisenterprise.cache.azure.net?mode=cluster",
				Azure: Azure{
					ResourceID: "/subscriptions/sub-id/resourceGroups/group-name/providers/Microsoft.Cache/redisEnterprise/bad-format",
				},
			},
			expectError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			database, err := NewDatabaseV3(Metadata{
				Name: "test",
			}, test.spec)

			if test.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.expectAzure, database.GetAzure())
			}
		})
	}
}

func TestMySQLVersionValidation(t *testing.T) {
	t.Parallel()

	t.Run("correct config", func(t *testing.T) {
		database, err := NewDatabaseV3(Metadata{
			Name: "test",
		}, DatabaseSpecV3{
			Protocol: "mysql",
			URI:      "localhost:5432",
			MySQL: MySQLOptions{
				ServerVersion: "8.0.18",
			},
		})
		require.NoError(t, err)
		require.Equal(t, "8.0.18", database.GetMySQLServerVersion())
	})

	t.Run("incorrect config - wrong protocol", func(t *testing.T) {
		_, err := NewDatabaseV3(Metadata{
			Name: "test",
		}, DatabaseSpecV3{
			Protocol: "Postgres",
			URI:      "localhost:5432",
			MySQL: MySQLOptions{
				ServerVersion: "8.0.18",
			},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "ServerVersion")
	})
}

func TestMySQLServerVersion(t *testing.T) {
	t.Parallel()

	database, err := NewDatabaseV3(Metadata{
		Name: "test",
	}, DatabaseSpecV3{
		Protocol: "mysql",
		URI:      "localhost:5432",
	})
	require.NoError(t, err)

	require.Equal(t, "", database.GetMySQLServerVersion())

	database.SetMySQLServerVersion("8.0.1")
	require.Equal(t, "8.0.1", database.GetMySQLServerVersion())
}

func TestCassandraAWSEndpoint(t *testing.T) {
	t.Parallel()

	t.Run("aws cassandra url from region", func(t *testing.T) {
		database, err := NewDatabaseV3(Metadata{
			Name: "test",
		}, DatabaseSpecV3{
			Protocol: "cassandra",
			AWS: AWS{
				Region:    "us-west-1",
				AccountID: "12345",
			},
		})
		require.NoError(t, err)
		require.Equal(t, "cassandra.us-west-1.amazonaws.com:9142", database.GetURI())
	})

	t.Run("aws cassandra custom uri", func(t *testing.T) {
		database, err := NewDatabaseV3(Metadata{
			Name: "test",
		}, DatabaseSpecV3{
			Protocol: "cassandra",
			URI:      "cassandra.us-west-1.amazonaws.com:9142",
			AWS: AWS{
				AccountID: "12345",
			},
		})
		require.NoError(t, err)
		require.Equal(t, "cassandra.us-west-1.amazonaws.com:9142", database.GetURI())
		require.Equal(t, "us-west-1", database.GetAWS().Region)
	})

	t.Run("aws cassandra missing AccountID", func(t *testing.T) {
		_, err := NewDatabaseV3(Metadata{
			Name: "test",
		}, DatabaseSpecV3{
			Protocol: "cassandra",
			URI:      "cassandra.us-west-1.amazonaws.com:9142",
			AWS: AWS{
				AccountID: "",
			},
		})
		require.Error(t, err)
	})
}
