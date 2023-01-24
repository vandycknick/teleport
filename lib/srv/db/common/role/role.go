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

package role

import (
	"strings"

	"github.com/aws/aws-sdk-go/aws/arn"

	"github.com/gravitational/teleport/api/types"
	awsapiutils "github.com/gravitational/teleport/api/utils/aws"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/services"
	awsutils "github.com/gravitational/teleport/lib/utils/aws"
)

// DatabaseRoleMatchers returns role matchers based on the database.
func DatabaseRoleMatchers(db types.Database, user, database string) services.RoleMatchers {
	roleMatchers := services.RoleMatchers{
		databaseUserMatcher(db, user),
	}

	if matcher, ok := databaseNameMatcher(db.GetProtocol(), database); ok {
		roleMatchers = append(roleMatchers, matcher)
	}
	return roleMatchers
}

// RequireDatabaseUserMatcher returns true if databases with provided protocol
// require database users.
func RequireDatabaseUserMatcher(protocol string) bool {
	return true // Always required.
}

// RequireDatabaseNameMatcher returns true if databases with provided protocol
// require database names.
func RequireDatabaseNameMatcher(protocol string) bool {
	_, ok := databaseNameMatcher(protocol, "")
	return ok
}

func databaseNameMatcher(dbProtocol, database string) (*services.DatabaseNameMatcher, bool) {
	switch dbProtocol {
	case
		// In MySQL, unlike Postgres, "database" and "schema" are the same thing
		// and there's no good way to prevent users from performing cross-database
		// queries once they're connected, apart from granting proper privileges
		// in MySQL itself.
		//
		// As such, checking db_names for MySQL is quite pointless, so we only
		// check db_users. In the future, if we implement some sort of access controls
		// on queries, we might be able to restrict db_names as well e.g. by
		// detecting full-qualified table names like db.table, until then the
		// proper way is to use MySQL grants system.
		defaults.ProtocolMySQL,
		// Cockroach uses the same wire protocol as Postgres but handling of
		// databases is different and there's no way to prevent cross-database
		// queries so only apply RBAC to db_users.
		defaults.ProtocolCockroachDB,
		// Redis integration doesn't support schema access control.
		defaults.ProtocolRedis,
		// Cassandra integration doesn't support schema access control.
		defaults.ProtocolCassandra,
		// Elasticsearch integration doesn't support schema access control.
		defaults.ProtocolElasticsearch,
		// DynamoDB integration doesn't support schema access control.
		defaults.ProtocolDynamoDB:
		return nil, false
	default:
		return &services.DatabaseNameMatcher{Name: database}, true
	}
}

func databaseUserMatcher(db types.Database, user string) *services.DatabaseUserMatcher {
	switch db.GetType() {
	case types.DatabaseTypeAWSKeyspaces,
		types.DatabaseTypeDynamoDB,
		types.DatabaseTypeRedshiftServerless:
		return &services.DatabaseUserMatcher{
			User: user,
			AlternativeUsers: []services.DatabaseAlternativeUserFunc{
				alternativeUserForAWSAssumedRole(db),
			},
		}
	}

	// Default user matcher.
	return &services.DatabaseUserMatcher{User: user}
}

func alternativeUserForAWSAssumedRole(db types.Database) services.DatabaseAlternativeUserFunc {
	return func(user string) (string, bool) {
		metadata := db.GetAWS()
		if metadata.Region == "" || metadata.AccountID == "" {
			return "", false
		}

		// If input database user is a role ARN, try the short role name.
		// The input role ARN must have matching partition and account ID in
		// order to try the short role name.
		if arn.IsARN(user) {
			role, err := arn.Parse(user)
			if err != nil {
				return "", false
			}
			if !strings.HasPrefix(role.Resource, "role/") {
				return "", false
			}
			if role.AccountID != metadata.AccountID {
				return "", false
			}
			if role.Partition != awsapiutils.GetPartitionFromRegion(metadata.AccountID) {
				return "", false
			}
			return strings.TrimPrefix(role.Resource, "role/"), true
		}

		// If input database is the short role name, try the full ARN.
		return awsutils.BuildRoleARN(user, metadata.Region, metadata.AccountID), true
	}
}
