// Copyright 2023 Gravitational, Inc
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

package gcp

import (
	"strings"

	"github.com/gravitational/trace"
)

// SortedGCPServiceAccounts sorts service accounts by project and service account name.
type SortedGCPServiceAccounts []string

// Len returns the length of a list.
func (s SortedGCPServiceAccounts) Len() int {
	return len(s)
}

// Less compares items. Given two accounts, it first compares the project (i.e. what goes after @)
// and if they are equal proceeds to compare the service account name (what goes before @).
// Example of sorted list:
// - test-0@example-100200.iam.gserviceaccount.com
// - test-1@example-123456.iam.gserviceaccount.com
// - test-2@example-123456.iam.gserviceaccount.com
// - test-3@example-123456.iam.gserviceaccount.com
// - test-0@other-999999.iam.gserviceaccount.com
func (s SortedGCPServiceAccounts) Less(i, j int) bool {
	beforeI, afterI, _ := strings.Cut(s[i], "@")
	beforeJ, afterJ, _ := strings.Cut(s[j], "@")

	if afterI != afterJ {
		return afterI < afterJ
	}

	return beforeI < beforeJ
}

// Swap swaps two items in a list.
func (s SortedGCPServiceAccounts) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

const expectedParentDomain = "iam.gserviceaccount.com"

func ProjectIDFromServiceAccountName(serviceAccount string) (string, error) {
	if serviceAccount == "" {
		return "", trace.BadParameter("invalid service account format: empty string received")
	}

	user, domain, found := strings.Cut(serviceAccount, "@")
	if !found {
		return "", trace.BadParameter("invalid service account format: missing @")
	}
	if user == "" {
		return "", trace.BadParameter("invalid service account format: empty user")
	}

	projectID, iamDomain, found := strings.Cut(domain, ".")
	if !found {
		return "", trace.BadParameter("invalid service account format: missing <project-id>.iam.gserviceaccount.com after @")
	}

	if projectID == "" {
		return "", trace.BadParameter("invalid service account format: missing project ID")
	}

	if iamDomain != expectedParentDomain {
		return "", trace.BadParameter("invalid service account format: expected suffix %q, got %q", expectedParentDomain, iamDomain)
	}

	return projectID, nil
}

func ValidateGCPServiceAccountName(serviceAccount string) error {
	_, err := ProjectIDFromServiceAccountName(serviceAccount)
	return err
}
