/*
Copyright 2020 Gravitational, Inc.

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

package utils

import (
	"strings"
	"testing"

	"github.com/coreos/go-semver/semver"
	"github.com/stretchr/testify/require"
)

// TestKernelVersion checks that version strings for various distributions
// can be parsed correctly.
func TestKernelVersion(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		inRelease  string
		inMin      string
		inMax      string
		outRelease string
	}{
		// Debian 10
		{
			inRelease:  "4.19.0-6-cloud-amd64",
			inMin:      "4.18.0",
			inMax:      "4.20.0",
			outRelease: "4.19.0",
		},
		// CentOS 6
		{
			inRelease:  "4.19.94",
			inMin:      "4.18.0",
			inMax:      "4.20.0",
			outRelease: "4.19.94",
		},
		// CentOS 7
		{
			inRelease:  "4.19.72-25.58.amzn2.x86_64",
			inMin:      "4.18.0",
			inMax:      "4.20.0",
			outRelease: "4.19.72",
		},
		// CentOS 8
		{
			inRelease:  "4.18.0-80.11.2.el8_0.x86_64",
			inMin:      "4.17.0",
			inMax:      "4.29.0",
			outRelease: "4.18.0",
		},
		// Ubuntu 19.04
		{
			inRelease:  "5.0.0-1028-gcp",
			inMin:      "4.18.0",
			inMax:      "5.1.0",
			outRelease: "5.0.0",
		},
		// Windows WSL2
		{
			inRelease:  "5.15.68.1-microsoft-standard-WSL2",
			inMin:      "5.14.0",
			inMax:      "5.16.0",
			outRelease: "5.15.68",
		},
	}

	for _, tt := range tests {
		t.Run(tt.inRelease, func(t *testing.T) {
			// Check the version is parsed correctly.
			version, err := kernelVersion(strings.NewReader(tt.inRelease))
			require.NoError(t, err)
			require.Equal(t, version.String(), tt.outRelease)

			// Check that version comparisons work.
			min, err := semver.NewVersion(tt.inMin)
			require.NoError(t, err)
			max, err := semver.NewVersion(tt.inMax)
			require.NoError(t, err)
			require.Equal(t, version.LessThan(*max), true)
			require.Equal(t, version.LessThan(*min), false)
		})
	}

	t.Run("invalid kernel version", func(t *testing.T) {
		v, err := kernelVersion(strings.NewReader("10.23"))
		require.Nil(t, v)
		require.EqualError(
			t,
			err,
			`unable to extract kernel semver from string "10.23"`,
		)
	})
}
