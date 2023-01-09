//go:build !bpf || 386
// +build !bpf 386

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

package restrictedsession

import "github.com/gravitational/teleport/lib/bpf"

// New returns a new NOP service. Note this function does nothing.
func New(config *bpf.RestrictedSessionConfig, wc RestrictionsWatcherClient) (Manager, error) {
	return &NOP{}, nil
}
