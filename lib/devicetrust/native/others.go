//go:build !darwin

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

package native

import (
	"errors"

	devicepb "github.com/gravitational/teleport/api/gen/proto/go/teleport/devicetrust/v1"
)

// trace.NotImplemented avoided on purpose: we use NotImplemented errors to
// detect the lack of a server-side Device Trust implementation.
var errPlatformNotSupported = errors.New("platform not supported")

func enrollDeviceInit() (*devicepb.EnrollDeviceInit, error) {
	return nil, errPlatformNotSupported
}

func collectDeviceData() (*devicepb.DeviceCollectedData, error) {
	return nil, errPlatformNotSupported
}

func signChallenge(chal []byte) (sig []byte, err error) {
	return nil, errPlatformNotSupported
}

func getDeviceCredential() (*devicepb.DeviceCredential, error) {
	return nil, errPlatformNotSupported
}
