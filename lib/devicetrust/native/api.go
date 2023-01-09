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

import devicepb "github.com/gravitational/teleport/api/gen/proto/go/teleport/devicetrust/v1"

// EnrollDeviceInit creates the initial enrollment data for the device.
// This includes fetching or creating a device credential, collecting device
// data and filling in any OS-specific fields.
func EnrollDeviceInit() (*devicepb.EnrollDeviceInit, error) {
	return enrollDeviceInit()
}

// CollectDeviceData collects OS-specific device data for device enrollment or
// device authentication ceremonies.
func CollectDeviceData() (*devicepb.DeviceCollectedData, error) {
	return collectDeviceData()
}

// SignChallenge signs a device challenge for device enrollment or device
// authentication ceremonies.
func SignChallenge(chal []byte) (sig []byte, err error) {
	return signChallenge(chal)
}

// GetDeviceCredential returns the current device credential, if it exists.
func GetDeviceCredential() (*devicepb.DeviceCredential, error) {
	return getDeviceCredential()
}
