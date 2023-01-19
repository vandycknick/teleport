/*
Copyright 2023 Gravitational, Inc.

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

package v5

import (
	"sigs.k8s.io/controller-runtime/pkg/conversion"

	"github.com/gravitational/teleport/api/types"
	v6 "github.com/gravitational/teleport/operator/apis/resources/v6"
)

// ConvertTo converts this CronJob to the Hub version (v6).
func (r *TeleportRole) ConvertTo(dstRaw conversion.Hub) error {
	src := r
	dst := dstRaw.(*v6.TeleportRole)

	dst.Spec = v6.TeleportRoleSpec(src.Spec)
	dst.Version = types.V5
	// ObjectMeta
	dst.ObjectMeta = src.ObjectMeta

	// Status
	dst.Status.Conditions = src.Status.Conditions
	dst.Status.TeleportResourceID = src.Status.TeleportResourceID

	return nil
}

// ConvertFrom converts from the Hub version (v1) to this version.
func (r *TeleportRole) ConvertFrom(srcRaw conversion.Hub) error {
	dst := r
	src := srcRaw.(*v6.TeleportRole)

	dst.Spec = TeleportRoleSpec(src.Spec)
	// ObjectMeta
	dst.ObjectMeta = src.ObjectMeta

	// Status
	dst.Status.Conditions = src.Status.Conditions
	dst.Status.TeleportResourceID = src.Status.TeleportResourceID

	return nil
}
