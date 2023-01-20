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

package loginrule

import (
	"github.com/gogo/protobuf/proto"
	"github.com/gravitational/trace"

	loginrulepb "github.com/gravitational/teleport/api/gen/proto/go/teleport/loginrule/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/types/wrappers"
	"github.com/gravitational/teleport/lib/utils"
)

// Resource is a type to represent login rules which implements types.Resource
// and custom YAML (un)marshaling. This satisfies the expected YAML format for
// the resource, which would be hard/impossible to do for loginrulepb.LoginRule
// directly. Specifically, protoc-gen-go does not have good support for parsing
// a map[string][]string from YAML.
type Resource struct {
	// ResourceHeader is embedded to implement types.Resource
	types.ResourceHeader
	// Spec is the login rule specification
	Spec spec `json:"spec"`
}

// spec holds the login rule properties.
type spec struct {
	Priority         int32               `json:"priority"`
	TraitsMap        map[string][]string `json:"traits_map,omitempty"`
	TraitsExpression string              `json:"traits_expression,omitempty"`
}

// CheckAndSetDefaults sanity checks Resource fields to catch simple errors, and
// sets default values for all fields with defaults.
func (r *Resource) CheckAndSetDefaults() error {
	if err := r.Metadata.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	if r.Kind == "" {
		r.Kind = types.KindLoginRule
	} else if r.Kind != types.KindLoginRule {
		return trace.BadParameter("unexpected resource kind %q, must be %q", r.Kind, types.KindLoginRule)
	}
	if r.Version == "" {
		r.Version = types.V1
	} else if r.Version != types.V1 {
		return trace.BadParameter("unsupported resource version %q, %q is currently the only supported version", r.Version, types.V1)
	}
	if r.Metadata.Name == "" {
		return trace.BadParameter("login rule must have a name")
	}
	if len(r.Spec.TraitsMap) > 0 && len(r.Spec.TraitsExpression) > 0 {
		return trace.BadParameter("login rule has non-empty traits_map and traits_expression, exactly one must be set")
	}
	if len(r.Spec.TraitsMap) == 0 && len(r.Spec.TraitsExpression) == 0 {
		return trace.BadParameter("login rule has empty traits_map and traits_expression, exactly one must be set")
	}
	for key, values := range r.Spec.TraitsMap {
		empty := true
		for _, value := range values {
			if len(value) > 0 {
				empty = false
				break
			}
		}
		if empty {
			return trace.BadParameter("traits_map has zero non-empty values for key %q", key)
		}
	}
	return nil
}

// UnmarshalLoginRule parses a login rule in the Resource format which matches
// the expected YAML format for Teleport resources, sets default values, and
// converts to *loginrulepb.LoginRule.
func UnmarshalLoginRule(raw []byte) (*loginrulepb.LoginRule, error) {
	var resource Resource
	if err := utils.FastUnmarshal(raw, &resource); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := resource.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	return resourceToProto(&resource), nil
}

// ProtoToResource converts a *loginrulepb.LoginRule into a *Resource which
// implements types.Resource and can be marshaled to YAML or JSON in a
// human-friendly format.
func ProtoToResource(rule *loginrulepb.LoginRule) *Resource {
	r := &Resource{
		ResourceHeader: types.ResourceHeader{
			Kind:     types.KindLoginRule,
			Version:  rule.Version,
			Metadata: *proto.Clone(rule.Metadata).(*types.Metadata),
		},
		Spec: spec{
			Priority:         rule.Priority,
			TraitsExpression: rule.TraitsExpression,
			TraitsMap:        traitsMapProtoToResource(rule.TraitsMap),
		},
	}
	return r
}

func resourceToProto(r *Resource) *loginrulepb.LoginRule {
	return &loginrulepb.LoginRule{
		Metadata:         proto.Clone(&r.Metadata).(*types.Metadata),
		Version:          r.Version,
		Priority:         r.Spec.Priority,
		TraitsMap:        traitsMapResourceToProto(r.Spec.TraitsMap),
		TraitsExpression: r.Spec.TraitsExpression,
	}
}

func traitsMapResourceToProto(in map[string][]string) map[string]*wrappers.StringValues {
	if in == nil {
		return nil
	}
	out := make(map[string]*wrappers.StringValues, len(in))
	for key, values := range in {
		out[key] = &wrappers.StringValues{
			Values: append([]string{}, values...),
		}
	}
	return out
}

func traitsMapProtoToResource(in map[string]*wrappers.StringValues) map[string][]string {
	if in == nil {
		return nil
	}
	out := make(map[string][]string, len(in))
	for key, values := range in {
		out[key] = append([]string{}, values.Values...)
	}
	return out
}
