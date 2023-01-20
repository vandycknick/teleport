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

package responsewriters

import (
	"io"
	"net/http"

	"k8s.io/apimachinery/pkg/runtime"
)

// FilterObj is the interface a Kubernetes Resource Object filter must implement.
type FilterObj interface {
	// FilterObj receives a runtime.Object type and filters the resources on it
	// based on allowed and denied rules.
	// After filtering them, the obj is manipulated to hold the filtered information.
	// The boolean returned indicates if the client is allowed to receive the event
	// with the object.
	FilterObj(runtime.Object) (bool, error)
}

// FilterBuffer is the interface a Kubernetes Resource response filter must implement.
type FilterBuffer interface {
	// FilterBuffer receives a byte array, decodes the response into the appropriate
	// type and filters the resources based on allowed and denied rules configured.
	// After filtering them, it serializes the response and dumps it into output buffer.
	// If any error occurs, the call returns an error.
	FilterBuffer(buf []byte, output io.Writer) error
}

// Filter is the interface a Kubernetes Resource filter must implement.
type Filter interface {
	FilterObj
	FilterBuffer
}

// FilterWrapper is the wrapper function signature that once executed creates
// a runtime filter for Pods.
// The filter exclusion criteria is:
// - deniedPods: excluded if (namespace,name) matches an entry even if it matches
// the allowedPod's list.
// - allowedPods: excluded if (namespace,name) not match a single entry.
type FilterWrapper func(contentType string, responseCode int) (Filter, error)

// GetContentHeader checks for the presence of the "Content-Type" header and
// returns its value or returns the default content-type: "application/json".
func GetContentHeader(header http.Header) string {
	contentType := header.Get(ContentTypeHeader)
	if len(contentType) > 0 {
		return contentType
	}
	return DefaultContentType
}
