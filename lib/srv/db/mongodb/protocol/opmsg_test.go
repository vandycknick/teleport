/*
Copyright 2022 Gravitational, Inc.

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

package protocol

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDocumentSequenceInsertMultipleParts(t *testing.T) {
	// Payload contains the OP_MSG message content with multiple parts.
	// It was captured from a 'mongo' legacy client by executing following command:
	// db.getCollection('test').insert({foo:"bar"})
	payload := []byte{
		1, 0, 0, 0, 1, 49, 0, 0, 0, 100, 111, 99, 117, 109, 101, 110, 116, 115, 0, 35, 0, 0, 0, 7, 95, 105, 100, 0, 99, 125, 1, 252, 21, 90, 167, 191, 25, 86, 190, 226, 2, 102, 111, 111, 0, 4, 0, 0, 0, 98, 97, 114, 0, 0, 0, 184, 0, 0, 0, 2, 105, 110, 115, 101, 114, 116, 0, 5, 0, 0, 0, 116, 101, 115, 116, 0, 8, 111, 114, 100, 101, 114, 101, 100, 0, 1, 3, 108, 115, 105, 100, 0, 30, 0, 0, 0, 5, 105, 100, 0, 16, 0, 0, 0, 4, 100, 238, 97, 122, 183, 226, 66, 159, 162, 30, 64, 161, 133, 176, 175, 242, 0, 3, 36, 99, 108, 117, 115, 116, 101, 114, 84, 105, 109, 101, 0, 88, 0, 0, 0, 17, 99, 108, 117, 115, 116, 101, 114, 84, 105, 109, 101, 0, 44, 0, 0, 0, 240, 1, 125, 99, 3, 115, 105, 103, 110, 97, 116, 117, 114, 101, 0, 51, 0, 0, 0, 5, 104, 97, 115, 104, 0, 20, 0, 0, 0, 0, 3, 170, 42, 239, 173, 49, 138, 138, 191, 37, 42, 76, 124, 17, 128, 40, 181, 209, 73, 104, 18, 107, 101, 121, 73, 100, 0, 10, 0, 0, 0, 50, 115, 163, 98, 0, 0, 2, 36, 100, 98, 0, 5, 0, 0, 0, 116, 101, 115, 116, 0, 0, 9, 179, 89, 245,
	}
	var header MessageHeader
	_, err := readOpMsg(header, payload)
	require.NoError(t, err)
}
