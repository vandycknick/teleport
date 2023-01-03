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

package common

import "time"

const (
	// DefaultMongoDBServerSelectionTimeout is the timeout for selecting a
	// MongoDB server to connect to.
	DefaultMongoDBServerSelectionTimeout = 5 * time.Second

	// MaxPages is the maximum number of pages to iterate over when fetching cloud databases.
	MaxPages = 10

	// DefaultTestConnectionTimeout is the timeout used for quick connection test.
	DefaultTestConnectionTimeout = 5 * time.Second
)
