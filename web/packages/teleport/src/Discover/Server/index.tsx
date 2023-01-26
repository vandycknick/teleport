/**
 * Copyright 2022 Gravitational, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import React from 'react';

import { Server } from 'design/Icon';

import { Resource } from 'teleport/Discover/flow';
import { DownloadScript } from 'teleport/Discover/Server/DownloadScript';
import { SetupAccess } from 'teleport/Discover/Server/SetupAccess';
import { TestConnection } from 'teleport/Discover/Server/TestConnection';
import { ResourceKind, Finished } from 'teleport/Discover/Shared';
import { DiscoverEvent } from 'teleport/services/userEvent';

import { ServerWrapper } from './ServerWrapper';

export const ServerResource: Resource = {
  kind: ResourceKind.Server,
  icon: <Server />,
  wrapper: (component: React.ReactNode) => (
    <ServerWrapper>{component}</ServerWrapper>
  ),
  shouldPrompt(currentStep) {
    // do not prompt on exit if they're selecting a resource
    return currentStep !== 0;
  },
  views: [
    {
      title: 'Select Resource Type',
      eventName: DiscoverEvent.ResourceSelection,
    },
    {
      title: 'Configure Resource',
      component: DownloadScript,
      eventName: DiscoverEvent.DeployService,
    },
    {
      title: 'Set Up Access',
      component: SetupAccess,
      eventName: DiscoverEvent.SetUpAccess,
    },
    {
      title: 'Test Connection',
      component: TestConnection,
      eventName: DiscoverEvent.TestConnection,
    },
    {
      title: 'Finished',
      component: Finished,
      hide: true,
      eventName: DiscoverEvent.Completed,
    },
  ],
};
