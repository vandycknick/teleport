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

import { Prompt } from 'react-router-dom';

import { FeatureBox } from 'teleport/components/Layout';

import { Navigation } from 'teleport/Discover/Navigation/Navigation';
import { SelectResource } from 'teleport/Discover/SelectResource';
import cfg from 'teleport/config';

import { findViewAtIndex } from './flow';

import { DiscoverProvider, useDiscover } from './useDiscover';

function DiscoverContent() {
  const {
    currentStep,
    selectedResource,
    onSelectResource,
    views,
    ...agentProps
  } = useDiscover();

  let content;
  // we reserve step 0 for "Select Resource Type", that is present in all resource configs
  if (currentStep > 0) {
    const view = findViewAtIndex(views, currentStep);

    const Component = view.component;

    content = <Component {...agentProps} />;

    if (selectedResource.wrapper) {
      content = selectedResource.wrapper(content);
    }
  } else {
    content = (
      <SelectResource
        selectedResourceKind={selectedResource.kind}
        onSelect={kind => onSelectResource(kind)}
        onNext={() => agentProps.nextStep()}
        resourceState={agentProps.resourceState}
      />
    );
  }

  return (
    <>
      <FeatureBox>
        <Navigation
          currentStep={currentStep}
          selectedResource={selectedResource}
          views={views}
        />

        {content}
      </FeatureBox>

      <Prompt
        message={nextLocation => {
          if (nextLocation.pathname === cfg.routes.discover) return true;
          return 'Are you sure you want to exit the “Add New Resource” workflow? You’ll have to start from the beginning next time.';
        }}
        when={selectedResource.shouldPrompt(currentStep)}
      />
    </>
  );
}

export function Discover() {
  return (
    <DiscoverProvider>
      <DiscoverContent />
    </DiscoverProvider>
  );
}
