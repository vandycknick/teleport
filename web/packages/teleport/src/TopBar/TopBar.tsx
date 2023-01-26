/*
Copyright 2019-2020 Gravitational, Inc.

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

import React from 'react';
import styled from 'styled-components';
import { Text, Flex, TopNav } from 'design';

import { matchPath, useHistory } from 'react-router';

import useTeleport from 'teleport/useTeleport';
import useStickyClusterId from 'teleport/useStickyClusterId';
import { UserMenuNav } from 'teleport/components/UserMenuNav';
import { useFeatures } from 'teleport/FeaturesContext';

import cfg from 'teleport/config';

import ClusterSelector from './ClusterSelector';

export function TopBar() {
  const ctx = useTeleport();
  const history = useHistory();
  const features = useFeatures();

  const { clusterId, hasClusterUrl } = useStickyClusterId();

  function loadClusters() {
    return ctx.clusterService.fetchClusters();
  }

  function changeCluster(value: string) {
    const newPrefix = cfg.getClusterRoute(value);

    const oldPrefix = cfg.getClusterRoute(clusterId);

    const newPath = history.location.pathname.replace(oldPrefix, newPrefix);
    history.push(newPath);
  }

  // find active feature
  const feature = features
    .filter(feature => Boolean(feature.route))
    .find(f =>
      matchPath(history.location.pathname, {
        path: f.route.path,
        exact: false,
      })
    );

  const title = feature?.route?.title || '';

  // instead of re-creating an expensive react-select component,
  // hide/show it instead
  const styles = {
    display: !hasClusterUrl ? 'none' : 'block',
  };

  return (
    <TopBarContainer>
      {!hasClusterUrl && (
        <Text fontSize="18px" bold>
          {title}
        </Text>
      )}
      <ClusterSelector
        value={clusterId}
        width="384px"
        maxMenuHeight={200}
        mr="20px"
        onChange={changeCluster}
        onLoad={loadClusters}
        style={styles}
      />
      <Flex ml="auto" height="100%">
        <UserMenuNav username={ctx.storeUser.state.username} />
      </Flex>
    </TopBarContainer>
  );
}

export const TopBarContainer = styled(TopNav)`
  height: 72px;
  background-color: inherit;
  padding-left: ${({ theme }) => `${theme.space[6]}px`};
  overflow-y: initial;
  flex-shrink: 0;
  border-bottom: 1px solid ${({ theme }) => theme.colors.primary.main};
`;
