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

import React, { useCallback, useEffect, useState } from 'react';
import styled from 'styled-components';

import { matchPath, useHistory } from 'react-router';

import { NavigationSwitcher } from 'teleport/Navigation/NavigationSwitcher';
import cfg from 'teleport/config';

import {
  NAVIGATION_CATEGORIES,
  NavigationCategory,
} from 'teleport/Navigation/categories';

import { useFeatures } from 'teleport/FeaturesContext';

import { NavigationCategoryContainer } from 'teleport/Navigation/NavigationCategoryContainer';

import logo from './logo.png';

import type { Location } from 'history';

import type { TeleportFeature } from 'teleport/types';

const NavigationLogo = styled.div`
  background: url(${logo}) no-repeat;
  background-size: contain;
  width: 181px;
  height: 32px;
  margin-top: 20px;
  margin-left: 32px;
  margin-bottom: 46px;
`;

const NavigationContainer = styled.div`
  background: ${p => p.theme.colors.primary.light};
  width: var(--sidebar-width);
  overflow: hidden;
  position: relative;
  display: flex;
  flex-direction: column;
`;

const CategoriesContainer = styled.div`
  position: relative;
  width: inherit;
  flex: 1;
`;

export function getFirstRouteForCategory(
  features: TeleportFeature[],
  category: NavigationCategory
) {
  const firstRoute = features
    .filter(feature => feature.category === category)
    .filter(feature => Boolean(feature.route))[0];

  return (
    firstRoute?.navigationItem?.getLink(cfg.proxyCluster) || cfg.routes.support
  );
}

function getCategoryForRoute(
  features: TeleportFeature[],
  route: Location<unknown>
) {
  const feature = features
    .filter(feature => Boolean(feature.route))
    .find(feature =>
      matchPath(route.pathname, {
        path: feature.route.path,
        exact: false,
      })
    );

  if (!feature) {
    return NavigationCategory.Resources;
  }

  return feature.category;
}

export function Navigation() {
  const features = useFeatures();
  const history = useHistory();

  const [view, setView] = useState(
    getCategoryForRoute(features, history.location) ||
      NavigationCategory.Resources
  );

  const [previousRoute, setPreviousRoute] = useState('');

  useEffect(() => {
    const category = getCategoryForRoute(features, history.location);

    if (category && category !== view) {
      setView(category);
    }
  }, [history.location, features, view]);

  const handleCategoryChange = useCallback(
    (category: NavigationCategory) => {
      if (view === category) {
        return;
      }

      const previousPathName = history.location.pathname;

      history.push(
        previousRoute || getFirstRouteForCategory(features, category)
      );

      setPreviousRoute(previousPathName);
      setView(category);
    },
    [view, history.location.pathname, previousRoute]
  );

  const categories = NAVIGATION_CATEGORIES.map((category, index) => (
    <NavigationCategoryContainer
      category={category}
      key={index}
      visible={view === category}
    />
  ));

  return (
    <NavigationContainer>
      <NavigationLogo />

      <NavigationSwitcher
        onChange={handleCategoryChange}
        value={view}
        items={NAVIGATION_CATEGORIES}
      />

      <CategoriesContainer>{categories}</CategoriesContainer>
    </NavigationContainer>
  );
}
