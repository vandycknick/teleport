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
import styled from 'styled-components';

import { StepList } from './StepList';

import type { View } from 'teleport/Discover/flow';

interface StepItemProps {
  view: View;
  currentStep: number;
  index: number;
}

export function StepItem(props: StepItemProps) {
  if (props.view.hide) {
    return null;
  }

  let isActive = props.currentStep === props.view.index;
  if (props.view.views) {
    return (
      <StepList
        views={props.view.views}
        currentStep={props.currentStep}
        index={props.index}
      />
    );
  }

  const isDone = props.currentStep > props.view.index;

  return (
    <StepsContainer active={isDone || isActive}>
      <StepTitle>
        {getBulletIcon(isDone, isActive, props.view.index + 1)}

        {props.view.title}
      </StepTitle>
    </StepsContainer>
  );
}

function getBulletIcon(isDone: boolean, isActive: boolean, stepNumber: number) {
  if (isActive) {
    return <ActiveBullet />;
  }

  if (isDone) {
    return <CheckedBullet />;
  }

  return <Bullet>{stepNumber}</Bullet>;
}

const StepTitle = styled.div`
  display: flex;
  align-items: center;
`;

const Bullet = styled.span`
  height: 14px;
  width: 14px;
  border: 1px solid #9b9b9b;
  font-size: 11px;
  border-radius: 50%;
  margin-right: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
`;

const ActiveBullet = styled(Bullet)`
  border-color: ${props => props.theme.colors.secondary.main};
  background: ${props => props.theme.colors.secondary.main};

  :before {
    content: '';
    height: 8px;
    width: 8px;
    border-radius: 50%;
    border: 2px solid ${props => props.theme.colors.primary.main};
  }
`;

const CheckedBullet = styled(Bullet)`
  border-color: ${props => props.theme.colors.secondary.main};
  background: ${props => props.theme.colors.secondary.main};

  :before {
    content: '✓';
  }
`;

const StepsContainer = styled.div<{ active: boolean }>`
  display: flex;
  flex-direction: column;
  color: ${p => (p.active ? 'inherit' : p.theme.colors.text.secondary)};
  margin-right: 32px;
  position: relative;

  &:after {
    position: absolute;
    content: '';
    width: 16px;
    background: #222c59;
    height: 1px;
    top: 50%;
    transform: translate(0, -50%);
    right: -25px;
  }

  &:last-of-type {
    &:after {
      display: none;
    }
  }
`;
