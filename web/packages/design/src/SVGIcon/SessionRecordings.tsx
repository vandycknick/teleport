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

import React from 'react';

import type { SVGIconProps } from './common';

export function SessionRecordingsIcon({
  size = 14,
  fill = 'white',
}: SVGIconProps) {
  return (
    <svg
      viewBox="0 0 14 14"
      xmlns="http://www.w3.org/2000/svg"
      width={size}
      height={size}
      fill={fill}
    >
      <path
        fillRule="evenodd"
        clipRule="evenodd"
        d="M1.94731 12.0528C3.20381 13.3084 4.87331 14.0001 6.65 14.0001C8.42669 14.0001 10.0971 13.3084 11.3527 12.0528C12.6083 10.7971 13.3 9.12764 13.3 7.35095C13.3 5.57426 12.6092 3.90476 11.3527 2.64826C10.0962 1.39176 8.42669 0.700073 6.65 0.700073C4.87331 0.700073 3.20294 1.39176 1.94731 2.64826C0.691688 3.90476 0 5.57426 0 7.35095C0 9.12676 0.690813 10.7971 1.94731 12.0528ZM0.7 7.35007C0.7 4.06926 3.36919 1.40007 6.65 1.40007C9.93081 1.40007 12.6 4.06926 12.6 7.35007C12.6 10.6309 9.93081 13.3001 6.65 13.3001C3.36919 13.3001 0.7 10.6309 0.7 7.35007ZM4.38052 11.1558C4.43302 11.1851 4.49164 11.2 4.54983 11.2C4.61414 11.2 4.67845 11.1825 4.73533 11.1466L10.3353 7.6466C10.4377 7.58317 10.4998 7.47029 10.4998 7.34998C10.4998 7.22967 10.4377 7.11723 10.3353 7.05335L4.73533 3.55335C4.6277 3.48598 4.49208 3.48248 4.38052 3.54417C4.26895 3.60585 4.19983 3.72267 4.19983 3.84998V10.85C4.19983 10.9764 4.26939 11.0941 4.38052 11.1558ZM4.89983 10.2187V4.48129L9.48964 7.34998L4.89983 10.2187Z"
      />
    </svg>
  );
}
