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

export function DownloadsIcon({ size = 18, fill = 'white' }: SVGIconProps) {
  return (
    <svg
      viewBox="0 0 18 18"
      xmlns="http://www.w3.org/2000/svg"
      width={size}
      height={size}
      fill={fill}
    >
      <path d="M8.62734 13.3277C8.73281 13.4543 8.86641 13.5 9 13.5C9.13359 13.5 9.26698 13.4528 9.37336 13.3577L14.4359 8.85772C14.6677 8.65174 14.6897 8.29593 14.4831 8.06389C14.2766 7.83098 13.9185 7.80957 13.6889 8.01721L9.5625 11.6859V0.5625C9.5625 0.251578 9.30937 0 9 0C8.69063 0 8.4375 0.251578 8.4375 0.5625V11.6859L4.31016 8.01562C4.08164 7.8082 3.72305 7.83281 3.51562 8.06484C3.31031 8.26523 3.33211 8.65195 3.56484 8.82773L8.62734 13.3277ZM15.75 11.25H14.0625C13.7519 11.25 13.5 11.5018 13.5 11.8125C13.5 12.1231 13.7519 12.375 14.0625 12.375H15.75C16.3712 12.375 16.875 12.8788 16.875 13.5V15.75C16.875 16.3712 16.3712 16.875 15.75 16.875H2.25C1.62879 16.875 1.125 16.3712 1.125 15.75V13.5C1.125 12.8788 1.62879 12.375 2.25 12.375H3.9375C4.24687 12.375 4.5 12.1219 4.5 11.8125C4.5 11.5031 4.24687 11.25 3.9375 11.25H2.25C1.00723 11.25 0 12.2572 0 13.5V15.75C0 16.9928 1.00723 18 2.25 18H15.75C16.9928 18 18 16.9928 18 15.75V13.5C18 12.259 16.991 11.25 15.75 11.25ZM15.4688 14.625C15.4688 14.1592 15.0908 13.7812 14.625 13.7812C14.1592 13.7812 13.7812 14.1592 13.7812 14.625C13.7812 15.0908 14.1592 15.4688 14.625 15.4688C15.0908 15.4688 15.4688 15.0926 15.4688 14.625Z" />
    </svg>
  );
}
