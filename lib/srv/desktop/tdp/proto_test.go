/*
Copyright 2021 Gravitational, Inc.

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

package tdp

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/color"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"

	authproto "github.com/gravitational/teleport/api/client/proto"
	wantypes "github.com/gravitational/teleport/api/types/webauthn"
	wanlib "github.com/gravitational/teleport/lib/auth/webauthn"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/defaults"
)

func TestEncodeDecode(t *testing.T) {
	for _, m := range []Message{
		MouseMove{X: 1, Y: 2},
		MouseButton{Button: MiddleMouseButton, State: ButtonPressed},
		KeyboardButton{KeyCode: 1, State: ButtonPressed},
		func() Message {
			img := image.NewNRGBA(image.Rect(5, 5, 10, 10))
			for x := img.Rect.Min.X; x < img.Rect.Max.X; x++ {
				for y := img.Rect.Min.Y; y < img.Rect.Max.Y; y++ {
					img.Set(x, y, color.NRGBA{1, 2, 3, 4})
				}
			}
			return PNGFrame{Img: img}
		}(),
		ClientScreenSpec{Width: 123, Height: 456},
		ClientUsername{Username: "admin"},
		MouseWheel{Axis: HorizontalWheelAxis, Delta: -123},
		Error{Message: "An error occurred"},
	} {
		t.Run(fmt.Sprintf("%T", m), func(t *testing.T) {
			buf, err := m.Encode()
			require.NoError(t, err)

			out, err := Decode(buf)
			require.NoError(t, err)

			require.Empty(t, cmp.Diff(m, out, cmpopts.IgnoreUnexported(PNGFrame{})))
		})
	}
}

func TestBadDecode(t *testing.T) {
	// 254 is an unknown message type.
	_, err := Decode([]byte{254})
	require.Error(t, err)
}

func TestMFA(t *testing.T) {
	var buff bytes.Buffer
	c := NewConn(&fakeConn{Buffer: &buff})

	mfaWant := &MFA{
		Type: defaults.WebsocketWebauthnChallenge[0],
		MFAAuthenticateChallenge: &client.MFAAuthenticateChallenge{
			WebauthnChallenge: &wanlib.CredentialAssertion{
				Response: protocol.PublicKeyCredentialRequestOptions{
					Challenge:      []byte("challenge"),
					Timeout:        10,
					RelyingPartyID: "teleport",
					AllowedCredentials: []protocol.CredentialDescriptor{
						{
							Type:         "public-key",
							CredentialID: []byte("credential id"),
							Transport:    []protocol.AuthenticatorTransport{protocol.USB},
						},
					},
					UserVerification: "discouraged",
					Extensions: protocol.AuthenticationExtensions{
						"ext1": "value1",
					},
				},
			},
		},
	}
	err := c.WriteMessage(mfaWant)
	require.NoError(t, err)

	mt, err := buff.ReadByte()
	require.NoError(t, err)
	require.Equal(t, TypeMFA, MessageType(mt))

	mfaGot, err := DecodeMFAChallenge(&buff)
	require.NoError(t, err)
	require.Equal(t, mfaWant, mfaGot)

	respWant := &MFA{
		Type: defaults.WebsocketWebauthnChallenge[0],
		MFAAuthenticateResponse: &authproto.MFAAuthenticateResponse{
			Response: &authproto.MFAAuthenticateResponse_Webauthn{
				Webauthn: &wantypes.CredentialAssertionResponse{
					Type:  "public-key",
					RawId: []byte("credential id"),
					Response: &wantypes.AuthenticatorAssertionResponse{
						ClientDataJson:    []byte("client data json"),
						AuthenticatorData: []byte("authenticator data"),
						Signature:         []byte("signature"),
						UserHandle:        []byte("user handle"),
					},
					Extensions: &wantypes.AuthenticationExtensionsClientOutputs{
						AppId: true,
					},
				},
			},
		},
	}
	err = c.WriteMessage(respWant)
	require.NoError(t, err)
	respGot, err := c.ReadMessage()
	require.NoError(t, err)
	require.Equal(t, respWant, respGot)
}

func TestIsNonFatalErr(t *testing.T) {
	// Test that nil returns false
	require.False(t, IsNonFatalErr(nil))
	// Test that any other error returns false
	require.False(t, IsNonFatalErr(errors.New("some other error")))
}

// TDP messages must have size limits in order to prevent attacks that
// soak up system memory. At the same time, exceeding such size limits shouldn't
// kill a user's running session, or else that becomes a DoS attack vector.
// To this end, TestSizeLimitsAreNonFatal checks that exceeding size limits causes
// only non-fatal errors.
//
// An exception to this rule is a long ClientUsername, which can't be used in a DoS
// attack (because there's no way for the RDP server to send a message that's translated
// into a too-long ClientUsername). The best UX in this case is to send a fatal error
// letting them know that the username was too long.
func TestSizeLimitsAreNonFatal(t *testing.T) {
	for _, test := range []struct {
		name  string
		msg   Message
		fatal bool
	}{
		{
			name: "rejects long ClientUsername as fatal",
			msg: ClientUsername{
				Username: string(bytes.Repeat([]byte("a"), windowsMaxUsernameLength+1)),
			},
			fatal: true,
		},
		{
			name:  "rejects long Clipboard",
			msg:   ClipboardData(bytes.Repeat([]byte("a"), maxClipboardDataLength+1)),
			fatal: false,
		},
		{
			name: "rejects long Error",
			msg: Error{
				Message: string(bytes.Repeat([]byte("a"), tdpMaxNotificationMessageLength+1)),
			},
			fatal: false,
		},
		{
			name: "rejects long Notification",
			msg: Notification{
				Message: string(bytes.Repeat([]byte("a"), tdpMaxNotificationMessageLength+1)),
			},
			fatal: false,
		},
		{
			name: "rejects long SharedDirectoryAnnounce",
			msg: SharedDirectoryAnnounce{
				Name: string(bytes.Repeat([]byte("a"), windowsMaxUsernameLength+1)),
			},
			fatal: false,
		},
		{
			name: "rejects long SharedDirectoryInfoRequest",
			msg: SharedDirectoryInfoRequest{
				Path: string(bytes.Repeat([]byte("a"), tdpMaxPathLength+1)),
			},
			fatal: false,
		},
		{
			name: "rejects long SharedDirectoryCreateRequest",
			msg: SharedDirectoryCreateRequest{
				Path: string(bytes.Repeat([]byte("a"), tdpMaxPathLength+1)),
			},
			fatal: false,
		},
		{
			name: "rejects long SharedDirectoryDeleteRequest",
			msg: SharedDirectoryDeleteRequest{
				Path: string(bytes.Repeat([]byte("a"), tdpMaxPathLength+1)),
			},
			fatal: false,
		},
		{
			name: "rejects long SharedDirectoryListRequest",
			msg: SharedDirectoryListRequest{
				Path: string(bytes.Repeat([]byte("a"), tdpMaxPathLength+1)),
			},
			fatal: false,
		},
		{
			name: "rejects long SharedDirectoryReadRequest",
			msg: SharedDirectoryReadRequest{
				Path: string(bytes.Repeat([]byte("a"), tdpMaxPathLength+1)),
			},
			fatal: false,
		},
		{
			name: "rejects long SharedDirectoryReadResponse",
			msg: SharedDirectoryReadResponse{
				ReadDataLength: tdpMaxFileReadWriteLength + 1,
			},
			fatal: false,
		},
		{
			name: "rejects long SharedDirectoryWriteRequest",
			msg: SharedDirectoryWriteRequest{
				WriteDataLength: tdpMaxFileReadWriteLength + 1,
			},
			fatal: false,
		},
		{
			name: "rejects long SharedDirectoryMoveRequest",
			msg: SharedDirectoryMoveRequest{
				OriginalPath: string(bytes.Repeat([]byte("a"), tdpMaxPathLength+1)),
			},
			fatal: false,
		},
		{
			name: "rejects long SharedDirectoryInfoResponse",
			msg: SharedDirectoryInfoResponse{
				CompletionID: 0,
				ErrCode:      0,
				Fso: FileSystemObject{
					Path: string(bytes.Repeat([]byte("a"), tdpMaxPathLength+1)),
				},
			},
			fatal: false,
		},
		{
			name: "rejects long SharedDirectoryCreateResponse",
			msg: SharedDirectoryCreateResponse{
				CompletionID: 0,
				ErrCode:      0,
				Fso: FileSystemObject{
					Path: string(bytes.Repeat([]byte("a"), tdpMaxPathLength+1)),
				},
			},
			fatal: false,
		},
		{
			name: "rejects long SharedDirectoryListResponse",
			msg: SharedDirectoryListResponse{
				CompletionID: 0,
				ErrCode:      0,
				FsoList: []FileSystemObject{{
					Path: string(bytes.Repeat([]byte("a"), tdpMaxPathLength+1)),
				}},
			},
			fatal: false,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			bytes, err := test.msg.Encode()
			require.NoError(t, err)
			_, err = Decode(bytes)
			require.True(t, trace.IsLimitExceeded(err))
			require.Equal(t, test.fatal, IsFatalErr(err))
			require.Equal(t, !test.fatal, IsNonFatalErr(err))
		})
	}
}
