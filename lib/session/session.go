/*
Copyright 2015-2018 Gravitational, Inc.

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

// Package session is used for bookkeeping of SSH interactive sessions
// that happen in realtime across the teleport cluster
package session

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gravitational/trace"
	"github.com/moby/term"

	"github.com/gravitational/teleport/api/types"
)

// ID is a unique session ID.
type ID string

// IsZero returns true if this ID is empty.
func (s *ID) IsZero() bool {
	return len(*s) == 0
}

// String returns string representation of this ID.
func (s *ID) String() string {
	return string(*s)
}

// Check will check that the underlying UUID is valid.
func (s *ID) Check() error {
	_, err := ParseID(string(*s))
	return trace.Wrap(err)
}

// ParseID parses ID and checks if it's correct.
func ParseID(id string) (*ID, error) {
	_, err := uuid.Parse(id)
	if err != nil {
		return nil, trace.BadParameter("%v not a valid UUID", id)
	}
	uid := ID(id)
	return &uid, nil
}

// NewID returns new session ID. The session ID is based on UUIDv4.
func NewID() ID {
	return ID(uuid.New().String())
}

// Session is an interactive collaboration session that represents one
// or many sessions started by the teleport user.
type Session struct {
	// Kind describes what kind of session this is e.g. ssh or kubernetes.
	Kind types.SessionKind `json:"kind"`
	// ID is a unique session identifier
	ID ID `json:"id"`
	// Namespace is a session namespace, separating sessions from each other
	Namespace string `json:"namespace"`
	// Parties is a list of session parties.
	Parties []Party `json:"parties"`
	// TerminalParams sets terminal properties
	TerminalParams TerminalParams `json:"terminal_params"`
	// Login is a login used by all parties joining the session
	Login string `json:"login"`
	// Created records the information about the time when session
	// was created
	Created time.Time `json:"created"`
	// LastActive holds the information about when the session
	// was last active
	LastActive time.Time `json:"last_active"`
	// ServerID of session
	ServerID string `json:"server_id"`
	// ServerHostname of session
	ServerHostname string `json:"server_hostname"`
	// ServerHostPort of session
	ServerHostPort int `json:"server_hostport"`
	// ServerAddr of session
	ServerAddr string `json:"server_addr"`
	// ClusterName is the name of the Teleport cluster that this session belongs to.
	ClusterName string `json:"cluster_name"`
	// KubernetesClusterName is the name of the kube cluster that this session is running in.
	KubernetesClusterName string `json:"kubernetes_cluster_name"`
	// DesktopName is the name of the desktop that this session is running in.
	DesktopName string `json:"desktop_name"`
	// DatabaseName is the name of the database being accessed.
	DatabaseName string `json:"database_name"`
	// AppName is the name of the app being accessed.
	AppName string `json:"app_name"`
	// Owner is the name of the session owner, ie the one who created the session.
	Owner string `json:"owner"`
}

// Participants returns the usernames of the current session participants.
func (s *Session) Participants() []string {
	participants := make([]string, 0, len(s.Parties))
	for _, p := range s.Parties {
		participants = append(participants, p.User)
	}
	return participants
}

// RemoveParty helper allows to remove a party by it's ID from the
// session's list. Returns 'false' if pid couldn't be found
func (s *Session) RemoveParty(pid ID) bool {
	for i := range s.Parties {
		if s.Parties[i].ID == pid {
			s.Parties = append(s.Parties[:i], s.Parties[i+1:]...)
			return true
		}
	}
	return false
}

// Party is a participant a user or a script executing some action
// in the context of the session
type Party struct {
	// ID is a unique party id
	ID ID `json:"id"`
	// Site is a remote address?
	RemoteAddr string `json:"remote_addr"`
	// User is a teleport user using this session
	User string `json:"user"`
	// ServerID is an address of the server
	ServerID string `json:"server_id"`
	// LastActive is a last time this party was active
	LastActive time.Time `json:"last_active"`
}

// String returns debug friendly representation
func (p *Party) String() string {
	return fmt.Sprintf(
		"party(id=%v, remote=%v, user=%v, server=%v, last_active=%v)",
		p.ID, p.RemoteAddr, p.User, p.ServerID, p.LastActive,
	)
}

// TerminalParams holds the terminal size in a session.
type TerminalParams struct {
	W int `json:"w"`
	H int `json:"h"`
}

// UnmarshalTerminalParams takes a serialized string that contains the
// terminal parameters and returns a *TerminalParams.
func UnmarshalTerminalParams(s string) (*TerminalParams, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return nil, trace.BadParameter("failed to unmarshal: too many parts")
	}

	w, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, trace.Wrap(err)
	}
	h, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &TerminalParams{
		W: w,
		H: h,
	}, nil
}

// Serialize is a more strict version of String(): it returns a string
// representation of terminal size, this is used in our APIs.
// Format : "W:H"
// Example: "80:25"
func (p *TerminalParams) Serialize() string {
	return fmt.Sprintf("%d:%d", p.W, p.H)
}

// String returns debug friendly representation of terminal
func (p *TerminalParams) String() string {
	return fmt.Sprintf("TerminalParams(w=%v, h=%v)", p.W, p.H)
}

// Winsize returns low-level parameters for changing PTY
func (p *TerminalParams) Winsize() *term.Winsize {
	return &term.Winsize{
		Width:  uint16(p.W),
		Height: uint16(p.H),
	}
}

// MaxSessionSliceLength is the maximum number of sessions per time window
// that the backend will return.
const MaxSessionSliceLength = 1000

// NewTerminalParamsFromUint32 returns new terminal parameters from uint32 width and height
func NewTerminalParamsFromUint32(w uint32, h uint32) (*TerminalParams, error) {
	if w > maxSize || w < minSize {
		return nil, trace.BadParameter("bad width")
	}
	if h > maxSize || h < minSize {
		return nil, trace.BadParameter("bad height")
	}
	return &TerminalParams{W: int(w), H: int(h)}, nil
}

// NewTerminalParamsFromInt returns new terminal parameters from int width and height
func NewTerminalParamsFromInt(w int, h int) (*TerminalParams, error) {
	if w > maxSize || w < minSize {
		return nil, trace.BadParameter("bad witdth")
	}
	if h > maxSize || h < minSize {
		return nil, trace.BadParameter("bad height")
	}
	return &TerminalParams{W: w, H: h}, nil
}

const (
	minSize = 1
	maxSize = 4096
)
