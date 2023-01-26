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
	"bufio"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/lib/srv"
)

// Conn is a desktop protocol connection.
// It converts between a stream of bytes (io.ReadWriter) and a stream of
// Teleport Desktop Protocol (TDP) messages.
type Conn struct {
	rwc       io.ReadWriteCloser
	bufr      *bufio.Reader
	closeOnce sync.Once

	// OnSend is an optional callback that is invoked when a TDP message
	// is sent on the wire. It is passed both the raw bytes and the encoded
	// message.
	OnSend func(m Message, b []byte)

	// OnRecv is an optional callback that is invoked when a TDP message
	// is received on the wire.
	OnRecv func(m Message)

	// localAddr and remoteAddr will be set if rw is
	// a conn that provides these fields
	localAddr  net.Addr
	remoteAddr net.Addr
}

// NewConn creates a new Conn on top of a ReadWriter, for example a TCP
// connection. If the provided ReadWriter also implements srv.TrackingConn,
// then its LocalAddr() and RemoteAddr() will apply to this Conn.
func NewConn(rwc io.ReadWriteCloser) *Conn {
	c := &Conn{
		rwc:  rwc,
		bufr: bufio.NewReader(rwc),
	}

	if tc, ok := rwc.(srv.TrackingConn); ok {
		c.localAddr = tc.LocalAddr()
		c.remoteAddr = tc.RemoteAddr()
	}

	return c
}

// Close closes the connection if the underlying reader can be closed.
func (c *Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		err = c.rwc.Close()
	})
	return err
}

// ReadMessage reads the next incoming message from the connection.
func (c *Conn) ReadMessage() (Message, error) {
	m, err := decode(c.bufr)
	if c.OnRecv != nil {
		c.OnRecv(m)
	}
	return m, trace.Wrap(err)
}

// WriteMessage sends a message to the connection.
func (c *Conn) WriteMessage(m Message) error {
	buf, err := m.Encode()
	if err != nil {
		return trace.Wrap(err)
	}

	_, err = c.rwc.Write(buf)
	if c.OnSend != nil {
		c.OnSend(m, buf)
	}
	return trace.Wrap(err)
}

// SendNotification is a convenience function for sending a Notification message.
func (c *Conn) SendNotification(message string, severity Severity) error {
	return c.WriteMessage(Notification{Message: message, Severity: severity})
}

// LocalAddr returns local address
func (c *Conn) LocalAddr() net.Addr {
	return c.localAddr
}

// RemoteAddr returns remote address
func (c *Conn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

// IsNonFatalErr returns whether or not an error arising from
// the tdp package should be interpreted as fatal or non-fatal
// for an ongoing TDP connection.
func IsNonFatalErr(err error) bool {
	if err == nil {
		return false
	}

	return errors.Is(err, clipDataMaxLenErr) ||
		errors.Is(err, stringMaxLenErr) ||
		errors.Is(err, fileReadWriteMaxLenErr) ||
		errors.Is(err, mfaDataMaxLenErr)
}

// IsFatalErr returns the inverse of IsNonFatalErr
// (except for if err == nil, for which both functions return false)
func IsFatalErr(err error) bool {
	if err == nil {
		return false
	}

	return !IsNonFatalErr(err)
}
