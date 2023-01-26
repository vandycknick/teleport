// Copyright 2023 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package web

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/utils"
)

// ServerConfig provides dependencies required to create a [Server].
type ServerConfig struct {
	// Server serves the web api
	Server *http.Server
	// Handler web handler
	Handler *APIHandler
	// Log to write log messages
	Log logrus.FieldLogger
	// ShutdownPollPeriod sets polling period for shutdown
	ShutdownPollPeriod time.Duration
}

// CheckAndSetDefaults validates fields and populates empty fields with default values.
func (c *ServerConfig) CheckAndSetDefaults() error {
	if c.Server == nil {
		return trace.BadParameter("missing required parameter Server")
	}

	if c.Handler == nil {
		return trace.BadParameter("missing required parameter Handler")
	}

	if c.ShutdownPollPeriod <= 0 {
		c.ShutdownPollPeriod = defaults.ShutdownPollPeriod
	}

	if c.Log == nil {
		c.Log = utils.NewLogger().WithField(trace.Component, teleport.ComponentProxy)
	}

	return nil
}

// Server serves the web api.
type Server struct {
	cfg ServerConfig

	mu sync.Mutex
	ln net.Listener
}

// NewServer constructs a [Server] from the provided [ServerConfig].
func NewServer(cfg ServerConfig) (*Server, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	return &Server{
		cfg: cfg,
	}, nil
}

// Serve launches the configured [http.Server].
func (s *Server) Serve(l net.Listener) error {
	s.mu.Lock()
	s.ln = l
	s.mu.Unlock()
	return trace.Wrap(s.cfg.Server.Serve(l))
}

// Close immediately closes the [http.Server].
func (s *Server) Close() error {
	return trace.NewAggregate(s.cfg.Handler.Close(), s.cfg.Server.Close())
}

// HandleConnection handles connections from plain TCP applications.
func (s *Server) HandleConnection(ctx context.Context, conn net.Conn) error {
	return s.cfg.Handler.appHandler.HandleConnection(ctx, conn)
}

// Shutdown initiates graceful shutdown. The underlying [http.Server]
// is not shutdown until all active connections are terminated or
// the context times out. This is required because the [http.Server]
// does not attempt to close nor wait for hijacked connections such as
// WebSockets during Shutdown; which means that any open sessions in the
// web UI will not prevent the [http.Server] from shutting down.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	err := s.ln.Close()
	s.mu.Unlock()

	activeConnections := s.cfg.Handler.handler.userConns.Load()
	if activeConnections == 0 {
		err := s.cfg.Server.Shutdown(ctx)
		return trace.NewAggregate(err, s.cfg.Handler.Close())
	}

	s.cfg.Log.Infof("Shutdown: waiting for %v connections to finish.", activeConnections)
	lastReport := time.Time{}
	ticker := time.NewTicker(s.cfg.ShutdownPollPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			activeConnections = s.cfg.Handler.handler.userConns.Load()
			if activeConnections == 0 {
				err := s.cfg.Server.Shutdown(ctx)
				return trace.NewAggregate(err, s.cfg.Handler.Close())
			}
			if time.Since(lastReport) > 10*s.cfg.ShutdownPollPeriod {
				s.cfg.Log.Infof("Shutdown: waiting for %v connections to finish.", activeConnections)
				lastReport = time.Now()
			}
		case <-ctx.Done():
			s.cfg.Log.Infof("Context canceled wait, returning.")
			return trace.ConnectionProblem(trace.NewAggregate(err, s.cfg.Handler.Close()), "context canceled")
		}
	}
}
