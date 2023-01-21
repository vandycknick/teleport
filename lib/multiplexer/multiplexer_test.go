/*
Copyright 2017 Gravitational, Inc.

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

package multiplexer

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgproto3/v2"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/types"
	apisshutils "github.com/gravitational/teleport/api/utils/sshutils"
	"github.com/gravitational/teleport/lib/auth/native"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/fixtures"
	"github.com/gravitational/teleport/lib/httplib"
	"github.com/gravitational/teleport/lib/jwt"
	"github.com/gravitational/teleport/lib/multiplexer/test"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/sshutils"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/teleport/lib/utils/cert"
)

func TestMain(m *testing.M) {
	utils.InitLoggerForTests()
	os.Exit(m.Run())
}

// TestMux tests multiplexing protocols
// using the same listener.
func TestMux(t *testing.T) {
	_, signer, err := cert.CreateCertificate("foo", ssh.HostCert)
	require.NoError(t, err)

	// TestMux tests basic use case of multiplexing TLS
	// and SSH on the same listener socket
	t.Run("TLSSSH", func(t *testing.T) {
		t.Parallel()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)

		mux, err := New(Config{
			Listener:                    listener,
			EnableExternalProxyProtocol: true,
		})
		require.NoError(t, err)
		go mux.Serve()
		defer mux.Close()

		backend1 := &httptest.Server{
			Listener: mux.TLS(),
			Config: &http.Server{
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					fmt.Fprintf(w, "backend 1")
				}),
			},
		}
		backend1.StartTLS()
		defer backend1.Close()

		called := false
		sshHandler := sshutils.NewChanHandlerFunc(func(_ context.Context, _ *sshutils.ConnectionContext, nch ssh.NewChannel) {
			called = true
			err := nch.Reject(ssh.Prohibited, "nothing to see here")
			require.NoError(t, err)
		})

		srv, err := sshutils.NewServer(
			"test",
			utils.NetAddr{AddrNetwork: "tcp", Addr: "localhost:0"},
			sshHandler,
			[]ssh.Signer{signer},
			sshutils.AuthMethods{Password: pass("abc123")},
		)
		require.NoError(t, err)
		go srv.Serve(mux.SSH())
		defer srv.Close()
		clt, err := ssh.Dial("tcp", listener.Addr().String(), &ssh.ClientConfig{
			Auth:            []ssh.AuthMethod{ssh.Password("abc123")},
			Timeout:         time.Second,
			HostKeyCallback: ssh.FixedHostKey(signer.PublicKey()),
		})
		require.NoError(t, err)
		defer clt.Close()

		// call new session to initiate opening new channel
		_, err = clt.NewSession()
		require.NotNil(t, err)
		// make sure the channel handler was called OK
		require.True(t, called)

		client := testClient(backend1)
		re, err := client.Get(backend1.URL)
		require.NoError(t, err)
		defer re.Body.Close()
		bytes, err := io.ReadAll(re.Body)
		require.NoError(t, err)
		require.Equal(t, string(bytes), "backend 1")

		// Close mux, new requests should fail
		mux.Close()
		mux.Wait()

		// use new client to use new connection pool
		client = testClient(backend1)
		re, err = client.Get(backend1.URL)
		if err == nil {
			re.Body.Close()
		}
		require.NotNil(t, err)
	})

	// ProxyLine tests proxy line protocol
	t.Run("ProxyLine", func(t *testing.T) {
		t.Parallel()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)

		mux, err := New(Config{
			Listener:                    listener,
			EnableExternalProxyProtocol: true,
		})
		require.NoError(t, err)
		go mux.Serve()
		defer mux.Close()

		backend1 := &httptest.Server{
			Listener: mux.TLS(),
			Config: &http.Server{
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					fmt.Fprintf(w, r.RemoteAddr)
				}),
			},
		}
		backend1.StartTLS()
		defer backend1.Close()

		remoteAddr := net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8000}
		proxyLine := ProxyLine{
			Protocol:    TCP4,
			Source:      remoteAddr,
			Destination: net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000},
		}

		parsedURL, err := url.Parse(backend1.URL)
		require.NoError(t, err)

		conn, err := net.Dial("tcp", parsedURL.Host)
		require.NoError(t, err)
		defer conn.Close()
		// send proxy line first before establishing TLS connection
		_, err = fmt.Fprint(conn, proxyLine.String())
		require.NoError(t, err)

		// upgrade connection to TLS
		tlsConn := tls.Client(conn, clientConfig(backend1))
		defer tlsConn.Close()

		// make sure the TLS call succeeded and we got remote address
		// correctly
		out, err := utils.RoundtripWithConn(tlsConn)
		require.NoError(t, err)
		require.Equal(t, out, remoteAddr.String())
	})

	// ProxyLineV2 tests proxy protocol v2
	t.Run("ProxyLineV2", func(t *testing.T) {
		t.Parallel()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)

		mux, err := New(Config{
			Listener:                    listener,
			EnableExternalProxyProtocol: true,
		})
		require.NoError(t, err)
		go mux.Serve()
		defer mux.Close()

		backend1 := &httptest.Server{
			Listener: mux.TLS(),
			Config: &http.Server{
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					fmt.Fprintf(w, r.RemoteAddr)
				}),
			},
		}
		backend1.StartTLS()
		defer backend1.Close()

		parsedURL, err := url.Parse(backend1.URL)
		require.NoError(t, err)

		conn, err := net.Dial("tcp", parsedURL.Host)
		require.NoError(t, err)
		defer conn.Close()
		// send proxy header + addresses before establishing TLS connection
		_, err = conn.Write([]byte{
			0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, // signature
			0x21, 0x11, // version/command, family
			0x00, 12, // address length
			0x7F, 0x00, 0x00, 0x01, // source address: 127.0.0.1
			0x7F, 0x00, 0x00, 0x01, // destination address: 127.0.0.1
			0x1F, 0x40, 0x23, 0x28, // source port: 8000, destination port: 9000
		})
		require.NoError(t, err)

		// upgrade connection to TLS
		tlsConn := tls.Client(conn, clientConfig(backend1))
		defer tlsConn.Close()

		// make sure the TLS call succeeded and we got remote address
		// correctly
		out, err := utils.RoundtripWithConn(tlsConn)
		require.NoError(t, err)
		require.Equal(t, out, "127.0.0.1:8000")
	})

	// TestDisabledProxy makes sure the connection gets dropped
	// when Proxy line support protocol is turned off
	t.Run("DisabledProxy", func(t *testing.T) {
		t.Parallel()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)

		mux, err := New(Config{
			Listener:                    listener,
			EnableExternalProxyProtocol: false,
		})
		require.NoError(t, err)
		go mux.Serve()
		defer mux.Close()

		backend1 := &httptest.Server{
			Listener: mux.TLS(),
			Config: &http.Server{
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					fmt.Fprintf(w, r.RemoteAddr)
				}),
			},
		}
		backend1.StartTLS()
		defer backend1.Close()

		remoteAddr := net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8000}
		proxyLine := ProxyLine{
			Protocol:    TCP4,
			Source:      remoteAddr,
			Destination: net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000},
		}

		parsedURL, err := url.Parse(backend1.URL)
		require.NoError(t, err)

		conn, err := net.Dial("tcp", parsedURL.Host)
		require.NoError(t, err)
		defer conn.Close()
		// send proxy line first before establishing TLS connection
		_, err = fmt.Fprint(conn, proxyLine.String())
		require.NoError(t, err)

		// upgrade connection to TLS
		tlsConn := tls.Client(conn, clientConfig(backend1))
		defer tlsConn.Close()

		// make sure the TLS call failed
		_, err = utils.RoundtripWithConn(tlsConn)
		require.NotNil(t, err)
	})

	// Timeout test makes sure that multiplexer respects read deadlines.
	t.Run("Timeout", func(t *testing.T) {
		t.Parallel()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)

		config := Config{
			Listener: listener,
			// Set read deadline in the past to remove reliance on real time
			// and simulate scenario when read deadline has elapsed.
			ReadDeadline:                -time.Millisecond,
			EnableExternalProxyProtocol: true,
		}
		mux, err := New(config)
		require.NoError(t, err)
		go mux.Serve()
		defer mux.Close()

		backend1 := &httptest.Server{
			Listener: mux.TLS(),
			Config: &http.Server{
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					fmt.Fprintf(w, r.RemoteAddr)
				}),
			},
		}
		backend1.StartTLS()
		defer backend1.Close()

		parsedURL, err := url.Parse(backend1.URL)
		require.NoError(t, err)

		conn, err := net.Dial("tcp", parsedURL.Host)
		require.NoError(t, err)
		defer conn.Close()

		// upgrade connection to TLS
		tlsConn := tls.Client(conn, clientConfig(backend1))
		defer tlsConn.Close()

		// roundtrip should fail on the timeout
		_, err = utils.RoundtripWithConn(tlsConn)
		require.NotNil(t, err)
	})

	// UnknownProtocol make sure that multiplexer closes connection
	// with unknown protocol
	t.Run("UnknownProtocol", func(t *testing.T) {
		t.Parallel()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)

		mux, err := New(Config{
			Listener:                    listener,
			EnableExternalProxyProtocol: true,
		})
		require.NoError(t, err)
		go mux.Serve()
		defer mux.Close()

		conn, err := net.Dial("tcp", listener.Addr().String())
		require.NoError(t, err)
		defer conn.Close()

		// try plain HTTP
		_, err = fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
		require.NoError(t, err)

		// connection should be closed
		_, err = conn.Read(make([]byte, 1))
		require.Equal(t, err, io.EOF)
	})

	// DisableSSH disables SSH
	t.Run("DisableSSH", func(t *testing.T) {
		t.Parallel()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)

		mux, err := New(Config{
			Listener:                    listener,
			EnableExternalProxyProtocol: true,
		})
		require.NoError(t, err)
		go mux.Serve()
		defer mux.Close()

		backend1 := &httptest.Server{
			Listener: mux.TLS(),
			Config: &http.Server{
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					fmt.Fprintf(w, "backend 1")
				}),
			},
		}
		backend1.StartTLS()
		defer backend1.Close()

		_, err = ssh.Dial("tcp", listener.Addr().String(), &ssh.ClientConfig{
			Auth:            []ssh.AuthMethod{ssh.Password("abc123")},
			Timeout:         time.Second,
			HostKeyCallback: ssh.FixedHostKey(signer.PublicKey()),
		})
		require.NotNil(t, err)

		// TLS requests will succeed
		client := testClient(backend1)
		re, err := client.Get(backend1.URL)
		require.NoError(t, err)
		defer re.Body.Close()
		bytes, err := io.ReadAll(re.Body)
		require.NoError(t, err)
		require.Equal(t, string(bytes), "backend 1")

		// Close mux, new requests should fail
		mux.Close()
		mux.Wait()

		// use new client to use new connection pool
		client = testClient(backend1)
		re, err = client.Get(backend1.URL)
		if err == nil {
			re.Body.Close()
		}
		require.NotNil(t, err)
	})

	// TestDisableTLS tests scenario with disabled TLS
	t.Run("DisableTLS", func(t *testing.T) {
		t.Parallel()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)

		mux, err := New(Config{
			Listener:                    listener,
			EnableExternalProxyProtocol: true,
		})
		require.NoError(t, err)
		go mux.Serve()
		defer mux.Close()

		backend1 := &httptest.Server{
			Listener: &noopListener{addr: listener.Addr()},
			Config: &http.Server{
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					fmt.Fprintf(w, "backend 1")
				}),
			},
		}
		backend1.StartTLS()
		defer backend1.Close()

		called := false
		sshHandler := sshutils.NewChanHandlerFunc(func(_ context.Context, _ *sshutils.ConnectionContext, nch ssh.NewChannel) {
			called = true
			err := nch.Reject(ssh.Prohibited, "nothing to see here")
			require.NoError(t, err)
		})

		srv, err := sshutils.NewServer(
			"test",
			utils.NetAddr{AddrNetwork: "tcp", Addr: "localhost:0"},
			sshHandler,
			[]ssh.Signer{signer},
			sshutils.AuthMethods{Password: pass("abc123")},
		)
		require.NoError(t, err)
		go srv.Serve(mux.SSH())
		defer srv.Close()
		clt, err := ssh.Dial("tcp", listener.Addr().String(), &ssh.ClientConfig{
			Auth:            []ssh.AuthMethod{ssh.Password("abc123")},
			Timeout:         time.Second,
			HostKeyCallback: ssh.FixedHostKey(signer.PublicKey()),
		})
		require.NoError(t, err)
		defer clt.Close()

		// call new session to initiate opening new channel
		_, err = clt.NewSession()
		require.NotNil(t, err)
		// make sure the channel handler was called OK
		require.Equal(t, called, true)

		client := testClient(backend1)
		re, err := client.Get(backend1.URL)
		if err == nil {
			re.Body.Close()
		}
		require.NotNil(t, err)

		// Close mux, new requests should fail
		mux.Close()
		mux.Wait()
	})

	// NextProto tests multiplexing using NextProto selector
	t.Run("NextProto", func(t *testing.T) {
		t.Parallel()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)

		mux, err := New(Config{
			Listener:                    listener,
			EnableExternalProxyProtocol: true,
		})
		require.NoError(t, err)
		go mux.Serve()
		defer mux.Close()

		cfg, err := fixtures.LocalTLSConfig()
		require.NoError(t, err)

		tlsLis, err := NewTLSListener(TLSListenerConfig{
			Listener: tls.NewListener(mux.TLS(), cfg.TLS),
		})
		require.NoError(t, err)
		go tlsLis.Serve()

		opts := []grpc.ServerOption{
			grpc.Creds(&httplib.TLSCreds{
				Config: cfg.TLS,
			}),
		}
		s := grpc.NewServer(opts...)
		test.RegisterPingerServer(s, &server{})

		errCh := make(chan error, 2)

		go func() {
			errCh <- s.Serve(tlsLis.HTTP2())
		}()

		httpServer := http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, "http backend")
			}),
		}
		go func() {
			err := httpServer.Serve(tlsLis.HTTP())
			if err == nil || err == http.ErrServerClosed {
				errCh <- nil
				return
			}
			errCh <- err
		}()

		url := fmt.Sprintf("https://%s", listener.Addr())
		client := cfg.NewClient()
		re, err := client.Get(url)
		require.NoError(t, err)
		defer re.Body.Close()
		bytes, err := io.ReadAll(re.Body)
		require.NoError(t, err)
		require.Equal(t, string(bytes), "http backend")

		creds := credentials.NewClientTLSFromCert(cfg.CertPool, "")

		// Set up a connection to the server.
		conn, err := grpc.Dial(listener.Addr().String(), grpc.WithTransportCredentials(creds), grpc.WithBlock())
		require.NoError(t, err)
		defer conn.Close()

		gclient := test.NewPingerClient(conn)

		out, err := gclient.Ping(context.TODO(), &test.Request{})
		require.NoError(t, err)
		require.Equal(t, out.GetPayload(), "grpc backend")

		// Close mux, new requests should fail
		mux.Close()
		mux.Wait()

		// use new client to use new connection pool
		client = cfg.NewClient()
		re, err = client.Get(url)
		if err == nil {
			re.Body.Close()
		}
		require.NotNil(t, err)

		httpServer.Close()
		s.Stop()
		// wait for both servers to finish
		for i := 0; i < 2; i++ {
			err := <-errCh
			require.NoError(t, err)
		}
	})

	t.Run("PostgresProxy", func(t *testing.T) {
		t.Parallel()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		mux, err := New(Config{
			Context:  ctx,
			Listener: listener,
		})
		require.NoError(t, err)
		go mux.Serve()
		defer mux.Close()

		// register listener before establishing frontend connection
		dblistener := mux.DB()

		// Connect to the listener and send Postgres SSLRequest which is what
		// psql or other Postgres client will do.
		conn, err := net.Dial("tcp", listener.Addr().String())
		require.NoError(t, err)
		defer conn.Close()

		frontend := pgproto3.NewFrontend(pgproto3.NewChunkReader(conn), conn)
		err = frontend.Send(&pgproto3.SSLRequest{})
		require.NoError(t, err)

		// This should not hang indefinitely since we set timeout on the mux context above.
		conn, err = dblistener.Accept()
		require.NoError(t, err, "detected Postgres connection")
		require.Equal(t, ProtoPostgres, conn.(*Conn).Protocol())
	})

	// WebListener verifies web listener correctly multiplexes connections
	// between web and database listeners based on the client certificate.
	t.Run("WebListener", func(t *testing.T) {
		t.Parallel()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)

		mux, err := New(Config{
			Listener:                    listener,
			EnableExternalProxyProtocol: true,
		})
		require.NoError(t, err)
		go mux.Serve()
		defer mux.Close()

		// register listener before establishing frontend connection
		tlslistener := mux.TLS()

		// Generate self-signed CA.
		caKey, caCert, err := tlsca.GenerateSelfSignedCA(pkix.Name{CommonName: "test-ca"}, nil, time.Hour)
		require.NoError(t, err)
		ca, err := tlsca.FromKeys(caCert, caKey)
		require.NoError(t, err)
		certPool := x509.NewCertPool()
		certPool.AppendCertsFromPEM(caCert)

		// Sign server certificate.
		serverRSAKey, err := native.GenerateRSAPrivateKey()
		require.NoError(t, err)
		serverPEM, err := ca.GenerateCertificate(tlsca.CertificateRequest{
			Subject:   pkix.Name{CommonName: "localhost"},
			PublicKey: serverRSAKey.Public(),
			NotAfter:  time.Now().Add(time.Hour),
			DNSNames:  []string{"127.0.0.1"},
		})
		require.NoError(t, err)
		serverCert, err := tls.X509KeyPair(serverPEM, tlsca.MarshalPrivateKeyPEM(serverRSAKey))
		require.NoError(t, err)

		// Sign client certificate with database access identity.
		clientRSAKey, err := rsa.GenerateKey(rand.Reader, constants.RSAKeySize)
		require.NoError(t, err)
		subject, err := (&tlsca.Identity{
			Username: "alice",
			Groups:   []string{"admin"},
			RouteToDatabase: tlsca.RouteToDatabase{
				ServiceName: "postgres",
			},
		}).Subject()
		require.NoError(t, err)
		clientPEM, err := ca.GenerateCertificate(tlsca.CertificateRequest{
			Subject:   subject,
			PublicKey: clientRSAKey.Public(),
			NotAfter:  time.Now().Add(time.Hour),
		})
		require.NoError(t, err)
		clientCert, err := tls.X509KeyPair(clientPEM, tlsca.MarshalPrivateKeyPEM(clientRSAKey))
		require.NoError(t, err)

		webLis, err := NewWebListener(WebListenerConfig{
			Listener: tls.NewListener(tlslistener, &tls.Config{
				ClientCAs:    certPool,
				ClientAuth:   tls.VerifyClientCertIfGiven,
				Certificates: []tls.Certificate{serverCert},
			}),
		})
		require.NoError(t, err)
		go webLis.Serve()
		defer webLis.Close()

		go func() {
			conn, err := webLis.Web().Accept()
			require.NoError(t, err)
			defer conn.Close()
			conn.Write([]byte("web listener"))
		}()

		go func() {
			conn, err := webLis.DB().Accept()
			require.NoError(t, err)
			defer conn.Close()
			conn.Write([]byte("db listener"))
		}()

		webConn, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
			RootCAs: certPool,
		})
		require.NoError(t, err)
		defer webConn.Close()

		webBytes, err := io.ReadAll(webConn)
		require.NoError(t, err)
		require.Equal(t, "web listener", string(webBytes))

		dbConn, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
			RootCAs:      certPool,
			Certificates: []tls.Certificate{clientCert},
		})
		require.NoError(t, err)
		defer dbConn.Close()

		dbBytes, err := io.ReadAll(dbConn)
		require.NoError(t, err)
		require.Equal(t, "db listener", string(dbBytes))
	})

	t.Run("SSHProxyHelloSignature", func(t *testing.T) {
		// Ensures SSH connections fronted with the ProxyHelloSignature are
		// detected as SSH connections.
		t.Parallel()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)

		mux, err := New(Config{
			Listener:                    listener,
			EnableExternalProxyProtocol: true,
		})
		require.NoError(t, err)
		go mux.Serve()
		defer mux.Close()

		// Record the remote addr from the point of view of the ssh handler
		// so we can confirm that the header is parsed properly.
		calledWithRemoteAddr := ""
		sshHandler := sshutils.NewChanHandlerFunc(func(_ context.Context, c *sshutils.ConnectionContext, nch ssh.NewChannel) {
			calledWithRemoteAddr = c.ServerConn.RemoteAddr().String()
			err := nch.Reject(ssh.Prohibited, "nothing to see here")
			require.NoError(t, err)
		})

		srv, err := sshutils.NewServer(
			"test",
			utils.NetAddr{AddrNetwork: "tcp", Addr: "localhost:0"},
			sshHandler,
			[]ssh.Signer{signer},
			sshutils.AuthMethods{Password: pass("abc123")},
		)
		require.NoError(t, err)
		go srv.Serve(mux.SSH())
		defer srv.Close()

		// Manually create client conn so we can inject the ProxyHelloSignature
		conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
		remoteAddr := "6.6.6.6:1337"
		require.NoError(t, err)
		hp := &apisshutils.HandshakePayload{
			ClientAddr: remoteAddr,
		}
		payloadJSON, err := json.Marshal(hp)
		require.NoError(t, err)
		payload := fmt.Sprintf("%s%s\x00", apisshutils.ProxyHelloSignature, payloadJSON)
		_, err = conn.Write([]byte(payload))
		require.NoError(t, err)
		c, chans, reqs, err := ssh.NewClientConn(conn, listener.Addr().String(), &ssh.ClientConfig{
			Auth:            []ssh.AuthMethod{ssh.Password("abc123")},
			Timeout:         time.Second,
			HostKeyCallback: ssh.FixedHostKey(signer.PublicKey()),
		})
		require.NoError(t, err)
		clt := ssh.NewClient(c, chans, reqs)
		defer clt.Close()

		// call new session to initiate opening new channel
		_, err = clt.NewSession()
		require.EqualError(t, err, "ssh: rejected: administratively prohibited (nothing to see here)")
		// make sure the channel handler was called OK
		require.Equal(t, remoteAddr, calledWithRemoteAddr)

		// Close mux, new requests should fail
		mux.Close()
		mux.Wait()
	})

	// Ensures that we can correctly send and verify signed PROXY header
	t.Run("signed PROXYv2 headers", func(t *testing.T) {
		t.Parallel()

		const clusterName = "teleport-test"
		tlsProxyCert, casGetter, jwtSigner := getTestCertCAsGetterAndSigner(t, clusterName)

		listener4, err := net.Listen("tcp", "127.0.0.1:")
		require.NoError(t, err)

		// If listener for IPv6 will fail to be created we'll skip IPv6 portion of test.
		listener6, _ := net.Listen("tcp6", "[::1]:0")

		startServing := func(muxListener net.Listener) (*Mux, *httptest.Server) {
			mux, err := New(Config{
				Listener:                    muxListener,
				EnableExternalProxyProtocol: true,
				CertAuthorityGetter:         casGetter,
				Clock:                       clockwork.NewFakeClockAt(time.Now()),
				LocalClusterName:            clusterName,
			})
			require.NoError(t, err)

			muxTLSListener := mux.TLS()

			go mux.Serve()

			backend := &httptest.Server{
				Listener: muxTLSListener,

				Config: &http.Server{
					Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						fmt.Fprintf(w, r.RemoteAddr)
					}),
				},
			}
			backend.StartTLS()

			return mux, backend
		}

		mux4, backend4 := startServing(listener4)
		defer mux4.Close()
		defer backend4.Close()

		var backend6 *httptest.Server
		var mux6 *Mux
		if listener6 != nil {
			mux6, backend6 = startServing(listener6)
			defer mux6.Close()
			defer backend6.Close()
		}

		addr1 := net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 444}
		addr2 := net.TCPAddr{IP: net.ParseIP("5.4.3.2"), Port: 555}
		addrV6 := net.TCPAddr{IP: net.ParseIP("::1"), Port: 999}

		t.Run("single signed PROXY header", func(t *testing.T) {
			conn, err := net.Dial("tcp", listener4.Addr().String())
			require.NoError(t, err)
			defer conn.Close()

			signedHeader, err := GetSignedPROXYHeader(&addr1, &addr2, clusterName, tlsProxyCert, jwtSigner)
			require.NoError(t, err)

			_, err = conn.Write(signedHeader)
			require.NoError(t, err)

			clt := tls.Client(conn, clientConfig(backend4))

			out, err := utils.RoundtripWithConn(clt)
			require.NoError(t, err)
			require.Equal(t, addr1.String(), out)
		})
		t.Run("single signed PROXY header on IPv6", func(t *testing.T) {
			if listener6 == nil {
				t.Skip("Skipping since IPv6 listener is not available")
			}
			conn, err := net.Dial("tcp6", listener6.Addr().String())
			require.NoError(t, err)

			defer conn.Close()

			signedHeader, err := GetSignedPROXYHeader(&addrV6, &addrV6, clusterName, tlsProxyCert, jwtSigner)
			require.NoError(t, err)

			_, err = conn.Write(signedHeader)
			require.NoError(t, err)

			clt := tls.Client(conn, clientConfig(backend6))

			out, err := utils.RoundtripWithConn(clt)
			require.NoError(t, err)
			require.Equal(t, addrV6.String(), out)
		})
		t.Run("two signed PROXY headers", func(t *testing.T) {
			conn, err := net.Dial("tcp", listener4.Addr().String())
			require.NoError(t, err)
			defer conn.Close()

			signedHeader, err := GetSignedPROXYHeader(&addr1, &addr2, clusterName, tlsProxyCert, jwtSigner)
			require.NoError(t, err)

			_, err = conn.Write(signedHeader)
			require.NoError(t, err)
			_, err = conn.Write(signedHeader)
			require.NoError(t, err)

			clt := tls.Client(conn, clientConfig(backend4))

			_, err = utils.RoundtripWithConn(clt)
			require.Error(t, err)
		})
		t.Run("two signed PROXY headers, one signed for wrong cluster", func(t *testing.T) {
			conn, err := net.Dial("tcp", listener4.Addr().String())
			require.NoError(t, err)
			defer conn.Close()

			signedHeader, err := GetSignedPROXYHeader(&addr1, &addr2, clusterName, tlsProxyCert, jwtSigner)
			require.NoError(t, err)
			signedHeader2, err := GetSignedPROXYHeader(&addr2, &addr1, clusterName+"wrong", tlsProxyCert, jwtSigner)
			require.NoError(t, err)

			_, err = conn.Write(signedHeader)
			require.NoError(t, err)
			_, err = conn.Write(signedHeader2)
			require.NoError(t, err)

			clt := tls.Client(conn, clientConfig(backend4))

			_, err = utils.RoundtripWithConn(clt)
			require.Error(t, err)
		})
		t.Run("first unsigned then signed PROXY headers", func(t *testing.T) {
			conn, err := net.Dial("tcp", listener4.Addr().String())
			require.NoError(t, err)
			defer conn.Close()

			signedHeader, err := GetSignedPROXYHeader(&addr1, &addr2, clusterName, tlsProxyCert, jwtSigner)
			require.NoError(t, err)

			pl := ProxyLine{
				Protocol:    TCP4,
				Source:      addr2,
				Destination: addr1,
			}

			b, err := pl.Bytes()
			require.NoError(t, err)

			_, err = conn.Write(b)
			require.NoError(t, err)
			_, err = conn.Write(signedHeader)
			require.NoError(t, err)

			clt := tls.Client(conn, clientConfig(backend4))

			out, err := utils.RoundtripWithConn(clt)
			require.NoError(t, err)
			require.Equal(t, addr1.String(), out)
		})
		t.Run("first signed then unsigned PROXY headers", func(t *testing.T) {
			conn, err := net.Dial("tcp", listener4.Addr().String())
			require.NoError(t, err)
			defer conn.Close()

			signedHeader, err := GetSignedPROXYHeader(&addr1, &addr2, clusterName, tlsProxyCert, jwtSigner)
			require.NoError(t, err)

			pl := ProxyLine{
				Protocol:    TCP4,
				Source:      addr2,
				Destination: addr1,
			}

			b, err := pl.Bytes()
			require.NoError(t, err)

			_, err = conn.Write(signedHeader)
			require.NoError(t, err)
			_, err = conn.Write(b)
			require.NoError(t, err)

			clt := tls.Client(conn, clientConfig(backend4))

			out, err := utils.RoundtripWithConn(clt)
			require.NoError(t, err)
			require.Equal(t, addr1.String(), out)
		})
		t.Run("two unsigned PROXY headers, gets an error", func(t *testing.T) {
			conn, err := net.Dial("tcp", listener4.Addr().String())
			require.NoError(t, err)
			defer conn.Close()

			pl := ProxyLine{
				Protocol:    TCP4,
				Source:      addr2,
				Destination: addr1,
			}

			b, err := pl.Bytes()
			require.NoError(t, err)

			_, err = conn.Write(b)
			require.NoError(t, err)
			_, err = conn.Write(b)
			require.NoError(t, err)

			clt := tls.Client(conn, clientConfig(backend4))

			_, err = utils.RoundtripWithConn(clt)
			require.Error(t, err)
		})
	})
	// Ensures that we can correctly send and verify signed PROXY header
	t.Run("is ignored if signed PROXY header can't be verified (wrong cluster)", func(t *testing.T) {
		t.Parallel()

		const clusterName = "teleport-test"
		tlsProxyCert, _, jwtSigner := getTestCertCAsGetterAndSigner(t, clusterName)
		_, wrongCAsGetter, _ := getTestCertCAsGetterAndSigner(t, "wrong-cluster")

		listener, err := net.Listen("tcp", "127.0.0.1:")
		require.NoError(t, err)

		mux, err := New(Config{
			Listener:                    listener,
			EnableExternalProxyProtocol: true,
			CertAuthorityGetter:         wrongCAsGetter,
			LocalClusterName:            "different-cluster",
		})
		require.NoError(t, err)

		muxTLSListener := mux.TLS()

		go mux.Serve()
		defer mux.Close()

		backend := &httptest.Server{
			Listener: muxTLSListener,
			Config: &http.Server{
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					fmt.Fprintf(w, r.RemoteAddr)
				}),
			},
		}
		backend.StartTLS()
		defer backend.Close()

		conn, err := net.Dial("tcp", listener.Addr().String())
		require.NoError(t, err)
		defer conn.Close()

		ip := "1.2.3.4"
		sAddr := net.TCPAddr{IP: net.ParseIP(ip), Port: 444}
		dAddr := net.TCPAddr{IP: net.ParseIP(ip), Port: 555}

		signedHeader, err := GetSignedPROXYHeader(&sAddr, &dAddr, clusterName, tlsProxyCert, jwtSigner)
		require.NoError(t, err)

		_, err = conn.Write(signedHeader)
		require.NoError(t, err)

		clt := tls.Client(conn, clientConfig(backend))

		out, err := utils.RoundtripWithConn(clt)
		require.NoError(t, err)
		require.Equal(t, conn.LocalAddr().String(), out)
	})
}

type mockCAsGetter struct {
	HostCA types.CertAuthority
}

func (m *mockCAsGetter) GetCertAuthority(ctx context.Context, id types.CertAuthID, loadKeys bool, opts ...services.MarshalOption) (types.CertAuthority, error) {
	return m.HostCA, nil
}

func TestProtocolString(t *testing.T) {
	for i := -1; i < len(protocolStrings)+1; i++ {
		got := Protocol(i).String()
		switch i {
		case -1, len(protocolStrings) + 1:
			require.Equal(t, "", got)
		default:
			require.Equal(t, protocolStrings[Protocol(i)], got)
		}
	}
}

// server is used to implement test.PingerServer
type server struct {
	test.UnimplementedPingerServer
}

func (s *server) Ping(ctx context.Context, req *test.Request) (*test.Response, error) {
	return &test.Response{Payload: "grpc backend"}, nil
}

// clientConfig returns tls client config from test http server
// set up to listen on TLS
func clientConfig(srv *httptest.Server) *tls.Config {
	cert, err := x509.ParseCertificate(srv.TLS.Certificates[0].Certificate[0])
	if err != nil {
		panic(err)
	}

	certpool := x509.NewCertPool()
	certpool.AddCert(cert)
	return &tls.Config{
		RootCAs:    certpool,
		ServerName: fmt.Sprintf("%v", cert.IPAddresses[0].String()),
	}
}

// testClient is a test HTTP client set up for TLS
func testClient(srv *httptest.Server) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: clientConfig(srv),
		},
	}
}

func pass(need string) sshutils.PasswordFunc {
	return func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if string(password) == need {
			return nil, nil
		}
		return nil, fmt.Errorf("passwords don't match")
	}
}

type noopListener struct {
	addr net.Addr
}

func (noopListener) Accept() (net.Conn, error) {
	return nil, errors.New("noop")
}

func (noopListener) Close() error {
	return nil
}

func (l noopListener) Addr() net.Addr {
	return l.addr
}

func TestIsHTTP(t *testing.T) {
	t.Parallel()
	for _, verb := range httpMethods {
		t.Run(fmt.Sprintf("Accept %v", string(verb)), func(t *testing.T) {
			data := fmt.Sprintf("%v /some/path HTTP/1.1", string(verb))
			require.True(t, isHTTP([]byte(data)))
		})
	}

	rejectedInputs := []string{
		"some random junk",
		"FAKE /some/path HTTP/1.1",
		// This case checks for a bug where the arguments to bytes.HasPrefix are reversed.
		"GE",
	}
	for _, input := range rejectedInputs {
		t.Run(fmt.Sprintf("Reject %q", input), func(t *testing.T) {
			require.False(t, isHTTP([]byte(input)))
		})
	}
}

func getTestCertCAsGetterAndSigner(t testing.TB, clusterName string) ([]byte, CertAuthorityGetter, PROXYSigner) {
	t.Helper()
	caPriv, caCert, err := tlsca.GenerateSelfSignedCA(pkix.Name{
		CommonName: clusterName, Organization: []string{clusterName}}, []string{clusterName}, time.Hour)
	require.NoError(t, err)

	tlsCA, err := tlsca.FromKeys(caCert, caPriv)
	require.NoError(t, err)

	ca, err := types.NewCertAuthority(types.CertAuthoritySpecV2{
		Type:        types.HostCA,
		ClusterName: clusterName,
		ActiveKeys: types.CAKeySet{
			TLS: []*types.TLSKeyPair{
				{
					Cert: caCert,
					Key:  caPriv,
				},
			},
		},
	})
	require.NoError(t, err)
	mockCAsGetter := &mockCAsGetter{HostCA: ca}

	proxyPriv, err := rsa.GenerateKey(rand.Reader, constants.RSAKeySize)
	require.NoError(t, err)

	// Create host identity with role "Proxy"
	identity := tlsca.Identity{
		TeleportCluster: clusterName,
		Username:        "proxy1",
		Groups:          []string{string(types.RoleProxy)},
		Expires:         time.Now().Add(time.Hour),
	}

	subject, err := identity.Subject()
	require.NoError(t, err)
	certReq := tlsca.CertificateRequest{
		PublicKey: proxyPriv.Public(),
		Subject:   subject,
		NotAfter:  time.Now().Add(time.Hour),
		DNSNames:  []string{"localhost", "127.0.0.1"},
	}
	tlsProxyCertPEM, err := tlsCA.GenerateCertificate(certReq)
	require.NoError(t, err)
	clock := clockwork.NewFakeClockAt(time.Now())
	jwtSigner, err := services.GetJWTSigner(proxyPriv, clusterName, clock)
	require.NoError(t, err)

	tlsProxyCertDER, err := tlsca.ParseCertificatePEM(tlsProxyCertPEM)
	require.NoError(t, err)

	return tlsProxyCertDER.Raw, mockCAsGetter, jwtSigner
}

func BenchmarkMux_ProxyV2Signature(b *testing.B) {
	const clusterName = "test-teleport"

	clock := clockwork.NewFakeClockAt(time.Now())
	tlsProxyCert, casGetter, jwtSigner := getTestCertCAsGetterAndSigner(b, clusterName)

	ca, err := casGetter.GetCertAuthority(context.Background(), types.CertAuthID{
		Type:       types.HostCA,
		DomainName: clusterName,
	}, false)
	require.NoError(b, err)

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(ca.GetTrustedTLSKeyPairs()[0].Cert)
	require.True(b, ok)

	ip := "1.2.3.4"
	sAddr := net.TCPAddr{IP: net.ParseIP(ip), Port: 444}
	dAddr := net.TCPAddr{IP: net.ParseIP(ip), Port: 555}

	b.Run("simulation of signing and verifying PROXY header", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			token, err := jwtSigner.SignPROXY(jwt.PROXYSignParams{
				ClusterName:        clusterName,
				SourceAddress:      sAddr.String(),
				DestinationAddress: dAddr.String(),
			})
			require.NoError(b, err)

			pl := ProxyLine{
				Protocol:    TCP4,
				Source:      sAddr,
				Destination: dAddr,
			}
			err = pl.AddSignature([]byte(token), tlsProxyCert)
			require.NoError(b, err)

			_, err = pl.Bytes()
			require.NoError(b, err)

			cert, err := tlsca.ParseCertificatePEM(tlsProxyCert)
			require.NoError(b, err)
			chains, err := cert.Verify(x509.VerifyOptions{Roots: roots})
			require.NoError(b, err)
			require.NotNil(b, chains)

			identity, err := tlsca.FromSubject(cert.Subject, cert.NotAfter)
			require.NoError(b, err)

			foundRole := checkForSystemRole(identity, types.RoleProxy)
			require.True(b, foundRole, "Missing 'Proxy' role on the signing certificate")

			// Check JWT using proxy cert's public key
			jwtVerifier, err := jwt.New(&jwt.Config{
				Clock:       clock,
				PublicKey:   cert.PublicKey,
				Algorithm:   defaults.ApplicationTokenAlgorithm,
				ClusterName: clusterName,
			})
			require.NoError(b, err, "Could not create JWT verifier")

			claims, err := jwtVerifier.VerifyPROXY(jwt.PROXYVerifyParams{
				ClusterName:        clusterName,
				SourceAddress:      sAddr.String(),
				DestinationAddress: dAddr.String(),
				RawToken:           token,
			})
			require.NoError(b, err, "Got an error while verifying PROXY JWT")
			require.NotNil(b, claims)
			require.Equal(b, fmt.Sprintf("%s/%s", sAddr.String(), dAddr.String()), claims.Subject,
				"IP addresses in PROXY header don't match JWT")
		}
	})
}
