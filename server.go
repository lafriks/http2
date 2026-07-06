package http2

import (
	"bufio"
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/valyala/fasthttp"
)

// ErrServerShutdown is returned by ServeConn on connections accepted
// after Shutdown has been called.
var ErrServerShutdown = errors.New("server is shutting down")

// ServerConfig ...
type ServerConfig struct {
	// PingInterval is the interval at which the server will send a
	// ping message to a client.
	//
	// To disable pings set the PingInterval to a negative value.
	PingInterval time.Duration

	// ...
	MaxConcurrentStreams int

	// ShutdownGracePeriod is the longest a connection keeps accepting new
	// streams between the warning GOAWAY and the definitive GOAWAY when
	// Shutdown is called (RFC 9113, section 6.8). A PING is sent along
	// the warning GOAWAY and its ack, which proves the client has seen
	// the GOAWAY, ends the wait earlier; the grace period is the
	// fallback for clients that don't reply.
	//
	// It defaults to 500ms. Set it to a negative value to send the
	// definitive GOAWAY right away.
	ShutdownGracePeriod time.Duration

	// Debug is a flag that will allow the library to print debugging information.
	Debug bool
}

func (sc *ServerConfig) defaults() {
	if sc.PingInterval == 0 {
		sc.PingInterval = time.Second * 10
	}

	if sc.MaxConcurrentStreams <= 0 {
		sc.MaxConcurrentStreams = 1024
	}

	if sc.ShutdownGracePeriod == 0 {
		sc.ShutdownGracePeriod = time.Millisecond * 500
	}
}

// Server defines an HTTP/2 entity that can handle HTTP/2 connections.
type Server struct {
	s *fasthttp.Server

	cnf ServerConfig

	mu           sync.Mutex
	conns        map[*serverConn]struct{}
	shuttingDown bool
}

func (s *Server) trackConn(sc *serverConn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.shuttingDown {
		return false
	}

	if s.conns == nil {
		s.conns = make(map[*serverConn]struct{})
	}
	s.conns[sc] = struct{}{}

	return true
}

func (s *Server) untrackConn(sc *serverConn) {
	s.mu.Lock()
	delete(s.conns, sc)
	s.mu.Unlock()
}

// Shutdown gracefully shuts down the HTTP/2 connections: every connection
// sends a warning GOAWAY, keeps accepting new streams for the configured
// ShutdownGracePeriod, then sends the definitive GOAWAY and closes once the
// accepted streams have been served (RFC 9113, section 6.8). If ctx expires
// before that, the remaining connections are closed forcefully and the
// context error is returned. The ctx deadline should therefore exceed the
// ShutdownGracePeriod.
//
// Shutdown doesn't close the listeners, that is the caller's (or
// fasthttp.Server.Shutdown's) job. Call Shutdown first so that the
// fasthttp shutdown doesn't have to wait for the HTTP/2 connections.
// Once Shutdown has been called the server can't be reused.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.shuttingDown = true
	conns := make([]*serverConn, 0, len(s.conns))
	for sc := range s.conns {
		conns = append(conns, sc)
	}
	s.mu.Unlock()

	for _, sc := range conns {
		sc.gracefulShutdown()
	}

	ticker := time.NewTicker(time.Millisecond * 50)
	defer ticker.Stop()

	for {
		s.mu.Lock()
		open := len(s.conns)
		s.mu.Unlock()

		if open == 0 {
			return nil
		}

		select {
		case <-ctx.Done():
			s.mu.Lock()
			for sc := range s.conns {
				_ = sc.c.Close()
			}
			s.mu.Unlock()

			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// ServeConn starts serving a net.Conn as HTTP/2.
//
// This function will fail if the connection does not support the HTTP/2 protocol.
func (s *Server) ServeConn(c net.Conn) error {
	defer func() { _ = c.Close() }()

	if !ReadPreface(c) {
		return errors.New("wrong preface")
	}

	sc := &serverConn{
		c:              c,
		h:              s.s.Handler,
		br:             bufio.NewReader(c),
		bw:             bufio.NewWriterSize(c, 1<<14*10),
		lastID:         0,
		writer:         make(chan *FrameHeader, 128),
		reader:         make(chan *FrameHeader, 128),
		maxRequestTime:      s.s.ReadTimeout,
		maxIdleTime:         s.s.IdleTimeout,
		pingInterval:        s.cnf.PingInterval,
		shutdown:            make(chan struct{}),
		shutdownGracePeriod: s.cnf.ShutdownGracePeriod,
		pingAck:             make(chan struct{}, 1),
		logger:              s.s.Logger,
		debug:               s.cnf.Debug,
	}

	if sc.logger == nil {
		sc.logger = logger
	}

	sc.enc.Reset()
	sc.dec.Reset()

	sc.maxWindow = 1 << 22
	sc.currentWindow = sc.maxWindow

	sc.st.Reset()
	sc.st.SetMaxWindowSize(uint32(sc.maxWindow))
	sc.st.SetMaxConcurrentStreams(uint32(s.cnf.MaxConcurrentStreams))

	if !s.trackConn(sc) {
		return ErrServerShutdown
	}
	defer s.untrackConn(sc)

	if err := sc.Handshake(); err != nil {
		return err
	}

	return sc.Serve()
}
