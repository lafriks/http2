// h2c (cleartext HTTP/2) with prior knowledge: the client speaks HTTP/2
// directly over a plain TCP connection, without TLS and without the
// HTTP/1.1 Upgrade dance (RFC 9113, section 3.3). This is the typical
// setup behind a TLS-terminating load balancer, and what gRPC clients
// with insecure credentials do.
//
// Try it with:
//
//	curl --http2-prior-knowledge http://localhost:8080/
package main

import (
	"fmt"
	"log"
	"net"

	"github.com/lafriks/http2"
	"github.com/valyala/fasthttp"
)

func main() {
	s := &fasthttp.Server{
		Handler: requestHandler,
		Name:    "h2c test",
	}

	// ConfigureServer also registers the TLS+ALPN path, but for h2c only
	// the returned *http2.Server matters: ServeConn serves any net.Conn
	// that opens with the HTTP/2 preface.
	h2s := http2.ConfigureServer(s, http2.ServerConfig{})

	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatalln(err)
	}

	log.Println("listening on http://localhost:8080 (h2c, prior knowledge)")

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatalln(err)
		}

		go func() {
			// connections that don't start with the HTTP/2 preface
			// (HTTP/1.x clients, TLS handshakes) fail here
			if err := h2s.ServeConn(c); err != nil {
				log.Printf("%s: %s\n", c.RemoteAddr(), err)
			}
		}()
	}
}

func requestHandler(ctx *fasthttp.RequestCtx) {
	fmt.Fprintf(ctx, "Hello over h2c! Requested path is %q.\n", ctx.Path())
}
