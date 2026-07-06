package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lafriks/http2"
	"github.com/valyala/fasthttp"
)

func main() {
	debug := flag.Bool("debug", true, "Debug mode")
	flag.Parse()

	cert, priv, err := GenerateTestCertificate("localhost:8443")
	if err != nil {
		log.Fatalln(err)
	}

	s := &fasthttp.Server{
		ReadTimeout: time.Second * 3,
		Handler:     requestHandler,
		Name:        "http2 test",
	}
	err = s.AppendCertEmbed(cert, priv)
	if err != nil {
		log.Fatalln(err)
	}

	h2s := http2.ConfigureServer(s, http2.ServerConfig{
		Debug: *debug,
	})

	go func() {
		if err := s.ListenAndServeTLS(":8443", "", ""); err != nil {
			log.Fatalln(err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	// drain the HTTP/2 connections first (GOAWAY + serving the accepted
	// streams); fasthttp's Shutdown would otherwise wait for them without
	// being able to close them
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	if err := h2s.Shutdown(ctx); err != nil {
		log.Println("HTTP/2 shutdown:", err)
	}

	if err := s.Shutdown(); err != nil {
		log.Println("shutdown:", err)
	}
}

func requestHandler(ctx *fasthttp.RequestCtx) {
	if ctx.Request.Header.IsPost() {
		fmt.Fprintf(ctx, "%s\n", ctx.Request.Body())
		return
	}

	if ctx.FormValue("long") == nil {
		fmt.Fprintf(ctx, "Hello 21th century!\n")
	} else {
		for i := 0; i < 1<<16; i++ {
			ctx.Response.AppendBodyString("A")
		}
	}
}
