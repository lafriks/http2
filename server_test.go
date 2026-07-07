package http2

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

func serve(s *Server, ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			break
		}

		go s.ServeConn(c)
	}
}

func getConn(s *Server) (*Conn, net.Listener, error) {
	s.cnf.defaults()

	ln := fasthttputil.NewInmemoryListener()

	go serve(s, ln)

	c, err := ln.Dial()
	if err != nil {
		return nil, nil, err
	}

	nc := NewConn(c, ConnOpts{})
	err = nc.doHandshake()

	return nc, ln, err
}

func makeHeaders(id uint32, enc *HPACK, endHeaders, endStream bool, hs map[string]string) *FrameHeader {
	fr := AcquireFrameHeader()

	fr.SetStream(id)

	h := AcquireFrame(FrameHeaders).(*Headers)
	fr.SetBody(h)

	hf := AcquireHeaderField()

	// pseudo-header fields must precede the regular ones, and hs is a map
	// with random iteration order
	for k, v := range hs {
		if k[0] != ':' {
			continue
		}

		hf.Set(k, v)
		enc.AppendHeaderField(h, hf, true)
	}

	for k, v := range hs {
		if k[0] == ':' {
			continue
		}

		hf.Set(k, v)
		enc.AppendHeaderField(h, hf, false)
	}

	h.SetPadding(false)
	h.SetEndStream(endStream)
	h.SetEndHeaders(endHeaders)

	return fr
}

// makeHeadersOrdered is like makeHeaders but preserves the field order, for
// tests where the order is the point.
func makeHeadersOrdered(id uint32, enc *HPACK, endHeaders, endStream bool, hs [][2]string) *FrameHeader {
	fr := AcquireFrameHeader()

	fr.SetStream(id)

	h := AcquireFrame(FrameHeaders).(*Headers)
	fr.SetBody(h)

	hf := AcquireHeaderField()

	for _, kv := range hs {
		hf.Set(kv[0], kv[1])
		enc.AppendHeaderField(h, hf, kv[0][0] == ':')
	}

	h.SetPadding(false)
	h.SetEndStream(endStream)
	h.SetEndHeaders(endHeaders)

	return fr
}

func TestMalformedRequestIsReset(t *testing.T) {
	s := &Server{
		s: &fasthttp.Server{
			Handler: func(ctx *fasthttp.RequestCtx) {
				ctx.WriteString("OK")
			},
		},
		cnf: ServerConfig{
			PingInterval: -1,
		},
	}

	c, ln, err := getConn(s)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	defer ln.Close()

	if err := c.c.SetReadDeadline(time.Now().Add(time.Second * 10)); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		headers [][2]string
	}{
		{"uppercase field name", [][2]string{
			{":method", "GET"}, {":path", "/"}, {":scheme", "https"}, {":authority", "localhost"},
			{"X-Custom", "1"},
		}},
		{"connection-specific field", [][2]string{
			{":method", "GET"}, {":path", "/"}, {":scheme", "https"}, {":authority", "localhost"},
			{"connection", "keep-alive"},
		}},
		{"te other than trailers", [][2]string{
			{":method", "GET"}, {":path", "/"}, {":scheme", "https"}, {":authority", "localhost"},
			{"te", "gzip"},
		}},
		{"pseudo-header after regular field", [][2]string{
			{":method", "GET"}, {":path", "/"}, {":scheme", "https"},
			{"x-custom", "1"},
			{":authority", "localhost"},
		}},
		{"missing :method", [][2]string{
			{":path", "/"}, {":scheme", "https"}, {":authority", "localhost"},
		}},
		{"empty :path", [][2]string{
			{":method", "GET"}, {":path", ""}, {":scheme", "https"}, {":authority", "localhost"},
		}},
		{"duplicated :path", [][2]string{
			{":method", "GET"}, {":path", "/"}, {":path", "/other"}, {":scheme", "https"}, {":authority", "localhost"},
		}},
		{"content-length without payload", [][2]string{
			{":method", "POST"}, {":path", "/"}, {":scheme", "https"}, {":authority", "localhost"},
			{"content-length", "5"},
		}},
	}

	id := uint32(3)

	for _, tc := range cases {
		c.writeFrame(makeHeadersOrdered(id, c.enc, true, true, tc.headers))

		fr, err := c.readNext()
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}

		if fr.Type() != FrameResetStream || fr.Stream() != id {
			t.Fatalf("%s: expected reset of stream %d, got %s on %d", tc.name, id, fr.Type(), fr.Stream())
		}

		if code := fr.Body().(*RstStream).Code(); code != ProtocolError {
			t.Fatalf("%s: expected ProtocolError, got %s", tc.name, code)
		}

		ReleaseFrameHeader(fr)

		id += 2
	}

	// content-length not matching the DATA payload
	h1 := makeHeadersOrdered(id, c.enc, true, false, [][2]string{
		{":method", "POST"}, {":path", "/"}, {":scheme", "https"}, {":authority", "localhost"},
		{"content-length", "5"},
	})
	c.writeFrame(h1)

	if err := writeData(c.bw, h1, []byte("xx")); err != nil {
		t.Fatal(err)
	}
	c.bw.Flush()

	fr, err := c.readNext()
	if err != nil {
		t.Fatal(err)
	}

	if fr.Type() != FrameResetStream || fr.Body().(*RstStream).Code() != ProtocolError {
		t.Fatalf("content-length mismatch: expected ProtocolError reset, got %s", fr.Type())
	}

	ReleaseFrameHeader(fr)

	id += 2

	// the connection and its HPACK state must survive the malformed
	// requests: a valid one still gets served
	c.writeFrame(makeHeadersOrdered(id, c.enc, true, true, [][2]string{
		{":method", "GET"}, {":path", "/"}, {":scheme", "https"}, {":authority", "localhost"},
	}))

	for _, expect := range []FrameType{FrameHeaders, FrameData} {
		fr, err := c.readNext()
		if err != nil {
			t.Fatal(err)
		}

		if fr.Type() != expect || fr.Stream() != id {
			t.Fatalf("expected %s on stream %d, got %s on %d", expect, id, fr.Type(), fr.Stream())
		}

		ReleaseFrameHeader(fr)
	}
}

func TestServerResetToleratesInFlightFrames(t *testing.T) {
	s := &Server{
		s: &fasthttp.Server{
			Handler: func(ctx *fasthttp.RequestCtx) {
				ctx.WriteString("OK")
			},
		},
		cnf: ServerConfig{
			PingInterval: -1,
		},
	}

	c, ln, err := getConn(s)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	defer ln.Close()

	if err := c.c.SetReadDeadline(time.Now().Add(time.Second * 10)); err != nil {
		t.Fatal(err)
	}

	body := make([]byte, 3<<20)

	// a malformed request pipelined with its whole body in one flush: the
	// server resets the stream at END_HEADERS, so all the DATA arrives on
	// an already-reset stream and must be ignored, not answered with a
	// GOAWAY
	h1 := makeHeadersOrdered(3, c.enc, true, false, [][2]string{
		{":method", "POST"}, {":path", "/"}, {":scheme", "https"}, {":authority", "localhost"},
		{"X-Bad", "1"},
		{"content-length", strconv.Itoa(len(body))},
	})
	c.writeFrame(h1)

	if err := writeData(c.bw, h1, body); err != nil {
		t.Fatal(err)
	}
	c.bw.Flush()

	fr, err := c.readNext()
	if err != nil {
		t.Fatal(err)
	}

	if fr.Type() != FrameResetStream || fr.Stream() != 3 {
		t.Fatalf("expected reset of stream 3, got %s on %d", fr.Type(), fr.Stream())
	}

	if code := fr.Body().(*RstStream).Code(); code != ProtocolError {
		t.Fatalf("expected ProtocolError, got %s", code)
	}

	ReleaseFrameHeader(fr)

	// the connection must have survived, and a large valid upload must
	// still complete
	h2 := makeHeaders(5, c.enc, true, false, map[string]string{
		string(StringAuthority): "localhost",
		string(StringMethod):    "POST",
		string(StringPath):      "/",
		string(StringScheme):    "https",
		"content-length":        strconv.Itoa(len(body)),
	})
	c.writeFrame(h2)

	if err := writeData(c.bw, h2, body); err != nil {
		t.Fatal(err)
	}
	c.bw.Flush()

	for {
		fr, err := c.readNext()
		if err != nil {
			t.Fatal(err)
		}

		if fr.Stream() != 5 {
			t.Fatalf("expected frame on stream 5, got %s on %d", fr.Type(), fr.Stream())
		}

		done := fr.Type() == FrameData && fr.Flags().Has(FlagEndStream)

		ReleaseFrameHeader(fr)

		if done {
			break
		}
	}

	// the DATA discarded on the reset stream must still have been counted
	// against the connection window and refilled: the handshake grants
	// 1<<22, and each 3MB phase (discarded and served) crosses the refill
	// threshold once, so well over 3MB of refills must have arrived
	if refilled := int(c.serverWindow) - 1<<22; refilled < 3<<20 {
		t.Fatalf("expected at least %d bytes of connection window refills, got %d", 3<<20, refilled)
	}
}

func TestUnknownFrameTypeIgnored(t *testing.T) {
	s := newShutdownServer(time.Millisecond * 50)

	c, ln, err := getConn(s)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	defer ln.Close()

	if err := c.c.SetReadDeadline(time.Now().Add(time.Second * 10)); err != nil {
		t.Fatal(err)
	}

	// a frame of unknown type must be ignored and discarded
	// (RFC 9113, section 4.1): length 4, type 0xdd, flags 0, stream 0
	raw := []byte{0x00, 0x00, 0x04, 0xdd, 0x00, 0x00, 0x00, 0x00, 0x00, 'w', 'a', 'a', 't'}
	if _, err := c.bw.Write(raw); err != nil {
		t.Fatal(err)
	}
	c.bw.Flush()

	// the connection must remain fully usable: no GOAWAY, requests served
	h1 := makeHeaders(3, c.enc, true, true, map[string]string{
		string(StringAuthority): "localhost",
		string(StringMethod):    "GET",
		string(StringPath):      "/",
		string(StringScheme):    "https",
	})
	c.writeFrame(h1)

	for _, expect := range []FrameType{FrameHeaders, FrameData} {
		fr, err := c.readNext()
		if err != nil {
			t.Fatal(err)
		}

		if fr.Type() != expect || fr.Stream() != 3 {
			t.Fatalf("expected %s on stream 3, got %s on %d", expect, fr.Type(), fr.Stream())
		}

		ReleaseFrameHeader(fr)
	}
}

func TestFatalErrorClosesConnection(t *testing.T) {
	s := newShutdownServer(time.Millisecond * 50)

	c, ln, err := getConn(s)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	defer ln.Close()

	if err := c.c.SetReadDeadline(time.Now().Add(time.Second * 10)); err != nil {
		t.Fatal(err)
	}

	// a PING carrying a stream ID is a connection error: the server must
	// announce it with a GOAWAY and then actually close the connection
	// (RFC 9113, section 5.4.1)
	fr := AcquireFrameHeader()
	fr.SetStream(3)
	fr.SetBody(AcquireFrame(FramePing))
	if _, err := fr.WriteTo(c.bw); err != nil {
		t.Fatal(err)
	}
	c.bw.Flush()
	ReleaseFrameHeader(fr)

	// readNext returns connection-level GOAWAYs as an error
	_, err = c.readNext()
	ga, ok := err.(*GoAway)
	if !ok {
		t.Fatalf("expected GoAway, got %v", err)
	}

	if ga.Code() != ProtocolError {
		t.Fatalf("expected ProtocolError, got %s", ga.Code())
	}

	// and the connection must be closed by the server
	if _, err := c.readNext(); err == nil {
		t.Fatal("expected the connection to be closed")
	}
}

func TestRequestHeaderSizeLimit(t *testing.T) {
	var handled int
	s := &Server{
		s: &fasthttp.Server{
			Handler: func(ctx *fasthttp.RequestCtx) {
				handled++
				ctx.WriteString("OK")
			},
			ReadBufferSize: 512,
		},
		cnf: ServerConfig{
			PingInterval: -1,
		},
	}

	c, ln, err := getConn(s)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	defer ln.Close()

	if err := c.c.SetReadDeadline(time.Now().Add(time.Second * 10)); err != nil {
		t.Fatal(err)
	}

	readResponse := func(id uint32) int {
		t.Helper()

		res := fasthttp.AcquireResponse()
		defer fasthttp.ReleaseResponse(res)

		for {
			fr, err := c.readNext()
			if err != nil {
				t.Fatal(err)
			}

			if fr.Stream() != id {
				t.Fatalf("expected frame on stream %d, got %s on %d", id, fr.Type(), fr.Stream())
			}

			end := fr.Flags().Has(FlagEndStream)

			if err := c.readStream(fr, res); err != nil {
				t.Fatal(err)
			}

			ReleaseFrameHeader(fr)

			if end {
				return res.StatusCode()
			}
		}
	}

	bigValue := make([]byte, 600)
	for i := range bigValue {
		bigValue[i] = 'a'
	}

	// over-limit header list on a complete request: plain 431
	h1 := makeHeadersOrdered(3, c.enc, true, true, [][2]string{
		{":method", "GET"}, {":path", "/"}, {":scheme", "https"}, {":authority", "localhost"},
		{"x-big", string(bigValue)},
	})
	c.writeFrame(h1)

	if status := readResponse(3); status != fasthttp.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("expected 431, got %d", status)
	}

	// over-limit header list on a request with a pending body: the 431 is
	// followed by a NO_ERROR reset aborting the upload
	h2 := makeHeadersOrdered(5, c.enc, true, false, [][2]string{
		{":method", "POST"}, {":path", "/"}, {":scheme", "https"}, {":authority", "localhost"},
		{"x-big", string(bigValue)},
	})
	c.writeFrame(h2)

	if status := readResponse(5); status != fasthttp.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("expected 431, got %d", status)
	}

	fr, err := c.readNext()
	if err != nil {
		t.Fatal(err)
	}

	if fr.Type() != FrameResetStream || fr.Body().(*RstStream).Code() != NoError {
		t.Fatalf("expected NoError reset, got %s", fr.Type())
	}

	ReleaseFrameHeader(fr)

	if handled != 0 {
		t.Fatalf("handler ran %d times for rejected requests", handled)
	}

	// the connection survived and normal requests still work
	h3 := makeHeaders(7, c.enc, true, true, map[string]string{
		string(StringAuthority): "localhost",
		string(StringMethod):    "GET",
		string(StringPath):      "/",
		string(StringScheme):    "https",
	})
	c.writeFrame(h3)

	if status := readResponse(7); status != fasthttp.StatusOK {
		t.Fatalf("expected 200, got %d", status)
	}

	if handled != 1 {
		t.Fatalf("expected the handler to run once, ran %d times", handled)
	}
}

func TestContinuationFloodIsStopped(t *testing.T) {
	s := &Server{
		s: &fasthttp.Server{
			Handler: func(ctx *fasthttp.RequestCtx) {
				ctx.WriteString("OK")
			},
			ReadBufferSize: 512,
		},
		cnf: ServerConfig{
			PingInterval: -1,
		},
	}

	c, ln, err := getConn(s)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	defer ln.Close()

	if err := c.c.SetReadDeadline(time.Now().Add(time.Second * 10)); err != nil {
		t.Fatal(err)
	}

	// an endless header block: HEADERS without END_HEADERS followed by
	// CONTINUATION frames until the server gives up
	h1 := makeHeadersOrdered(3, c.enc, false, false, [][2]string{
		{":method", "GET"}, {":path", "/"}, {":scheme", "https"}, {":authority", "localhost"},
	})
	c.writeFrame(h1)

	filler := make([]byte, 1000)
	for i := range filler {
		filler[i] = 'b'
	}

	hf := AcquireHeaderField()
	for i := 0; i < 64; i++ {
		// encode one large field through the Headers frame, then move the
		// raw fragment into a CONTINUATION frame
		henc := AcquireFrame(FrameHeaders).(*Headers)
		hf.Set("x-flood-"+strconv.Itoa(i), string(filler))
		c.enc.AppendHeaderField(henc, hf, false)

		cont := AcquireFrame(FrameContinuation).(*Continuation)
		cont.SetHeader(append([]byte{}, henc.Headers()...))
		cont.SetEndHeaders(false)
		ReleaseFrame(henc)

		fr := AcquireFrameHeader()
		fr.SetStream(3)
		fr.SetBody(cont)

		if _, err := fr.WriteTo(c.bw); err != nil {
			break // the server already closed the connection
		}
		if err := c.bw.Flush(); err != nil {
			break
		}

		ReleaseFrameHeader(fr)
	}

	// the server must answer with ENHANCE_YOUR_CALM instead of decoding
	// the flood forever
	fr, err := c.readNext()
	if err != nil {
		t.Fatal(err)
	}

	if fr.Type() != FrameGoAway {
		t.Fatalf("expected GoAway, got %s", fr.Type())
	}

	if code := fr.Body().(*GoAway).Code(); code != EnhanceYourCalm {
		t.Fatalf("expected EnhanceYourCalm, got %s", code)
	}
}

func TestRequestBodySizeLimit(t *testing.T) {
	var handled int
	s := &Server{
		s: &fasthttp.Server{
			Handler: func(ctx *fasthttp.RequestCtx) {
				handled++
				ctx.WriteString("OK")
			},
			MaxRequestBodySize: 16,
		},
		cnf: ServerConfig{
			PingInterval: -1,
		},
	}

	c, ln, err := getConn(s)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	defer ln.Close()

	if err := c.c.SetReadDeadline(time.Now().Add(time.Second * 10)); err != nil {
		t.Fatal(err)
	}

	// readResponse reads HEADERS(+DATA) for the stream and returns the status
	readResponse := func(id uint32) int {
		t.Helper()

		res := fasthttp.AcquireResponse()
		defer fasthttp.ReleaseResponse(res)

		for {
			fr, err := c.readNext()
			if err != nil {
				t.Fatal(err)
			}

			if fr.Stream() != id {
				t.Fatalf("expected frame on stream %d, got %s on %d", id, fr.Type(), fr.Stream())
			}

			end := fr.Flags().Has(FlagEndStream)

			if err := c.readStream(fr, res); err != nil {
				t.Fatal(err)
			}

			ReleaseFrameHeader(fr)

			if end {
				return res.StatusCode()
			}
		}
	}

	post := func(id uint32, contentLength int, body []byte) {
		t.Helper()

		hs := map[string]string{
			string(StringAuthority): "localhost",
			string(StringMethod):    "POST",
			string(StringPath):      "/",
			string(StringScheme):    "https",
		}
		if contentLength >= 0 {
			hs["content-length"] = strconv.Itoa(contentLength)
		}

		h := makeHeaders(id, c.enc, true, false, hs)
		c.writeFrame(h)

		if err := writeData(c.bw, h, body); err != nil {
			t.Fatal(err)
		}
		c.bw.Flush()
	}

	// after the early 413 the server asks the client to stop the upload
	expectAbort := func(id uint32) {
		t.Helper()

		fr, err := c.readNext()
		if err != nil {
			t.Fatal(err)
		}

		if fr.Type() != FrameResetStream || fr.Stream() != id {
			t.Fatalf("expected reset of stream %d, got %s on %d", id, fr.Type(), fr.Stream())
		}

		if code := fr.Body().(*RstStream).Code(); code != NoError {
			t.Fatalf("expected NoError reset, got %s", code)
		}

		ReleaseFrameHeader(fr)
	}

	// declared length over the limit: rejected without the handler running,
	// even though the actual payload is small
	post(3, 100, make([]byte, 100))
	if status := readResponse(3); status != fasthttp.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", status)
	}
	expectAbort(3)

	// streamed body over the limit without any declared length, spanning
	// several DATA frames: the abort happens mid-upload
	post(5, -1, make([]byte, 40<<10))
	if status := readResponse(5); status != fasthttp.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", status)
	}
	expectAbort(5)

	if handled != 0 {
		t.Fatalf("handler ran %d times for rejected requests", handled)
	}

	// a body exactly at the limit passes, and the connection survived the
	// rejections
	post(7, 16, make([]byte, 16))
	if status := readResponse(7); status != fasthttp.StatusOK {
		t.Fatalf("expected 200, got %d", status)
	}

	if handled != 1 {
		t.Fatalf("expected the handler to run once, ran %d times", handled)
	}
}

func TestIssue52(t *testing.T) {
	for i := 0; i < 100; i++ {
		testIssue52(t)
	}
}

func testIssue52(t *testing.T) {
	s := &Server{
		s: &fasthttp.Server{
			Handler: func(ctx *fasthttp.RequestCtx) {
				ctx.WriteString("Hello world")
			},
			ReadTimeout: time.Second * 30,
		},
		cnf: ServerConfig{
			Debug: false,
		},
	}

	c, ln, err := getConn(s)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	defer ln.Close()

	msg := []byte("Hello world, how are you doing?")

	h1 := makeHeaders(3, c.enc, true, false, map[string]string{
		string(StringAuthority): "localhost",
		string(StringMethod):    "POST",
		string(StringPath):      "/hello/world",
		string(StringScheme):    "https",
		"content-length":        strconv.Itoa(len(msg)),
	})
	h2 := makeHeaders(9, c.enc, true, false, map[string]string{
		string(StringAuthority): "localhost",
		string(StringMethod):    "POST",
		string(StringPath):      "/hello/world",
		string(StringScheme):    "https",
		"content-length":        strconv.Itoa(len(msg)),
	})
	h3 := makeHeaders(7, c.enc, true, true, map[string]string{
		string(StringAuthority): "localhost",
		string(StringMethod):    "GET",
		string(StringPath):      "/hello/world",
		string(StringScheme):    "https",
	})
	h4 := makeHeaders(11, c.enc, true, true, map[string]string{
		string(StringAuthority): "localhost",
		string(StringMethod):    "GET",
		string(StringPath):      "/hello/world",
		string(StringScheme):    "https",
	})

	c.writeFrame(h1)
	c.writeFrame(h2)
	c.writeFrame(h3)
	c.writeFrame(h4)

	for _, h := range []*FrameHeader{h1, h2} {
		err = writeData(c.bw, h, msg)
		if err != nil {
			t.Fatal(err)
		}

		c.bw.Flush()
	}

	// expect [GOAWAY, RESET, HEADERS, DATA, HEADERS, DATA]
	expect := []FrameType{
		FrameGoAway, FrameResetStream, FrameHeaders,
		FrameData, FrameHeaders, FrameData,
	}

	for len(expect) != 0 {
		next := expect[0]

		fr, err := c.readNext()
		if err != nil {
			t.Fatal(err)
		}

		if fr.Type() != next {
			t.Fatalf("unexpected frame type: %s <> %s", next, fr.Type())
		}

		if fr.Type() == FrameResetStream {
			rst := fr.Body().(*RstStream)
			if rst.Code() != RefusedStreamError {
				t.Fatalf("expected RefusedStreamError, got %s", rst.Code())
			}
		}

		expect = expect[1:]
	}

	_, err = c.readNext()
	if err == nil {
		t.Fatal("Expecting error")
	}

	if err != io.EOF {
		t.Fatalf("expected EOF, got %s", err)
	}
}

func TestIssue27(t *testing.T) {
	s := &Server{
		s: &fasthttp.Server{
			Handler: func(ctx *fasthttp.RequestCtx) {
				ctx.WriteString("Hello world")
			},
			ReadTimeout: time.Second * 1,
		},
		cnf: ServerConfig{
			Debug: false,
		},
	}

	c, ln, err := getConn(s)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	defer ln.Close()

	msg := []byte("Hello world, how are you doing?")

	h1 := makeHeaders(3, c.enc, true, false, map[string]string{
		string(StringAuthority): "localhost",
		string(StringMethod):    "POST",
		string(StringPath):      "/hello/world",
		string(StringScheme):    "https",
		"content-length":        strconv.Itoa(len(msg)),
	})
	h2 := makeHeaders(5, c.enc, true, false, map[string]string{
		string(StringAuthority): "localhost",
		string(StringMethod):    "POST",
		string(StringPath):      "/hello/world",
		string(StringScheme):    "https",
		"content-length":        strconv.Itoa(len(msg)),
	})
	h3 := makeHeaders(7, c.enc, false, false, map[string]string{
		string(StringAuthority): "localhost",
		string(StringMethod):    "GET",
		string(StringPath):      "/hello/world",
		string(StringScheme):    "https",
		"content-length":        strconv.Itoa(len(msg)),
	})

	c.writeFrame(h1)
	c.writeFrame(h2)

	time.Sleep(time.Second)
	c.writeFrame(h3)

	id := uint32(3)

	for i := 0; i < 3; i++ {
		fr, err := c.readNext()
		if err != nil {
			t.Fatal(err)
		}

		if fr.Stream() != id {
			t.Fatalf("Expecting update on stream %d, got %d", id, fr.Stream())
		}

		if fr.Type() != FrameResetStream {
			t.Fatalf("Expecting Reset, got %s", fr.Type())
		}

		rst := fr.Body().(*RstStream)
		if rst.Code() != StreamCanceled {
			t.Fatalf("Expecting StreamCanceled, got %s", rst.Code())
		}

		id += 2
	}
}

func TestUploadReplenishesWindow(t *testing.T) {
	var gotBody int
	s := &Server{
		s: &fasthttp.Server{
			Handler: func(ctx *fasthttp.RequestCtx) {
				gotBody = len(ctx.Request.Body())
				ctx.WriteString("OK")
			},
		},
		cnf: ServerConfig{
			PingInterval: -1,
		},
	}

	c, ln, err := getConn(s)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	defer ln.Close()

	if err := c.c.SetReadDeadline(time.Now().Add(time.Second * 10)); err != nil {
		t.Fatal(err)
	}

	// more than half the server's 4MB connection window, so the
	// connection-level refill must trigger
	body := make([]byte, 3<<20)

	h1 := makeHeaders(3, c.enc, true, false, map[string]string{
		string(StringAuthority): "localhost",
		string(StringMethod):    "POST",
		string(StringPath):      "/upload",
		string(StringScheme):    "https",
		"content-length":        strconv.Itoa(len(body)),
	})

	writeErr := make(chan error, 1)
	go func() {
		c.writeFrame(h1)

		err := writeData(c.bw, h1, body)
		if err == nil {
			err = c.bw.Flush()
		}

		writeErr <- err
	}()

	var strmWin, connWin int
	respDone := false

	for !respDone {
		fr, err := c.readNext()
		if err != nil {
			t.Fatal(err)
		}

		switch fr.Type() {
		case FrameWindowUpdate:
			// readNext consumes stream-0 window updates internally and adds
			// them to serverWindow, so only stream updates arrive here
			if fr.Stream() == 3 {
				strmWin += fr.Body().(*WindowUpdate).Increment()
			}
		case FrameData:
			respDone = fr.Flags().Has(FlagEndStream)
		}

		ReleaseFrameHeader(fr)
	}

	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}

	if gotBody != len(body) {
		t.Fatalf("server got %d body bytes, expected %d", gotBody, len(body))
	}

	// the connection-level refills were consumed by readNext into serverWindow;
	// the server's handshake grants 1<<22, anything above that came from refills
	connWin = int(c.serverWindow) - 1<<22
	if connWin < 1<<21 {
		t.Fatalf("expected connection window replenishment of at least %d, got %d", 1<<21, connWin)
	}

	// every DATA frame except the last (END_STREAM) must have been replenished
	if expected := len(body) - 1<<14; strmWin < expected {
		t.Fatalf("expected stream window replenishment of at least %d, got %d", expected, strmWin)
	}
}

func newShutdownServer(gracePeriod time.Duration) *Server {
	return &Server{
		s: &fasthttp.Server{
			Handler: func(ctx *fasthttp.RequestCtx) {
				ctx.WriteString("OK")
			},
		},
		cnf: ServerConfig{
			PingInterval:        -1,
			ShutdownGracePeriod: gracePeriod,
		},
	}
}

// expectGoAway reads the next frame and asserts it's a GOAWAY with the
// given last stream ID and NoError. readNext returns connection-level
// GOAWAYs (last stream ID 0) as an error instead of a frame.
func expectGoAway(t *testing.T, c *Conn, lastStream uint32) {
	t.Helper()

	var ga *GoAway

	fr, err := c.readNext()
	if lastStream == 0 {
		var ok bool
		if ga, ok = err.(*GoAway); !ok {
			t.Fatalf("expected GoAway, got %v", err)
		}
	} else {
		if err != nil {
			t.Fatal(err)
		}

		if fr.Type() != FrameGoAway {
			t.Fatalf("expected GoAway, got %s", fr.Type())
		}

		ga = fr.Body().(*GoAway)
	}

	if ga.Code() != NoError {
		t.Fatalf("expected NoError, got %s", ga.Code())
	}

	if ga.Stream() != lastStream {
		t.Fatalf("expected last stream %d, got %d", lastStream, ga.Stream())
	}
}

func TestShutdownIdleConnection(t *testing.T) {
	s := newShutdownServer(time.Millisecond * 50)

	c, ln, err := getConn(s)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	defer ln.Close()

	if err := c.c.SetReadDeadline(time.Now().Add(time.Second * 10)); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		done <- s.Shutdown(context.Background())
	}()

	// first the warning GOAWAY, then the definitive one after the grace period
	expectGoAway(t, c, 1<<31-1)
	expectGoAway(t, c, 0)

	if err := <-done; err != nil {
		t.Fatalf("Shutdown returned %v", err)
	}
}

func TestShutdownNoGracePeriod(t *testing.T) {
	s := newShutdownServer(-1)

	c, ln, err := getConn(s)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	defer ln.Close()

	if err := c.c.SetReadDeadline(time.Now().Add(time.Second * 10)); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		done <- s.Shutdown(context.Background())
	}()

	// the definitive GOAWAY comes right away, without the warning one
	expectGoAway(t, c, 0)

	if err := <-done; err != nil {
		t.Fatalf("Shutdown returned %v", err)
	}
}

func TestShutdownDrainsStreams(t *testing.T) {
	// generous grace period: the stream sent within it must not race
	// with the definitive GOAWAY
	s := newShutdownServer(time.Millisecond * 500)

	c, ln, err := getConn(s)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	defer ln.Close()

	if err := c.c.SetReadDeadline(time.Now().Add(time.Second * 10)); err != nil {
		t.Fatal(err)
	}

	msg := []byte("Hello world")

	// open stream 3 without finishing it
	h1 := makeHeaders(3, c.enc, true, false, map[string]string{
		string(StringAuthority): "localhost",
		string(StringMethod):    "POST",
		string(StringPath):      "/hello/world",
		string(StringScheme):    "https",
		"content-length":        strconv.Itoa(len(msg)),
	})
	c.writeFrame(h1)

	// wait for the server to accept the stream
	time.Sleep(time.Millisecond * 200)

	done := make(chan error, 1)
	go func() {
		done <- s.Shutdown(context.Background())
	}()

	expectGoAway(t, c, 1<<31-1)

	// a stream opened within the grace period must still be served
	h2 := makeHeaders(5, c.enc, true, true, map[string]string{
		string(StringAuthority): "localhost",
		string(StringMethod):    "GET",
		string(StringPath):      "/hello/world",
		string(StringScheme):    "https",
	})
	c.writeFrame(h2)

	for _, next := range []FrameType{FrameHeaders, FrameData} {
		fr, err := c.readNext()
		if err != nil {
			t.Fatal(err)
		}

		if fr.Type() != next || fr.Stream() != 5 {
			t.Fatalf("expected %s on stream 5, got %s on %d", next, fr.Type(), fr.Stream())
		}
	}

	// the definitive GOAWAY must cover the stream accepted within the grace period
	expectGoAway(t, c, 5)

	// a stream opened after the definitive GOAWAY must be refused...
	h3 := makeHeaders(7, c.enc, true, true, map[string]string{
		string(StringAuthority): "localhost",
		string(StringMethod):    "GET",
		string(StringPath):      "/hello/world",
		string(StringScheme):    "https",
	})
	c.writeFrame(h3)

	// ...while the accepted stream is served before closing
	if err := writeData(c.bw, h1, msg); err != nil {
		t.Fatal(err)
	}
	c.bw.Flush()

	expect := []FrameType{FrameResetStream, FrameHeaders, FrameData}
	for _, next := range expect {
		fr, err := c.readNext()
		if err != nil {
			t.Fatal(err)
		}

		if fr.Type() != next {
			t.Fatalf("expected %s, got %s", next, fr.Type())
		}

		switch fr.Type() {
		case FrameResetStream:
			if fr.Stream() != 7 {
				t.Fatalf("expected reset of stream 7, got %d", fr.Stream())
			}

			if code := fr.Body().(*RstStream).Code(); code != RefusedStreamError {
				t.Fatalf("expected RefusedStreamError, got %s", code)
			}
		default:
			if fr.Stream() != 3 {
				t.Fatalf("expected response on stream 3, got %d", fr.Stream())
			}
		}
	}

	if err := <-done; err != nil {
		t.Fatalf("Shutdown returned %v", err)
	}
}

func TestShutdownPingEndsGraceEarly(t *testing.T) {
	// the grace period is deliberately long: acking the shutdown PING must
	// end the wait, not the timer
	s := newShutdownServer(time.Second * 10)

	c, ln, err := getConn(s)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	defer ln.Close()

	if err := c.c.SetReadDeadline(time.Now().Add(time.Second * 5)); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		done <- s.Shutdown(context.Background())
	}()

	start := time.Now()
	sawWarning := false

loop:
	for {
		fr, err := ReadFrameFrom(c.br)
		if err != nil {
			t.Fatal(err)
		}

		switch fr.Type() {
		case FramePing:
			ping := fr.Body().(*Ping)
			if !ping.IsAck() {
				// ack echoing the payload, like a real peer would
				ackFr := AcquireFrameHeader()
				ack := AcquireFrame(FramePing).(*Ping)
				ack.SetAck(true)
				ack.SetData(ping.Data())
				ackFr.SetBody(ack)

				if _, err := ackFr.WriteTo(c.bw); err != nil {
					t.Fatal(err)
				}
				c.bw.Flush()

				ReleaseFrameHeader(ackFr)
			}
		case FrameGoAway:
			ga := fr.Body().(*GoAway)
			if !sawWarning {
				if ga.Stream() != 1<<31-1 {
					t.Fatalf("expected warning GOAWAY, got last stream %d", ga.Stream())
				}

				sawWarning = true
			} else {
				if ga.Stream() != 0 || ga.Code() != NoError {
					t.Fatalf("unexpected final GOAWAY: stream=%d code=%s", ga.Stream(), ga.Code())
				}

				break loop
			}
		}

		ReleaseFrameHeader(fr)
	}

	// well under the 10s grace period: the ack ended the wait
	if elapsed := time.Since(start); elapsed > time.Second*2 {
		t.Fatalf("expected the PING ack to end the grace period, took %s", elapsed)
	}

	if err := <-done; err != nil {
		t.Fatalf("Shutdown returned %v", err)
	}
}

// fakeShutdownServer speaks just enough HTTP/2 to drive the RFC 9113
// (section 6.8) shutdown sequence against a client Conn: it answers the
// first request after the warning GOAWAY, refuses the second one and then
// sends the definitive GOAWAY.
func fakeShutdownServer(c net.Conn, closeCh chan struct{}) error {
	defer func() { _ = c.Close() }()

	br := bufio.NewReader(c)
	bw := bufio.NewWriter(c)

	if !ReadPreface(br) {
		return errors.New("wrong preface")
	}

	st := &Settings{}
	st.Reset()
	if err := Handshake(false, bw, st, 1<<20); err != nil {
		return err
	}

	// wait for the two request streams, ignoring the client's settings,
	// window updates and acks
	headers := 0
	for headers < 2 {
		fr, err := ReadFrameFrom(br)
		if err != nil {
			return err
		}

		if fr.Type() == FrameHeaders {
			headers++
		}

		ReleaseFrameHeader(fr)
	}

	writeFrame := func(streamID uint32, body Frame) error {
		fr := AcquireFrameHeader()
		fr.SetStream(streamID)
		fr.SetBody(body)

		_, err := fr.WriteTo(bw)

		ReleaseFrameHeader(fr)

		return err
	}

	ga := AcquireFrame(FrameGoAway).(*GoAway)
	ga.SetStream(1<<31 - 1)
	ga.SetCode(NoError)
	if err := writeFrame(0, ga); err != nil {
		return err
	}

	// the response to stream 1 comes after the warning GOAWAY: a draining
	// client must still read it
	enc := AcquireHPACK()
	res := makeHeaders(1, enc, true, true, map[string]string{
		string(StringStatus): "200",
	})
	_, err := res.WriteTo(bw)
	ReleaseFrameHeader(res)
	ReleaseHPACK(enc)
	if err != nil {
		return err
	}

	rst := AcquireFrame(FrameResetStream).(*RstStream)
	rst.SetCode(RefusedStreamError)
	if err := writeFrame(3, rst); err != nil {
		return err
	}

	ga = AcquireFrame(FrameGoAway).(*GoAway)
	ga.SetStream(1)
	ga.SetCode(NoError)
	if err := writeFrame(0, ga); err != nil {
		return err
	}

	if err := bw.Flush(); err != nil {
		return err
	}

	<-closeCh

	return nil
}

func TestClientDrainOnShutdown(t *testing.T) {
	pipe := fasthttputil.NewPipeConns()

	closeSrv := make(chan struct{})
	srvErr := make(chan error, 1)
	go func() {
		srvErr <- fakeShutdownServer(pipe.Conn2(), closeSrv)
	}()

	c := NewConn(pipe.Conn1(), ConnOpts{})
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}

	newCtx := func(method string) *Ctx {
		req := fasthttp.AcquireRequest()
		req.Header.SetMethod(method)
		req.SetRequestURI("http://localhost/")

		return &Ctx{
			Request:  req,
			Response: fasthttp.AcquireResponse(),
			Err:      make(chan error, 1),
		}
	}

	wait := func(ctx *Ctx) error {
		select {
		case err := <-ctx.Err:
			return err
		case <-time.After(time.Second * 3):
			t.Fatal("request timed out")
			return nil
		}
	}

	ctxA := newCtx("GET") // stream 1
	ctxB := newCtx("GET") // stream 3
	c.Write(ctxA)
	c.Write(ctxB)

	// stream 1 is answered after the warning GOAWAY: the draining
	// connection must still serve it
	if err := wait(ctxA); err != nil {
		t.Fatalf("expected response, got %v", err)
	}

	if code := ctxA.Response.StatusCode(); code != 200 {
		t.Fatalf("expected status 200, got %d", code)
	}

	// stream 3 was refused by the server: the error must be retryable
	if err := wait(ctxB); !errors.Is(err, ErrStreamRefused) {
		t.Fatalf("expected ErrStreamRefused, got %v", err)
	}

	// no new streams on a draining connection
	if c.CanOpenStream() {
		t.Fatal("expected CanOpenStream to be false after GOAWAY")
	}

	ctxC := newCtx("GET")
	c.Write(ctxC)
	if err := wait(ctxC); !errors.Is(err, ErrNotAvailableStreams) {
		t.Fatalf("expected ErrNotAvailableStreams, got %v", err)
	}

	close(closeSrv)
	if err := <-srvErr; err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(time.Second * 3)
	for !c.Closed() {
		if time.Now().After(deadline) {
			t.Fatal("connection never closed")
		}

		time.Sleep(time.Millisecond * 10)
	}
}

func TestShutdownEndToEnd(t *testing.T) {
	// real client against real server: the client acks the shutdown PING
	// automatically, so the 10s grace period must be cut short
	s := newShutdownServer(time.Second * 10)
	s.cnf.defaults()

	ln := fasthttputil.NewInmemoryListener()
	defer ln.Close()
	go serve(s, ln)

	cc, err := ln.Dial()
	if err != nil {
		t.Fatal(err)
	}

	c := NewConn(cc, ConnOpts{})
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}

	req := fasthttp.AcquireRequest()
	req.SetRequestURI("http://localhost/")
	ctx := &Ctx{
		Request:  req,
		Response: fasthttp.AcquireResponse(),
		Err:      make(chan error, 1),
	}

	c.Write(ctx)

	select {
	case err := <-ctx.Err:
		if err != nil {
			t.Fatalf("expected response, got %v", err)
		}
	case <-time.After(time.Second * 3):
		t.Fatal("request timed out")
	}

	start := time.Now()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	if err := s.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown returned %v", err)
	}

	if elapsed := time.Since(start); elapsed > time.Second*2 {
		t.Fatalf("expected the PING ack to end the grace period, took %s", elapsed)
	}

	deadline := time.Now().Add(time.Second * 3)
	for !c.Closed() {
		if time.Now().After(deadline) {
			t.Fatal("connection never closed")
		}

		time.Sleep(time.Millisecond * 10)
	}
}

func TestShutdownForceClose(t *testing.T) {
	s := newShutdownServer(time.Millisecond * 50)

	c, ln, err := getConn(s)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	defer ln.Close()

	// open a stream and never finish it
	h1 := makeHeaders(3, c.enc, true, false, map[string]string{
		string(StringAuthority): "localhost",
		string(StringMethod):    "POST",
		string(StringPath):      "/hello/world",
		string(StringScheme):    "https",
		"content-length":        "11",
	})
	c.writeFrame(h1)

	time.Sleep(time.Millisecond * 200)

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*300)
	defer cancel()

	if err := s.Shutdown(ctx); err != context.DeadlineExceeded {
		t.Fatalf("expected DeadlineExceeded, got %v", err)
	}
}

func TestIdleConnection(t *testing.T) {
	s := &Server{
		s: &fasthttp.Server{
			Handler: func(ctx *fasthttp.RequestCtx) {
				ctx.WriteString("Hello world")
			},
			ReadTimeout: time.Second * 5,
			IdleTimeout: time.Second * 2,
		},
		cnf: ServerConfig{
			Debug: false,
		},
	}

	c, ln, err := getConn(s)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	defer ln.Close()

	h1 := makeHeaders(3, c.enc, true, true, map[string]string{
		string(StringAuthority): "localhost",
		string(StringMethod):    "GET",
		string(StringPath):      "/hello/world",
		string(StringScheme):    "https",
	})

	c.writeFrame(h1)

	expect := []FrameType{
		FrameHeaders, FrameData,
	}

	for i := 0; i < 2; i++ {
		fr, err := c.readNext()
		if err != nil {
			t.Fatal(err)
		}

		if fr.Stream() != 3 {
			t.Fatalf("Expecting update on stream %d, got %d", 3, fr.Stream())
		}

		if fr.Type() != expect[i] {
			t.Fatalf("Expecting %s, got %s", expect[i], fr.Type())
		}
	}

	_, err = c.readNext()
	if err != nil {
		if _, ok := err.(*GoAway); !ok {
			t.Fatal(err)
		}
	}

	_, err = c.readNext()
	if err == nil {
		t.Fatal("Expecting error")
	}
}
