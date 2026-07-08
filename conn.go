package http2

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/valyala/fasthttp"
)

// ConnOpts defines the connection options.
type ConnOpts struct {
	// PingInterval defines the interval in which the client will ping the server.
	//
	// An interval of <=0 will make the library to use DefaultPingInterval. Because ping intervals can't be disabled
	PingInterval time.Duration

	// DisablePingChecking ...
	DisablePingChecking bool

	// OnDisconnect is a callback that fires when the Conn disconnects.
	OnDisconnect func(c *Conn)
}

// Handshake performs an HTTP/2 handshake. That means, it will send
// the preface if `preface` is true, send a settings frame and a
// window update frame (for the connection's window).
// TODO: explain more
func Handshake(preface bool, bw *bufio.Writer, st *Settings, maxWin int32) error {
	if preface {
		err := WritePreface(bw)
		if err != nil {
			return err
		}
	}

	fr := AcquireFrameHeader()
	defer ReleaseFrameHeader(fr)

	// write the settings
	st2 := &Settings{}
	st.CopyTo(st2)

	fr.SetBody(st2)

	_, err := fr.WriteTo(bw)
	if err == nil {
		// then send a window update
		fr := AcquireFrameHeader()
		wu := AcquireFrame(FrameWindowUpdate).(*WindowUpdate)
		wu.SetIncrement(int(maxWin))

		fr.SetBody(wu)

		_, err = fr.WriteTo(bw)
		if err == nil {
			err = bw.Flush()
		}

		ReleaseFrameHeader(fr)
	}

	return err
}

// Conn represents a raw HTTP/2 connection over TLS + TCP.
type Conn struct {
	c net.Conn

	br *bufio.Reader
	// bwMu serializes the access to bw: the writeLoop owns it most of the
	// time, but Close writes the closing GOAWAY from whatever goroutine
	// ends the connection first
	bwMu sync.Mutex
	bw   *bufio.Writer

	enc *HPACK
	dec *HPACK

	nextID uint32

	// sendMu guards the send-side flow-control state: serverWindow,
	// serverInitialWindow and every request's stream window delta
	// (Ctx.sendWindow). sendCond wakes the body senders blocked on an
	// exhausted window.
	sendMu   sync.Mutex
	sendCond sync.Cond
	// serverWindow is the connection-level send window: what the server
	// can still receive. It starts at 65535 (RFC 9113, section 6.9.2),
	// grows with the server's WINDOW_UPDATEs and shrinks with the DATA
	// sent.
	serverWindow int64
	// serverInitialWindow is the server's SETTINGS_INITIAL_WINDOW_SIZE:
	// the base of every stream's send window
	serverInitialWindow int64

	maxWindow     int32
	currentWindow int32

	// closeCh unblocks the body senders parked on c.out when the
	// connection dies
	closeCh chan struct{}

	openStreams atomic.Int32

	current Settings
	serverS Settings
	// serverMaxStreams mirrors serverS.maxStreams for CanOpenStream, which
	// runs on caller goroutines while the readLoop rewrites serverS
	serverMaxStreams atomic.Uint32
	// encTableSize carries a pending HPACK table size from the server's
	// SETTINGS (read on the readLoop) to the writeLoop that owns the
	// encoder; negative means nothing pending
	encTableSize atomic.Int64

	state    atomic.Int32
	closeRef uint32

	reqQueued sync.Map

	in  chan *Ctx
	out chan *FrameHeader
	// bodyTasks hands streamed request bodies to an idle sender worker
	// (see writeRequest): sequential uploads reuse a goroutine instead of
	// spawning one each. Unbuffered: a send only succeeds when a worker
	// is already parked waiting.
	bodyTasks chan bodyTask

	pingInterval time.Duration

	// unacks counts the PINGs awaiting their ack; written by both the
	// write loop (sending) and the read loop (acks)
	unacks      atomic.Int32
	disableAcks bool

	// lastErr is written by both loops and read through LastErr
	lastErr      atomic.Pointer[error]
	onDisconnect func(*Conn)

	closed atomic.Bool
}

// NewConn returns a new HTTP/2 connection.
// To start using the connection you need to call Handshake.
func NewConn(c net.Conn, opts ConnOpts) *Conn {
	nc := &Conn{
		c:                   c,
		br:                  bufio.NewReaderSize(c, 4096),
		bw:                  bufio.NewWriterSize(c, maxFrameSize),
		enc:                 AcquireHPACK(),
		dec:                 AcquireHPACK(),
		nextID:              1,
		maxWindow:           1 << 20,
		currentWindow:       1 << 20,
		serverWindow:        65535,
		serverInitialWindow: 65535,
		in:                  make(chan *Ctx, 128),
		out:                 make(chan *FrameHeader, 128),
		bodyTasks:           make(chan bodyTask),
		closeCh:             make(chan struct{}),
		pingInterval:        opts.PingInterval,
		disableAcks:         opts.DisablePingChecking,
		onDisconnect:        opts.OnDisconnect,
	}

	nc.sendCond.L = &nc.sendMu
	nc.encTableSize.Store(-1)

	nc.current.SetMaxWindowSize(1 << 20)
	nc.current.SetPush(false)

	return nc
}

// Dialer allows creating HTTP/2 connections by specifying an address and tls configuration.
type Dialer struct {
	// Addr is the server's address in the form: `host:port`.
	Addr string

	// TLSConfig is the tls configuration.
	//
	// If TLSConfig is nil, a default one will be defined on the Dial call.
	TLSConfig *tls.Config

	// PingInterval defines the interval in which the client will ping the server.
	//
	// An interval of 0 will make the library to use DefaultPingInterval. Because ping intervals can't be disabled.
	PingInterval time.Duration

	// NetDial defines the callback for establishing new connection to the host.
	// Default Dial is used if not set.
	NetDial fasthttp.DialFunc
}

func (d *Dialer) tryDial() (net.Conn, error) {
	if d.TLSConfig == nil || !func() bool {
		for _, proto := range d.TLSConfig.NextProtos {
			if proto == "h2" {
				return true
			}
		}

		return false
	}() {
		configureDialer(d)
	}

	var c net.Conn
	var err error

	if d.NetDial != nil {
		c, err = d.NetDial(d.Addr)
		if err != nil {
			return nil, err
		}
	} else {
		tcpAddr, err := net.ResolveTCPAddr("tcp", d.Addr)
		if err != nil {
			return nil, err
		}
		c, err = net.DialTCP("tcp", nil, tcpAddr)
		if err != nil {
			return nil, err
		}
	}

	tlsConn := tls.Client(c, d.TLSConfig)

	if err := tlsConn.Handshake(); err != nil {
		_ = c.Close()
		return nil, err
	}

	if tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
		_ = c.Close()
		return nil, ErrServerSupport
	}

	return tlsConn, nil
}

// Dial creates an HTTP/2 connection or returns an error.
//
// An expected error is ErrServerSupport.
func (d *Dialer) Dial(opts ConnOpts) (*Conn, error) {
	c, err := d.tryDial()
	if err != nil {
		return nil, err
	}

	nc := NewConn(c, opts)

	err = nc.Handshake()
	return nc, err
}

// SetOnDisconnect sets the callback that will fire when the HTTP/2 connection is closed.
func (c *Conn) SetOnDisconnect(cb func(*Conn)) {
	c.onDisconnect = cb
}

// LastErr returns the last registered error in case the connection was closed by the server.
func (c *Conn) LastErr() error {
	if p := c.lastErr.Load(); p != nil {
		return *p
	}

	return nil
}

func (c *Conn) setLastErr(err error) {
	c.lastErr.Store(&err)
}

// Handshake will perform the necessary handshake to establish the connection
// with the server. If an error is returned you can assume the TCP connection has been closed.
func (c *Conn) Handshake() error {
	err := c.doHandshake()
	if err == nil {
		go c.writeLoop()
		go c.readLoop()
	}

	return err
}

func (c *Conn) doHandshake() error {
	var err error

	if err = Handshake(true, c.bw, &c.current, c.maxWindow-65535); err != nil {
		_ = c.c.Close()
		return err
	}

	var fr *FrameHeader

	if fr, err = ReadFrameFrom(c.br); err == nil && fr.Type() != FrameSettings {
		_ = c.c.Close()
		return fmt.Errorf("unexpected frame, expected settings, got %s", fr.Type())
	} else if err == nil {
		st := fr.Body().(*Settings)
		if !st.IsAck() {
			st.CopyTo(&c.serverS)
			c.serverMaxStreams.Store(c.serverS.maxStreams)

			c.sendMu.Lock()
			c.serverInitialWindow = int64(c.serverS.MaxWindowSize())
			c.sendMu.Unlock()

			if st.HeaderTableSize() <= defaultHeaderTableSize {
				c.enc.SetMaxTableSize(st.HeaderTableSize())
			}

			// reply back
			fr := AcquireFrameHeader()

			stRes := AcquireFrame(FrameSettings).(*Settings)
			stRes.SetAck(true)

			fr.SetBody(stRes)

			if _, err = fr.WriteTo(c.bw); err == nil {
				err = c.bw.Flush()
			}

			ReleaseFrameHeader(fr)
		}
	}

	if err != nil {
		_ = c.c.Close()
	} else {
		ReleaseFrameHeader(fr)
	}

	return err
}

func (c *Conn) getState() connState {
	return connState(c.state.Load())
}

func (c *Conn) setState(st connState) {
	c.state.Store(int32(st))
}

// CanOpenStream returns whether the client will be able to open a new stream or not.
//
// A connection draining after a server GOAWAY can't open new streams.
func (c *Conn) CanOpenStream() bool {
	return c.getState() == connStateOpen &&
		c.openStreams.Load() < int32(c.serverMaxStreams.Load())
}

// Closed indicates whether the connection is closed or not.
func (c *Conn) Closed() bool {
	return c.closed.Load()
}

// Close closes the connection gracefully, sending a GoAway message
// and then closing the underlying TCP connection.
func (c *Conn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return io.EOF
	}

	close(c.in)
	close(c.closeCh)

	// unblock the body senders waiting for window
	c.sendMu.Lock()
	c.sendCond.Broadcast()
	c.sendMu.Unlock()

	fr := AcquireFrameHeader()
	defer ReleaseFrameHeader(fr)

	ga := AcquireFrame(FrameGoAway).(*GoAway)
	ga.SetStream(0)
	ga.SetCode(NoError)

	fr.SetBody(ga)

	c.bwMu.Lock()
	_, err := fr.WriteTo(c.bw)
	if err == nil {
		err = c.bw.Flush()
	}
	c.bwMu.Unlock()

	_ = c.c.Close()

	if c.onDisconnect != nil {
		c.onDisconnect(c)
	}

	return err
}

// Write queues the request to be sent to the server.
//
// Check if `c` has been previously closed before accessing this function.
func (c *Conn) Write(r *Ctx) {
	c.in <- r
}

var ErrStreamNotReady = errors.New("stream hasn't been created")

// Cancel will try to cancel the request.
//
// Cancel can only return ErrStreamNotReady when the cancel is performed before the stream is created.
func (c *Conn) Cancel(ctx *Ctx) error {
	if ctx.streamID.Load() == 0 {
		return ErrStreamNotReady
	}

	c.cancel(ctx)

	return nil
}

func (c *Conn) cancel(ctx *Ctx) {
	id := ctx.streamID.Load()

	h := AcquireFrameHeader()
	h.SetStream(id)

	fr := AcquireFrame(FrameResetStream).(*RstStream)
	fr.SetCode(StreamCanceled)

	h.SetBody(fr)

	select {
	case c.out <- h:
	case <-c.closeCh:
		ReleaseFrameHeader(h)
	}

	// resolve the request: the server won't reply to the reset stream.
	// A request that already finished makes this a no-op.
	c.finish(ctx, id, ErrRequestCanceled)
}

type WriteError struct {
	err error
}

func (we WriteError) Error() string {
	return fmt.Sprintf("writing error: %s", we.err)
}

func (we WriteError) Unwrap() error {
	return we.err
}

func (we WriteError) Is(target error) bool {
	return errors.Is(we.err, target)
}

func (we WriteError) As(target any) bool {
	return errors.As(we.err, target)
}

func (c *Conn) writeLoop() {
	var lastErr error

	defer func() { _ = c.Close() }()
	// writeRequest (only run here) was the only dispatcher: closing the
	// task channel releases the parked body-sender workers
	defer close(c.bodyTasks)

	defer func() {
		if err := recover(); err != nil {
			if lastErr == nil {
				switch errn := err.(type) {
				case error:
					lastErr = errn
				case string:
					lastErr = errors.New(errn)
				}
			}
		}

		if lastErr == nil {
			lastErr = io.ErrUnexpectedEOF
		}

		c.reqQueued.Range(func(_, v any) bool {
			r := v.(*Ctx)
			c.resolveCtx(r, lastErr)

			return true
		})
	}()

	if c.pingInterval <= 0 {
		c.pingInterval = DefaultPingInterval
	}

	ticker := time.NewTicker(c.pingInterval)
	defer ticker.Stop()

loop:
	for {
		select {
		case ctx, ok := <-c.in: // sending requests
			if !ok {
				break loop
			}

			err := c.writeRequest(ctx)
			if err != nil {
				c.resolveCtx(ctx, err)

				if errors.Is(err, ErrNotAvailableStreams) {
					continue
				}

				lastErr = WriteError{err}

				break loop
			}
		case fr, ok := <-c.out: // generic output
			if !ok {
				break loop
			}

			err := c.writeFrame(fr)
			if err != nil {
				lastErr = WriteError{err}
				break loop
			}

			ReleaseFrameHeader(fr)
		case <-ticker.C: // ping
			if err := c.writePing(); err != nil {
				lastErr = WriteError{err}
				break loop
			}
		}

		if !c.disableAcks && c.unacks.Load() >= 3 {
			lastErr = ErrTimeout
			break loop
		}
	}
}

func (c *Conn) writeFrame(fr *FrameHeader) error {
	c.bwMu.Lock()
	defer c.bwMu.Unlock()

	_, err := fr.WriteTo(c.bw)
	if err == nil {
		if err := c.bw.Flush(); err != nil {
			return err
		}
	}

	return err
}

func (c *Conn) finish(r *Ctx, stream uint32, err error) {
	// the request can finish from the readLoop, its body sender or a
	// cancel: only the first one counts
	if _, ok := c.reqQueued.LoadAndDelete(stream); !ok {
		return
	}

	c.openStreams.Add(-1)

	c.resolveCtx(r, err)
}

// resolveCtx delivers the request's outcome to the caller. While a body
// sender still holds the Request the delivery is deferred to the sender's
// exit: the caller recycles the request as soon as it resolves.
func (c *Conn) resolveCtx(r *Ctx, err error) {
	c.sendMu.Lock()

	if r.bodySending {
		if !r.finishPending {
			r.finishPending = true
			r.finishErr = err
		}

		// wake the sender: the request is gone
		c.sendCond.Broadcast()
		c.sendMu.Unlock()

		return
	}

	c.sendMu.Unlock()

	r.resolve(err)
}

func (c *Conn) readLoop() {
	defer func() { _ = c.Close() }()

	for {
		fr, err := c.readNext()
		if err != nil {
			c.setLastErr(err)
			break
		}

		// TODO: panic otherwise?
		if ri, ok := c.reqQueued.Load(fr.Stream()); ok {
			r := ri.(*Ctx)

			err := c.readStream(fr, r)
			if err == nil {
				if fr.Flags().Has(FlagEndStream) {
					c.finish(r, fr.Stream(), nil)
				}
			} else {
				c.finish(r, fr.Stream(), err)

				// refusals are an expected part of a server shutdown
				if !errors.Is(err, ErrStreamRefused) {
					fmt.Fprintf(os.Stderr, "%s. payload=%v\n", err, fr.payload)
				}

				if errors.Is(err, FlowControlError) {
					break
				}
			}

			if c.getState() == connStateClosed {
				if fr.Stream() == c.closeRef {
					break
				}
			}
		}

		ReleaseFrameHeader(fr)
	}
}

func (c *Conn) writeRequest(ctx *Ctx) error {
	if !c.CanOpenStream() {
		return ErrNotAvailableStreams
	}

	c.bwMu.Lock()
	defer c.bwMu.Unlock()

	req := ctx.Request

	// a streamed body must not go through Body(), which would buffer it
	// whole in memory
	streamedBody := req.IsBodyStream()

	var body []byte
	if !streamedBody {
		body = req.Body()
	}

	hasBody := streamedBody || len(body) != 0

	enc := c.enc

	// apply an HPACK table size a SETTINGS frame changed meanwhile; the
	// writeLoop owns the encoder
	if v := c.encTableSize.Swap(-1); v >= 0 {
		enc.SetMaxTableSize(uint32(v))
	}

	id := c.nextID
	c.nextID += 2

	fr := AcquireFrameHeader()
	defer ReleaseFrameHeader(fr)

	fr.SetStream(id)

	h := AcquireFrame(FrameHeaders).(*Headers)
	fr.SetBody(h)

	hf := AcquireHeaderField()

	hf.SetBytes(StringAuthority, req.URI().Host())
	enc.AppendHeaderField(h, hf, true)

	hf.SetBytes(StringMethod, req.Header.Method())
	enc.AppendHeaderField(h, hf, true)

	hf.SetBytes(StringPath, req.URI().RequestURI())
	enc.AppendHeaderField(h, hf, true)

	hf.SetBytes(StringScheme, req.URI().Scheme())
	enc.AppendHeaderField(h, hf, true)

	hf.SetBytes(StringUserAgent, req.Header.UserAgent())
	enc.AppendHeaderField(h, hf, true)

	for k, v := range req.Header.All() {
		if bytes.EqualFold(k, StringUserAgent) {
			continue
		}

		// connection-specific fields are forbidden in HTTP/2 (RFC 9113,
		// section 8.2.2); fasthttp adds Transfer-Encoding to requests
		// with a body of unknown length
		if isConnectionSpecificField(k) {
			continue
		}

		hf.SetBytes(k, v)
		ToLower(hf.KeyBytes())
		enc.AppendHeaderField(h, hf, false)
	}

	h.SetPadding(false)
	h.SetEndStream(!hasBody)
	h.SetEndHeaders(true)

	// store the ctx before sending the request
	ctx.streamID.Store(id)
	c.reqQueued.Store(id, ctx)

	_, err := fr.WriteTo(c.bw)
	if err == nil && hasBody {
		if !streamedBody && c.tryReserveSendWindow(ctx, int64(len(body))) {
			// fast path: the whole buffered body fits the server's
			// flow-control windows right now, write it inline

			// release headers bc it's going to get replaced by the data frame
			ReleaseFrame(h)

			err = writeData(c.bw, fr, body)
		} else {
			// the body goes out through its own goroutine, paced by the
			// server's flow-control windows; DATA frames travel through
			// c.out, so other requests aren't blocked behind this one.
			// While the sender runs it owns the Request: resolutions
			// hold until it exits.
			c.sendMu.Lock()
			ctx.bodySending = true
			c.sendMu.Unlock()

			// hand the body to a parked worker; only when none is idle
			// does a new one spawn (a bounded pool would stall uploads
			// behind windows the server opens at its own pace)
			select {
			case c.bodyTasks <- bodyTask{ctx: ctx, id: id}:
			default:
				go c.bodySenderWorker(bodyTask{ctx: ctx, id: id})
			}
		}
	}

	if err == nil {
		err = c.bw.Flush()
		if err == nil {
			c.openStreams.Add(1)
		}
	}

	if err != nil {
		c.setLastErr(err)
		// if we had any error, remove it from the reqQueued.
		c.reqQueued.Delete(id)
	}

	ReleaseHeaderField(hf)

	return err
}

func writeData(bw *bufio.Writer, fh *FrameHeader, body []byte) (err error) {
	step := 1 << 14

	data := AcquireFrame(FrameData).(*Data)
	fh.SetBody(data)

	for i := 0; err == nil && i < len(body); i += step {
		if i+step >= len(body) {
			step = len(body) - i
		}

		data.SetEndStream(i+step == len(body))
		data.SetPadding(false)
		data.SetDataNoCopy(body[i : step+i])

		_, err = fh.WriteTo(bw)
	}

	return err
}

// connectionSpecificFields are forbidden in HTTP/2 (RFC 9113, section
// 8.2.2): connection-level semantics travel in frames instead.
var connectionSpecificFields = [][]byte{
	[]byte("connection"),
	[]byte("transfer-encoding"),
	[]byte("keep-alive"),
	[]byte("proxy-connection"),
	[]byte("upgrade"),
}

func isConnectionSpecificField(k []byte) bool {
	for _, f := range connectionSpecificFields {
		if bytes.EqualFold(k, f) {
			return true
		}
	}

	return false
}

// tryReserveSendWindow reserves n bytes from the connection and stream
// send windows if both fit right now, so small buffered bodies skip the
// sender goroutine.
func (c *Conn) tryReserveSendWindow(ctx *Ctx, n int64) bool {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	if c.serverWindow < n || c.serverInitialWindow+ctx.sendWindow < n {
		return false
	}

	c.serverWindow -= n
	ctx.sendWindow -= n

	return true
}

// waitSendWindow reserves up to want bytes from the connection and stream
// send windows, blocking until some window opens. It returns a negative
// value when the request or the connection ended while waiting.
func (c *Conn) waitSendWindow(ctx *Ctx, id uint32, want int64) int64 {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	for {
		if c.Closed() {
			return -1
		}

		if _, ok := c.reqQueued.Load(id); !ok {
			return -1
		}

		grant := want
		if c.serverWindow < grant {
			grant = c.serverWindow
		}
		if win := c.serverInitialWindow + ctx.sendWindow; win < grant {
			grant = win
		}

		if grant > 0 {
			c.serverWindow -= grant
			ctx.sendWindow -= grant

			return grant
		}

		c.sendCond.Wait()
	}
}

// refundSendWindow gives back the reserved bytes a body read didn't use.
func (c *Conn) refundSendWindow(ctx *Ctx, n int64) {
	c.sendMu.Lock()
	c.serverWindow += n
	ctx.sendWindow += n
	c.sendCond.Broadcast()
	c.sendMu.Unlock()
}

// abortRequestBody resets a stream whose request body won't be completed,
// so the server doesn't wait on it.
func (c *Conn) abortRequestBody(id uint32) {
	if c.Closed() {
		return
	}

	fr := AcquireFrameHeader()
	fr.SetStream(id)

	rst := AcquireFrame(FrameResetStream).(*RstStream)
	rst.SetCode(NoError)
	fr.SetBody(rst)

	select {
	case c.out <- fr:
	case <-c.closeCh:
		ReleaseFrameHeader(fr)
	}
}

// bodyTask is a queued request-body upload: the request's ctx and its
// stream ID.
type bodyTask struct {
	ctx *Ctx
	id  uint32
}

// bodySenderWorker runs queued body uploads, then parks on bodyTasks to be
// reused by the next one; it exits after sitting idle for
// handlerWorkerIdleTime or when the connection tears down.
func (c *Conn) bodySenderWorker(t bodyTask) {
	idle := time.NewTimer(handlerWorkerIdleTime)
	defer idle.Stop()

	for {
		c.sendRequestBody(t.ctx, t.id)

		idle.Reset(handlerWorkerIdleTime)

		var ok bool
		select {
		case t, ok = <-c.bodyTasks:
			if !ok {
				return
			}
		case <-idle.C:
			return
		}
	}
}

// sendRequestBody streams a request body on a body-sender worker, paced by
// the server's flow-control windows. The DATA frames travel through c.out,
// so control frames and other requests keep flowing while this body waits
// for window; the last frame carries END_STREAM. When the request finishes
// early (a response before the upload ended) the rest of the body is
// dropped and the stream reset.
func (c *Conn) sendRequestBody(ctx *Ctx, id uint32) {
	// the sender owns ctx.Request until it exits: deliver the resolution
	// that arrived in the meantime only after letting go
	defer func() {
		c.sendMu.Lock()
		ctx.bodySending = false
		pending, err := ctx.finishPending, ctx.finishErr
		c.sendMu.Unlock()

		if pending {
			ctx.resolve(err)
		}
	}()

	var (
		body   []byte
		reader io.Reader
		// size is what remains of a declared body length, negative when
		// unknown
		size int64 = -1
	)

	req := ctx.Request
	if req.IsBodyStream() {
		reader = req.BodyStream()
		size = int64(req.Header.ContentLength())
	} else {
		body = req.Body()
	}

	var buf []byte
	if reader != nil {
		buf = copyBufPool.Get().([]byte)
		defer copyBufPool.Put(buf) //nolint:staticcheck // buf is never resliced
	}

	for {
		want := int64(1 << 14) // max frame size 16384
		if reader == nil {
			if int64(len(body)) < want {
				want = int64(len(body))
			}
		} else if size >= 0 && size < want {
			want = size
		}

		var grant int64
		if want > 0 {
			grant = c.waitSendWindow(ctx, id, want)
			if grant < 0 {
				// the request already ended (an early response, a
				// cancel or the connection going away): the server
				// must not keep waiting for the body
				c.abortRequestBody(id)
				return
			}
		}

		var chunk []byte
		last := false

		if reader == nil {
			chunk = body[:grant]
			body = body[grant:]
			last = len(body) == 0
		} else {
			var n int
			var err error

			if grant > 0 {
				n, err = reader.Read(buf[:grant])
			}

			chunk = buf[:n]

			if size > 0 {
				size -= int64(n)
			}

			// give back what the read didn't use
			if unused := grant - int64(n); unused > 0 {
				c.refundSendWindow(ctx, unused)
			}

			if err != nil && !errors.Is(err, io.EOF) {
				// the body source failed: the server must not take the
				// upload as complete, and the caller must know
				c.abortRequestBody(id)
				c.finish(ctx, id, err)

				return
			}

			// EOF, a stalled reader or a sent-out declared size all end
			// the body
			last = err != nil || n == 0 || size == 0
		}

		fr := AcquireFrameHeader()
		fr.SetStream(id)

		data := AcquireFrame(FrameData).(*Data)
		data.SetEndStream(last)
		data.SetPadding(false)
		data.SetData(chunk)

		fr.SetBody(data)

		select {
		case c.out <- fr:
		case <-c.closeCh:
			ReleaseFrameHeader(fr)
			return
		}

		if last {
			return
		}
	}
}

func (c *Conn) readNext() (fr *FrameHeader, err error) {
loop:
	for err == nil {
		fr, err = ReadFrameFrom(c.br)
		if err != nil {
			break
		}

		if fr.Stream() != 0 {
			break
		}

		switch fr.Type() {
		case FrameSettings:
			st := fr.Body().(*Settings)
			if !st.IsAck() { // if it has ack, just ignore
				c.handleSettings(st)
			}
		case FrameWindowUpdate:
			win := int64(fr.Body().(*WindowUpdate).Increment())

			c.sendMu.Lock()
			c.serverWindow += win
			c.sendCond.Broadcast()
			c.sendMu.Unlock()
		case FramePing:
			ping := fr.Body().(*Ping)
			if !ping.IsAck() {
				c.handlePing(ping)
			} else {
				c.unacks.Add(-1)
			}
		case FrameGoAway:
			ga := fr.Body().(*GoAway)
			if ga.stream == 0 {
				_ = c.c.Close()
				err = ga
			} else {
				// the server is shutting down (RFC 9113, section 6.8):
				// stop opening new streams on this connection, but keep
				// reading so the streams up to closeRef complete. A GOAWAY
				// with the highest possible stream ID is the shutdown
				// warning; the definitive one lowers closeRef afterwards.
				c.closeRef = ga.stream
				c.setState(connStateClosed)
			}

			break loop
		}

		ReleaseFrameHeader(fr)
	}

	return
}

var ErrTimeout = errors.New("server is not replying to pings")

func (c *Conn) writePing() error {
	fr := AcquireFrameHeader()
	defer ReleaseFrameHeader(fr)

	ping := AcquireFrame(FramePing).(*Ping)
	ping.SetCurrentTime()

	fr.SetBody(ping)

	c.bwMu.Lock()
	defer c.bwMu.Unlock()

	_, err := fr.WriteTo(c.bw)
	if err == nil {
		err = c.bw.Flush()
		if err == nil {
			c.unacks.Add(1)
		}
	}

	return err
}

func (c *Conn) handleSettings(st *Settings) {
	st.CopyTo(&c.serverS)
	c.serverMaxStreams.Store(c.serverS.maxStreams)

	// a changed INITIAL_WINDOW_SIZE applies to every stream, the open
	// ones retroactively (RFC 9113, section 6.9.2): the send windows
	// derive from this base
	c.sendMu.Lock()
	c.serverInitialWindow = int64(c.serverS.MaxWindowSize())
	c.sendCond.Broadcast()
	c.sendMu.Unlock()

	// the HPACK encoder belongs to the writeLoop: park the new table
	// size for it instead of racing the request encoding
	c.encTableSize.Store(int64(st.HeaderTableSize()))

	// reply back
	fr := AcquireFrameHeader()

	stRes := AcquireFrame(FrameSettings).(*Settings)
	stRes.SetAck(true)

	fr.SetBody(stRes)

	c.out <- fr
}

func (c *Conn) handlePing(ping *Ping) {
	// reply back
	fr := AcquireFrameHeader()

	pong := AcquireFrame(FramePing).(*Ping)
	pong.SetAck(true)
	pong.SetData(ping.Data())

	fr.SetBody(pong)

	select {
	case c.out <- fr:
	default:
		ReleaseFrameHeader(fr)
	}
}

// ErrStreamRefused is returned for requests whose stream the server reset
// with REFUSED_STREAM: the request was not processed at all, so it's safe
// to retry it even if it's not idempotent (RFC 9113, section 8.7).
var ErrStreamRefused = errors.New("stream refused by the server")

func (c *Conn) readStream(fr *FrameHeader, ctx *Ctx) (err error) {
	res := ctx.Response

	switch fr.Type() {
	case FrameHeaders, FrameContinuation:
		h := fr.Body().(FrameWithHeaders)
		err = c.readHeader(h.Headers(), res)
	case FrameResetStream:
		rst := fr.Body().(*RstStream)
		if rst.Code() == RefusedStreamError {
			err = ErrStreamRefused
		} else {
			err = NewResetStreamError(rst.Code(), "stream reset by the server")
		}
	case FrameWindowUpdate:
		// the server opened the stream's send window: wake the request's
		// body sender
		c.sendMu.Lock()
		ctx.sendWindow += int64(fr.Body().(*WindowUpdate).Increment())
		c.sendCond.Broadcast()
		c.sendMu.Unlock()
	case FrameData:
		c.currentWindow -= int32(fr.Len())
		currentWin := c.currentWindow

		data := fr.Body().(*Data)
		if data.Len() != 0 {
			res.AppendBody(data.Data())

			// replenish the stream window, unless this frame just
			// ended the stream
			if !fr.Flags().Has(FlagEndStream) {
				c.updateWindow(fr.Stream(), fr.Len())
			}
		}

		if currentWin < c.maxWindow/2 {
			nValue := c.maxWindow - currentWin

			c.currentWindow = c.maxWindow

			c.updateWindow(0, int(nValue))
		}
	}

	return
}

func (c *Conn) updateWindow(streamID uint32, size int) {
	fr := AcquireFrameHeader()

	fr.SetStream(streamID)

	wu := AcquireFrame(FrameWindowUpdate).(*WindowUpdate)
	wu.SetIncrement(size)

	fr.SetBody(wu)

	c.out <- fr
}

func (c *Conn) readHeader(b []byte, res *fasthttp.Response) error {
	var err error
	hf := AcquireHeaderField()
	defer ReleaseHeaderField(hf)

	dec := c.dec

	for len(b) > 0 {
		b, err = dec.Next(hf, b)
		if err != nil {
			return err
		}

		if hf.IsPseudo() {
			if hf.KeyBytes()[1] == 's' { // status
				n, err := fasthttp.ParseUint(hf.ValueBytes())
				if err != nil {
					return err
				}

				res.SetStatusCode(n)
				continue
			}
		}

		if bytes.Equal(hf.KeyBytes(), StringContentLength) {
			n, _ := fasthttp.ParseUint(hf.ValueBytes())
			res.Header.SetContentLength(n)
		} else {
			res.Header.AddBytesKV(hf.KeyBytes(), hf.ValueBytes())
		}
	}

	return nil
}
