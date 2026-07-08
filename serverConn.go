package http2

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"runtime/debug"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/valyala/fasthttp"
)

// ratelim is a token-bucket rate limiter used for rapid-reset detection
// (RFC 9113 §10.6). Constants match nghttp2's defaults.
//
//	burst = 1000 — tokens available at connection open; allows legitimate
//	               bursts (browser prefetch cancellations, etc.)
//	rate  = 33   — tokens regenerated per second; sustained attack rate
//	               above 33 RST_STREAMs/sec triggers the defense
type ratelim struct {
	val  int64 // current token count
	last int64 // last refill timestamp (Unix seconds)
}

const (
	ratelimBurst = 1000
	ratelimRate  = 33
)

func newRatelim() ratelim {
	return ratelim{
		val:  ratelimBurst,
		last: time.Now().Unix(),
	}
}

// allow drains one token. Returns false (bucket exhausted) when the caller
// should close the connection with ENHANCE_YOUR_CALM.
func (r *ratelim) allow() bool {
	now := time.Now().Unix()
	if elapsed := now - r.last; elapsed > 0 {
		r.val = min(r.val+elapsed*ratelimRate, ratelimBurst)
		r.last = now
	}

	if r.val <= 0 {
		return false
	}

	r.val--

	return true
}

type connState int32

const (
	connStateOpen connState = iota
	connStateClosed
	// connStateDraining is the RFC 9113 (section 6.8) shutdown warning
	// phase: a GOAWAY with the highest possible stream ID has been sent,
	// but new streams are still accepted until the grace period ends and
	// the definitive GOAWAY is sent.
	connStateDraining
)

type serverConn struct {
	c net.Conn
	h fasthttp.RequestHandler

	br *bufio.Reader
	bw *bufio.Writer

	enc HPACK
	dec HPACK

	// last valid ID used as a reference for new IDs
	lastID uint32

	// clientWindow is the connection-level send window: what the peer
	// can still receive. It starts at 65535 (RFC 9113, section 6.9.2:
	// INITIAL_WINDOW_SIZE never changes the connection window), grows
	// with the peer's WINDOW_UPDATEs and shrinks with the DATA sent.
	// int64 because the user can try to overflow it.
	clientWindow atomic.Int64
	// clientInitialWindow is the peer's SETTINGS_INITIAL_WINDOW_SIZE:
	// the base of every stream's send window (see Stream.window)
	clientInitialWindow atomic.Int64
	// encTableSize carries a pending HPACK table size from the peer's
	// SETTINGS (read on the readLoop) to the goroutine that owns the
	// encoder; negative means nothing pending
	encTableSize atomic.Int64
	// windowPoke wakes handleStreams when the connection window or the
	// peer's INITIAL_WINDOW_SIZE moved, so stalled responses get retried
	windowPoke chan struct{}

	// our values
	maxWindow     int32
	currentWindow int32

	writer chan *FrameHeader
	reader chan *FrameHeader

	state atomic.Int32
	// closeRef stores the last stream that was valid before sending a GOAWAY.
	// Thus, the number stored in closeRef is used to complete all the requests that were sent before
	// to gracefully close the connection with a GOAWAY.
	closeRef atomic.Uint32

	// maxRequestTime is the max time of a request over one single stream
	maxRequestTime time.Duration
	pingInterval   time.Duration
	// maxIdleTime is the max time a client can be connected without sending any REQUEST.
	// As highlighted, PING/PONG frames are completely excluded.
	//
	// Therefore, a client that didn't send a request for more than `maxIdleTime` will see it's connection closed.
	maxIdleTime time.Duration

	// writeTimeout mirrors fasthttp.Server.WriteTimeout: the deadline a
	// single write into the connection gets before the connection is
	// considered stalled and closed
	writeTimeout time.Duration

	// streamRequestBody mirrors fasthttp.Server.StreamRequestBody: the
	// handler starts as soon as the request headers are complete and
	// reads the body from a bounded pipe while its DATA frames are still
	// in flight
	streamRequestBody bool
	// handlerDone returns the streams whose dispatched handler finished,
	// so the frame loop writes the response with its single-goroutine
	// HPACK encoder. Buffered to the stream limit: handlers never block
	// on it, even when the frame loop is already gone.
	handlerDone chan *Stream
	// handlerTasks hands dispatched streams to an idle handler worker
	// (see dispatchStream), so sequential streamed requests reuse a
	// goroutine instead of spawning one each. Unbuffered: a send only
	// succeeds when a worker is already parked waiting for work.
	handlerTasks chan *Stream

	// maxRequestBodySize limits how much of a request body is buffered,
	// mirroring fasthttp.Server.MaxRequestBodySize
	maxRequestBodySize int
	// maxHeaderListSize limits the decoded size of a request's header
	// list, mirroring the header size limit fasthttp derives from
	// Server.ReadBufferSize. It is advertised as
	// SETTINGS_MAX_HEADER_LIST_SIZE.
	maxHeaderListSize int
	// errorHandler mirrors fasthttp.Server.ErrorHandler for the errors
	// the HTTP/2 server generates itself (fasthttp.ErrBodyTooLarge)
	errorHandler func(*fasthttp.RequestCtx, error)

	st      Settings
	clientS Settings

	// pingTimer
	pingTimer       *time.Timer
	maxRequestTimer *time.Timer
	maxIdleTimer    *time.Timer

	closer chan struct{}

	// shutdown is closed to start a graceful shutdown of the connection:
	// a warning GOAWAY is sent and, once the shutdown PING is acked or
	// shutdownGracePeriod expires, the definitive GOAWAY; the connection
	// closes once the accepted streams have been served.
	shutdown     chan struct{}
	shutdownOnce sync.Once
	// shutdownGracePeriod is the longest the connection keeps accepting
	// new streams between the two shutdown GOAWAYs; the ack of the
	// shutdown PING ends the wait earlier. If <= 0 the definitive GOAWAY
	// is sent right away.
	shutdownGracePeriod time.Duration
	// pingAck receives a token when the client acks the shutdown PING
	pingAck chan struct{}

	debug  bool
	logger fasthttp.Logger
}

func (sc *serverConn) getState() connState {
	return connState(sc.state.Load())
}

func (sc *serverConn) setState(st connState) {
	sc.state.Store(int32(st))
}

// gracefulShutdown signals the connection to send a GOAWAY, serve the
// streams accepted so far and then close. It's safe to call it multiple
// times and from any goroutine.
func (sc *serverConn) gracefulShutdown() {
	sc.shutdownOnce.Do(func() {
		close(sc.shutdown)
	})
}

func (sc *serverConn) closeIdleConn() {
	if !sc.tryWriteFrame(sc.newGoAwayFrame(0, NoError, "connection has been idle for a long time")) {
		_ = sc.c.Close()
	}
	sc.setState(connStateClosed)

	if sc.debug {
		sc.logger.Printf("Connection is idle. Closing\n")
	}
	close(sc.closer)
}

func (sc *serverConn) Handshake() error {
	return Handshake(false, sc.bw, &sc.st, sc.maxWindow)
}

func (sc *serverConn) Serve() error {
	sc.closer = make(chan struct{}, 1)
	sc.maxRequestTimer = time.NewTimer(0)
	sc.clientWindow.Store(65535)
	sc.clientInitialWindow.Store(65535)
	sc.encTableSize.Store(-1)
	sc.windowPoke = make(chan struct{}, 1)
	sc.handlerDone = make(chan *Stream, sc.st.maxStreams)
	sc.handlerTasks = make(chan *Stream)

	// create the timer before spawning the writeLoop and readLoop
	// goroutines: they and the timer callback read sc.pingTimer, so a
	// later assignment would be a data race
	if sc.pingInterval > 0 {
		sc.pingTimer = time.AfterFunc(sc.pingInterval, sc.sendPingAndSchedule)
	}

	if sc.maxIdleTime > 0 {
		sc.maxIdleTimer = time.AfterFunc(sc.maxIdleTime, sc.closeIdleConn)
	}

	defer func() {
		if err := recover(); err != nil {
			sc.logger.Printf("Serve panicked: %s:\n%s\n", err, debug.Stack())
		}
	}()

	go func() {
		// defer closing the connection in the writeLoop in case the writeLoop panics
		defer func() {
			_ = sc.c.Close()
		}()

		sc.writeLoop()
	}()

	go func() {
		sc.handleStreams()
		// Fix #55: The pingTimer fired while we were closing the connection.
		if sc.pingTimer != nil {
			sc.pingTimer.Stop()
		}
		// close the writer here to ensure that no pending requests
		// are writing to a closed channel
		close(sc.writer)
		// handleStreams was the only dispatcher: closing the task channel
		// releases the parked handler workers
		close(sc.handlerTasks)
	}()

	defer func() {
		// close the reader here so we can stop handling stream updates
		close(sc.reader)
	}()

	var err error

	// unset any deadline
	if err = sc.c.SetWriteDeadline(time.Time{}); err == nil {
		err = sc.c.SetReadDeadline(time.Time{})
	}
	if err != nil {
		return err
	}

	err = sc.readLoop()
	if errors.Is(err, io.EOF) {
		err = nil
	}

	sc.close()

	return err
}

func (sc *serverConn) close() {
	if sc.pingTimer != nil {
		sc.pingTimer.Stop()
	}

	if sc.maxIdleTimer != nil {
		sc.maxIdleTimer.Stop()
	}

	sc.maxRequestTimer.Stop()
}

// closeConnSentinel makes the writeLoop flush the frames written so far and
// close the connection. It lets handleStreams end the connection without
// closing sc.writer while the readLoop might still be writing to it: closing
// the connection ends the readLoop, and the regular teardown follows.
var closeConnSentinel = &FrameHeader{}

func (sc *serverConn) writeFrame(fr *FrameHeader) {
	defer func() {
		if err := recover(); err != nil {
			sc.logger.Printf("Serve panicked: %s:\n%s\n", err, debug.Stack())
		}
	}()

	sc.writer <- fr
}

// tryWriteFrame queues fr without blocking and reports whether it fit.
// The writer queue only fills up while the writeLoop is stalled on a client
// that stopped reading (without a WriteTimeout that write never returns):
// the paths that must keep making progress behind such a client — PING acks
// on the readLoop and the connection teardown — use this instead of
// writeFrame so the stall can't spread to them.
func (sc *serverConn) tryWriteFrame(fr *FrameHeader) (ok bool) {
	defer func() {
		if err := recover(); err != nil {
			sc.logger.Printf("Serve panicked: %s:\n%s\n", err, debug.Stack())
		}
	}()

	select {
	case sc.writer <- fr:
		return true
	default:
		if fr != closeConnSentinel {
			ReleaseFrameHeader(fr)
		}

		return false
	}
}

func (sc *serverConn) handlePing(ping *Ping) {
	fr := AcquireFrameHeader()

	pong := AcquireFrame(FramePing).(*Ping)
	pong.SetAck(true)
	pong.SetData(ping.Data())

	fr.SetBody(pong)

	_ = sc.tryWriteFrame(fr)
}

func (sc *serverConn) writePing() {
	fr := AcquireFrameHeader()

	ping := AcquireFrame(FramePing).(*Ping)
	ping.SetCurrentTime()

	fr.SetBody(ping)

	sc.writeFrame(fr)
}

// shutdownPingData marks the PING sent along the shutdown warning GOAWAY,
// so that its ack can be told apart from the keepalive PING acks.
var shutdownPingData = [8]byte{'s', 'h', 'u', 't', 'd', 'o', 'w', 'n'}

// writeShutdownPing sends the PING that follows the shutdown warning
// GOAWAY: receiving its ack proves the client processed the GOAWAY,
// completing the round trip RFC 9113 (section 6.8) asks to wait for.
func (sc *serverConn) writeShutdownPing() {
	fr := AcquireFrameHeader()

	ping := AcquireFrame(FramePing).(*Ping)
	ping.SetData(shutdownPingData[:])

	fr.SetBody(ping)

	sc.writeFrame(fr)
}

func (sc *serverConn) checkFrameWithStream(fr *FrameHeader) error {
	if fr.Stream()&1 == 0 {
		return NewGoAwayError(ProtocolError, "invalid stream id")
	}

	switch fr.Type() {
	case FramePing:
		return NewGoAwayError(ProtocolError, "ping is carrying a stream id")
	case FramePushPromise:
		return NewGoAwayError(ProtocolError, "clients can't send push_promise frames")
	}

	return nil
}

// fatalConnError reports a connection error (RFC 9113, section 5.4.1):
// the GOAWAY carrying the code is queued, the writeLoop flushes it and
// closes the connection, and the incoming bytes are drained until the
// connection dies so the teardown can't cut the GOAWAY short.
func (sc *serverConn) fatalConnError(code ErrorCode, message string) {
	sc.setState(connStateClosed)

	if !sc.tryWriteFrame(sc.newGoAwayFrame(0, code, message)) ||
		!sc.tryWriteFrame(closeConnSentinel) {
		_ = sc.c.Close()
	}

	_, _ = io.Copy(io.Discard, sc.br)
}

func (sc *serverConn) readLoop() (err error) {
	defer func() {
		if err := recover(); err != nil {
			sc.logger.Printf("readLoop panicked: %s\n%s\n", err, debug.Stack())
		}
	}()

	var fr *FrameHeader

	// non-zero while a header block awaits its CONTINUATION frames: a
	// header block must be a contiguous run of HEADERS/CONTINUATION frames
	// (RFC 9113, section 4.3)
	var headerBlockStream uint32

	pingLim := newRatelim() // PING flood token bucket

	for err == nil {
		fr, err = ReadFrameFromWithSize(sc.br, sc.clientS.frameSize)
		if err != nil {
			if errors.Is(err, ErrUnknownFrameType) {
				// RFC 9113 (section 4.1): frames of unknown type MUST be
				// ignored and discarded (the reader already discarded the
				// payload, keeping the stream aligned), unless one arrives
				// in the middle of a header block, which breaks the
				// required contiguity (section 4.3)
				if headerBlockStream != 0 {
					err = NewGoAwayError(ProtocolError, "unknown frame in the middle of a header block")
					break
				}

				err = nil
				continue
			}

			break
		}

		if fr.Stream() != 0 {
			if cerr := sc.checkFrameWithStream(fr); cerr != nil {
				ReleaseFrameHeader(fr)
				err = cerr
				break
			}

			// a CONTINUATION frame is only valid while a header block is
			// open on that same stream (RFC 9113, section 6.10); without
			// this check the fragment would bypass the HPACK decoder and
			// desynchronize the tables
			if fr.Type() == FrameContinuation && headerBlockStream != fr.Stream() {
				ReleaseFrameHeader(fr)
				err = NewGoAwayError(ProtocolError, "CONTINUATION without a preceding HEADERS")
				break
			}

			// track header-block continuity for the unknown-frame check
			if t := fr.Type(); t == FrameHeaders || t == FrameContinuation {
				if fr.Flags().Has(FlagEndHeaders) {
					headerBlockStream = 0
				} else {
					headerBlockStream = fr.Stream()
				}
			}

			sc.reader <- fr

			continue
		}

		// handle 'anonymous' frames (frames without stream_id)
		switch fr.Type() {
		case FrameSettings:
			st := fr.Body().(*Settings)
			if !st.IsAck() { // if it has ack, just ignore
				sc.handleSettings(st)
			}
		case FrameWindowUpdate:
			win := int64(fr.Body().(*WindowUpdate).Increment())
			if win == 0 {
				err = NewGoAwayError(ProtocolError, "window increment of 0")
			} else if sc.clientWindow.Add(win) >= 1<<31-1 {
				err = NewGoAwayError(FlowControlError, "window is above limits")
			} else {
				// the connection window grew: retry stalled responses
				sc.pokeWindows()
			}
		case FramePing:
			ping := fr.Body().(*Ping)
			if !ping.IsAck() {
				if !pingLim.allow() {
					err = NewGoAwayError(EnhanceYourCalm, "ping flood detected")
				} else {
					sc.handlePing(ping)
				}
			} else if bytes.Equal(ping.Data(), shutdownPingData[:]) {
				select {
				case sc.pingAck <- struct{}{}:
				default:
				}
			}
		case FrameGoAway:
			ga := fr.Body().(*GoAway)
			if ga.Code() == NoError {
				err = io.EOF
			} else {
				err = fmt.Errorf("goaway: %s: %s", ga.Code(), ga.Data())
			}
		default:
			err = NewGoAwayError(ProtocolError, "invalid frame")
		}

		ReleaseFrameHeader(fr)
	}

	// connection errors carry an error code: announce it with a GOAWAY
	// and make sure the connection closes (RFC 9113, section 5.4.1)
	connErr := Error{}
	if errors.As(err, &connErr) {
		sc.fatalConnError(connErr.Code(), connErr.Error())
	}

	return
}

// handleStreams handles everything related to the streams
// and the HPACK table is accessed synchronously.
func (sc *serverConn) handleStreams() {
	defer func() {
		if err := recover(); err != nil {
			sc.logger.Printf("handleStreams panicked: %s\n%s\n", err, debug.Stack())
		}
	}()

	var strms Streams
	var reqTimerArmed bool
	var openStreams int

	rstLim := newRatelim() // rapid-reset token bucket

	// closedStrms remembers the streams that already ended; the value
	// records whether the server reset them, in which case frames the
	// client sent before learning about the reset are ignored instead of
	// being a connection error
	closedStrms := make(map[uint32]bool)

	// closedBelow is the pruning watermark for closedStrms: stream IDs are
	// monotonic, so once the map doubles maxClosedStrms the older half is
	// dropped and IDs below the watermark that aren't alive are known to
	// be long closed.
	var closedBelow uint32

	const maxClosedStrms = 512

	rememberClosed := func(strmID uint32, resetByServer bool) {
		closedStrms[strmID] = resetByServer

		if len(closedStrms) < maxClosedStrms*2 {
			return
		}

		ids := make([]uint32, 0, len(closedStrms))
		for id := range closedStrms {
			ids = append(ids, id)
		}
		slices.Sort(ids)

		ids = ids[:len(ids)-maxClosedStrms]
		for _, id := range ids {
			delete(closedStrms, id)
		}

		if watermark := ids[len(ids)-1] + 1; watermark > closedBelow {
			closedBelow = watermark
		}
	}

	closeStream := func(strm *Stream) {
		if strm.origType == FrameHeaders {
			openStreams--
		}

		strmID := strm.ID()

		rememberClosed(strm.ID(), strm.resetByServer)
		strms.Del(strm.ID())

		if strm.sending {
			// the response was cut short (a reset or the teardown):
			// drop what's pending and release a body stream's blocked
			// producer, if any
			strm.sending = false
			strm.sendBody = nil
			strm.sendReader = nil

			if strm.ctx.Response.IsBodyStream() {
				_ = strm.ctx.Response.CloseBodyStream()
			}
		}

		if strm.dispatched {
			// the handler is still running and owns the ctx: end its
			// body pipe and let the handlerDone case do the recycling
			strm.body.closeWithError(io.ErrUnexpectedEOF)
		} else {
			releaseStreamBody(strm)
			ctxPool.Put(strm.ctx)
			streamPool.Put(strm)
		}

		if sc.debug {
			sc.logger.Printf("Stream destroyed %d. Open streams: %d\n", strmID, openStreams)
		}
	}

	// finishResponse pumps a queued response as far as the peer's windows
	// allow and, once it has been fully queued, finishes the stream: the
	// deferred reset of early responses, then the close that recycles it.
	// A stalled response leaves the stream alive until the peer opens its
	// windows again.
	finishResponse := func(strm *Stream) {
		if !sc.pumpSend(strm) {
			return
		}

		if strm.afterSendReset {
			strm.resetByServer = true
			sc.writeReset(strm.ID(), NoError)
		}

		strm.SetState(StreamStateClosed)
		closeStream(strm)
	}

	// the body pipes of the handlers still running when the connection
	// goes away must be ended, so their reads don't stay blocked forever;
	// same for the producer of a stalled streamed response. The streams
	// themselves are reclaimed by the GC, since nobody consumes
	// handlerDone anymore.
	defer func() {
		for _, strm := range strms {
			if strm.dispatched {
				strm.body.closeWithError(io.ErrUnexpectedEOF)
			}

			if strm.sending && strm.ctx.Response.IsBodyStream() {
				_ = strm.ctx.Response.CloseBodyStream()
			}
		}
	}()

	// receiving on a nil channel blocks forever, so disabling a case
	// after its first (and only) receive is enough
	shutdownCh := sc.shutdown
	closerCh := sc.closer

	// graceTimer delays the definitive shutdown GOAWAY to give in-flight
	// requests the chance to still be accepted (RFC 9113, section 6.8)
	var graceTimer *time.Timer
	var graceTimerC <-chan time.Time

	defer func() {
		if graceTimer != nil {
			graceTimer.Stop()
		}
	}()

	// finalShutdown sends the definitive GOAWAY and, if all accepted
	// streams have been served already, closes the connection. Otherwise
	// the remaining streams are drained by the regular frame handling
	// (the isClosing path).
	finalShutdown := func() {
		// an error GOAWAY might have been sent in the meantime; don't
		// override its code, and don't raise the advertised last stream ID
		if sc.getState() != connStateClosed {
			sc.writeGoAway(sc.lastID, NoError, "graceful shutdown")
		}

		for _, strm := range strms {
			if strm.origType == FrameHeaders && strm.ID() <= sc.lastID {
				return
			}
		}

		sc.writeFrame(closeConnSentinel)
	}

	// maybeCloseAfterShutdown closes the connection while it's draining
	// (a closing GOAWAY has been sent) once every stream accepted before
	// the GOAWAY has been served.
	maybeCloseAfterShutdown := func() {
		ref := sc.closeRef.Load()
		if ref == 0 {
			return
		}

		for _, strm := range strms {
			// if the stream is here, then it's not closed yet
			if strm.origType == FrameHeaders && strm.ID() <= ref {
				return
			}
		}

		// all streams served: flush what's pending and close the
		// connection; readLoop then ends and the regular teardown
		// closes this loop through sc.reader
		sc.writeFrame(closeConnSentinel)
	}

loop:
	for {
		select {
		case strm := <-sc.handlerDone:
			strm.dispatched = false

			if strm.State() == StreamStateClosed {
				// the stream ended while the handler was running:
				// closeStream already did the accounting and ended the
				// body pipe, only the recycling waited for the handler
				// to let go of the ctx
				releaseStreamBody(strm)
				ctxPool.Put(strm.ctx)
				streamPool.Put(strm)

				continue loop
			}

			// nothing consumes the body anymore
			strm.body.closeWithError(errBodyStreamClosed)

			sc.writeResponse(strm)

			if strm.State() != StreamStateHalfClosed {
				// the handler responded before the request body ended:
				// once the response drains, ask the client to stop
				// sending with a RST_STREAM carrying NO_ERROR (RFC 9113,
				// section 8.1.1); the frames still in flight are
				// absorbed by the reset tolerance
				strm.afterSendReset = true
			}

			finishResponse(strm)

			if sc.getState() == connStateClosed {
				maybeCloseAfterShutdown()
			}
		case <-sc.windowPoke:
			// the connection window or the peer's INITIAL_WINDOW_SIZE
			// moved: retry the stalled responses. The snapshot keeps the
			// iteration safe while finishResponse removes drained
			// streams from strms.
			for _, strm := range slices.Clone(strms) {
				if strm.sending {
					finishResponse(strm)
				}
			}

			if sc.getState() == connStateClosed {
				maybeCloseAfterShutdown()
			}
		case <-closerCh:
			closerCh = nil
			// the GOAWAY has been queued by closeIdleConn already; closing
			// the connection through the writeLoop instead of breaking the
			// loop lets the regular teardown close sc.writer once nothing
			// can write to it anymore. If the sentinel doesn't fit the
			// writeLoop is stalled on a client that stopped reading: close
			// the connection directly to unwedge it.
			if !sc.tryWriteFrame(closeConnSentinel) {
				_ = sc.c.Close()
			}
		case <-shutdownCh:
			shutdownCh = nil

			if sc.shutdownGracePeriod <= 0 {
				finalShutdown()
				continue loop
			}

			// RFC 9113 (section 6.8): first warn the client with a GOAWAY
			// carrying the highest possible stream ID and keep accepting
			// new streams, so that requests racing with the shutdown are
			// not lost; the definitive GOAWAY with the real last stream ID
			// follows after one round trip (the shutdown PING ack), or when
			// the grace period expires for clients that don't ack
			sc.writeGoAwayFrame(1<<31-1, NoError, "graceful shutdown started")
			sc.setState(connStateDraining)

			sc.writeShutdownPing()

			graceTimer = time.NewTimer(sc.shutdownGracePeriod)
			graceTimerC = graceTimer.C
		case <-sc.pingAck:
			// the shutdown PING was acked, so the warning GOAWAY has made a
			// full round trip: any stream the client created before seeing
			// it has been received already, no need to wait out the grace
			// period
			if graceTimerC != nil {
				graceTimer.Stop()
				graceTimerC = nil

				finalShutdown()
			}
		case <-graceTimerC:
			graceTimerC = nil

			finalShutdown()
		case <-sc.maxRequestTimer.C:
			reqTimerArmed = false

			// the timer is created with NewTimer(0), so its startup tick can
			// arrive late, when streams already exist; without a request
			// timeout every stream would be considered due and canceled
			if sc.maxRequestTime <= 0 {
				continue loop
			}

			deleteUntil := 0
			for _, strm := range strms {
				// the request is due if the startedAt time + maxRequestTime is in the past
				isDue := time.Now().After(
					strm.startedAt.Add(sc.maxRequestTime))
				if !isDue {
					break
				}

				deleteUntil++
			}

			for deleteUntil > 0 {
				strm := strms[0]

				if sc.debug {
					sc.logger.Printf("Stream timed out: %d\n", strm.ID())
				}
				strm.resetByServer = true
				sc.writeReset(strm.ID(), StreamCanceled)

				// set the state to closed in case it comes back to life later
				strm.SetState(StreamStateClosed)
				closeStream(strm)

				deleteUntil--
			}

			if len(strms) != 0 && sc.maxRequestTime > 0 {
				// the first in the stream list might have started with a PushPromise
				strm := strms.GetFirstOf(FrameHeaders)
				if strm != nil {
					reqTimerArmed = true
					// try to arm the timer
					when := time.Until(strm.startedAt.Add(sc.maxRequestTime))
					// if the time is negative or zero it triggers imm
					sc.maxRequestTimer.Reset(when)

					if sc.debug {
						sc.logger.Printf("Next request will timeout in %f seconds\n", when.Seconds())
					}
				}
			}
		case fr, ok := <-sc.reader:
			if !ok {
				return
			}

			isClosing := sc.getState() == connStateClosed

			var strm *Stream
			if fr.Stream() <= sc.lastID {
				strm = strms.Search(fr.Stream())
			}

			if strm == nil {
				// if the stream doesn't exist, create it

				resetByServer, ok := closedStrms[fr.Stream()]
				if !ok && fr.Stream() < closedBelow {
					// the stream ended so long ago that its entry has been
					// pruned: tolerate stray frames like on a reset stream
					ok, resetByServer = true, true
				}

				if ok {
					switch {
					case resetByServer:
						// RFC 9113 (section 5.1): after sending RST_STREAM the
						// server MUST ignore the frames the client sent before
						// learning about the reset. Their DATA still counts
						// against the connection flow-control window.
						if fr.Type() == FrameData {
							sc.applyDataFlowControl(fr, false)
						}
					case fr.Type() == FramePriority,
						fr.Type() == FrameResetStream,
						fr.Type() == FrameWindowUpdate:
						// PRIORITY is tolerated on any closed stream, and
						// RST_STREAM/WINDOW_UPDATE race with the closure:
						// the peer sends them before learning the stream
						// ended (RFC 9113, section 5.1)
					default:
						sc.writeGoAway(fr.Stream(), StreamClosedError, "frame on closed stream")
					}

					continue
				}

				if fr.Type() == FrameResetStream {
					sc.writeGoAway(fr.Stream(), ProtocolError, "RST_STREAM on idle stream")
					continue
				}

				// if the client has more open streams than the maximum allowed OR
				//   the connection is closing, then refuse the stream
				if openStreams >= int(sc.st.maxStreams) || isClosing {
					if sc.debug {
						if isClosing {
							sc.logger.Printf("Closing the connection. Rejecting stream %d\n", fr.Stream())
						} else {
							sc.logger.Printf("Max open streams reached: %d >= %d\n",
								openStreams, sc.st.maxStreams)
						}
					}

					sc.writeReset(fr.Stream(), RefusedStreamError)
					// remember the refusal: frames for this stream may
					// already be in flight and must be ignored
					rememberClosed(fr.Stream(), true)

					continue
				}

				if fr.Stream() < sc.lastID {
					sc.writeGoAway(fr.Stream(), ProtocolError, "stream ID is lower than the latest")
					continue
				}

				// the stream's send window starts at zero delta: the
				// effective window is clientInitialWindow + delta
				strm = NewStream(fr.Stream(), 0)
				strms = append(strms, strm)

				// RFC(5.1.1):
				//
				// The identifier of a newly established stream MUST be numerically
				// greater than all streams that the initiating endpoint has opened
				// or reserved. This governs streams that are opened using a
				// HEADERS frame and streams that are reserved using PUSH_PROMISE.
				if fr.Type() == FrameHeaders {
					openStreams++
					sc.lastID = fr.Stream()
				}

				sc.createStream(sc.c, fr.Type(), strm)

				if sc.debug {
					sc.logger.Printf("Stream %d created. Open streams: %d\n", strm.ID(), openStreams)
				}

				if !reqTimerArmed && sc.maxRequestTime > 0 {
					reqTimerArmed = true
					sc.maxRequestTimer.Reset(sc.maxRequestTime)

					if sc.debug {
						sc.logger.Printf("Next request will timeout in %f seconds\n", sc.maxRequestTime.Seconds())
					}
				}
			}

			// if we have more than one stream (this one newly created) check if the previous finished sending the headers
			if fr.Type() == FrameHeaders {
				nstrm := strms.getPrevious(FrameHeaders)
				if nstrm != nil && !nstrm.headersFinished {
					sc.writeError(nstrm, NewGoAwayError(ProtocolError, "previous stream headers not ended"))
					continue
				}

				for len(strms) != 0 {
					nstrm := strms[0]
					// RFC(5.1.1):
					//
					// The first use of a new stream identifier implicitly
					// closes all streams in the "idle" state that might
					// have been initiated by that peer with a lower-valued stream identifier
					if nstrm.ID() < strm.ID() &&
						nstrm.State() == StreamStateIdle &&
						nstrm.origType == FrameHeaders {

						nstrm.SetState(StreamStateClosed)
						nstrm.resetByServer = true
						closeStream(nstrm)

						if sc.debug {
							sc.logger.Printf("Canceling stream in idle state: %d\n", nstrm.ID())
						}

						sc.writeReset(nstrm.ID(), StreamCanceled)

						continue
					}

					break
				}

				if sc.maxIdleTimer != nil {
					sc.maxIdleTimer.Reset(sc.maxIdleTime)
				}
			}

			if err := sc.handleFrame(strm, fr); err != nil {
				sc.writeError(strm, err)
				strm.SetState(StreamStateClosed)
			}

			handleState(fr, strm)

			// rapid-reset detection: drain one token per client RST_STREAM;
			// close with ENHANCE_YOUR_CALM when the bucket empties
			if fr.Type() == FrameResetStream && !strm.resetByServer {
				if !rstLim.allow() {
					sc.writeGoAway(0, EnhanceYourCalm, "rapid reset detected")
					sc.writeFrame(closeConnSentinel)
					break loop
				}
			}

			// a request over MaxRequestBodySize or with an over-limit
			// header list doesn't need the rest of its body: answer with
			// the 413/431 right away and, once the response drains, ask
			// the client to stop sending with a RST_STREAM carrying
			// NO_ERROR (RFC 9113, section 8.1.1); the frames still in
			// flight are absorbed by the reset tolerance above. The
			// header block must be complete first, though: aborting in
			// the middle of it would stop decoding the remaining
			// fragments and desync the HPACK tables. A dispatched stream
			// is excluded: its handler already runs, the over-limit body
			// surfaced as its read error.
			if (strm.tooLargeBody || strm.tooLargeHeaders) && !strm.dispatched && !strm.sending &&
				strm.headersFinished && strm.State() == StreamStateOpen {
				sc.handleEndRequest(strm)
				strm.afterSendReset = true
				finishResponse(strm)
			} else {
				switch strm.State() {
				case StreamStateHalfClosed:
					if strm.dispatched {
						// the request is complete: signal EOF to the
						// handler; the response follows through
						// handlerDone
						strm.body.closeWithError(io.EOF)
						break
					}

					if strm.sending {
						// the request completed while its early response
						// was still draining: no reset needed anymore,
						// and this frame may have opened the windows
						strm.afterSendReset = false
						finishResponse(strm)
						break
					}

					sc.handleEndRequest(strm)
					finishResponse(strm)
				case StreamStateClosed:
					closeStream(strm)
				default:
					if strm.sending {
						// a WINDOW_UPDATE may have opened the stream's
						// window: keep the early response draining
						finishResponse(strm)
					}
				}
			}

			if isClosing {
				maybeCloseAfterShutdown()
			}
		}
	}
}

func (sc *serverConn) writeReset(strm uint32, code ErrorCode) {
	r := AcquireFrame(FrameResetStream).(*RstStream)

	fr := AcquireFrameHeader()
	fr.SetStream(strm)
	fr.SetBody(r)

	r.SetCode(code)

	sc.writeFrame(fr)

	if sc.debug {
		sc.logger.Printf(
			"%s: Reset(stream=%d, code=%s)\n",
			sc.c.RemoteAddr(), strm, code,
		)
	}
}

// applyDataFlowControl accounts a received DATA frame against the receive
// windows and replenishes them (fr.Len() covers the whole payload, padding
// included, which is what flow control counts). It must run even for
// payloads that get discarded: the client consumed connection window to
// send them, and without the refill every other stream would slowly stall.
// streamAlive controls whether the stream window is replenished too.
func (sc *serverConn) applyDataFlowControl(fr *FrameHeader, streamAlive bool) {
	if fr.Len() == 0 {
		return
	}

	sc.currentWindow -= int32(fr.Len())

	if streamAlive && !fr.Flags().Has(FlagEndStream) {
		sc.updateWindow(fr.Stream(), fr.Len())
	}

	if sc.currentWindow < sc.maxWindow/2 {
		sc.updateWindow(0, int(sc.maxWindow-sc.currentWindow))
		sc.currentWindow = sc.maxWindow
	}
}

// applyEncTableSize applies an HPACK table size a SETTINGS frame changed
// meanwhile. Must run on the handleStreams goroutine, the encoder's owner.
func (sc *serverConn) applyEncTableSize() {
	if v := sc.encTableSize.Swap(-1); v >= 0 {
		sc.enc.SetMaxTableSize(uint32(v))
	}
}

// pokeWindows wakes handleStreams to retry the responses stalled on flow
// control. Non-blocking: a pending poke already covers this one.
func (sc *serverConn) pokeWindows() {
	select {
	case sc.windowPoke <- struct{}{}:
	default:
	}
}

// streamSendWindow is how much the peer can still receive on the stream:
// its INITIAL_WINDOW_SIZE plus the stream's WINDOW_UPDATE/sent delta. It
// can be negative after an INITIAL_WINDOW_SIZE decrease (RFC 9113,
// section 6.9.2).
func (sc *serverConn) streamSendWindow(strm *Stream) int64 {
	return sc.clientInitialWindow.Load() + strm.window.Load()
}

// updateWindow sends a WINDOW_UPDATE to replenish the peer's send window
// after consuming DATA. A streamID of 0 refills the connection window.
func (sc *serverConn) updateWindow(streamID uint32, size int) {
	fr := AcquireFrameHeader()
	fr.SetStream(streamID)

	wu := AcquireFrame(FrameWindowUpdate).(*WindowUpdate)
	wu.SetIncrement(size)

	fr.SetBody(wu)

	sc.writeFrame(fr)
}

// writeGoAwayFrame only queues the GOAWAY frame, leaving the connection
// state untouched.
// newGoAwayFrame builds a GOAWAY frame ready to be queued.
func (sc *serverConn) newGoAwayFrame(strm uint32, code ErrorCode, message string) *FrameHeader {
	ga := AcquireFrame(FrameGoAway).(*GoAway)

	fr := AcquireFrameHeader()

	ga.SetStream(strm)
	ga.SetCode(code)
	ga.SetData([]byte(message))

	fr.SetBody(ga)

	if sc.debug {
		sc.logger.Printf(
			"%s: GoAway(stream=%d, code=%s): %s\n",
			sc.c.RemoteAddr(), strm, code, message,
		)
	}

	return fr
}

func (sc *serverConn) writeGoAwayFrame(strm uint32, code ErrorCode, message string) {
	sc.writeFrame(sc.newGoAwayFrame(strm, code, message))
}

func (sc *serverConn) writeGoAway(strm uint32, code ErrorCode, message string) {
	sc.writeGoAwayFrame(strm, code, message)

	if strm != 0 {
		sc.closeRef.Store(sc.lastID)
	}

	sc.setState(connStateClosed)
}

func (sc *serverConn) writeError(strm *Stream, err error) {
	streamErr := Error{}
	if !errors.As(err, &streamErr) {
		strm.resetByServer = true
		sc.writeReset(strm.ID(), InternalError)
		strm.SetState(StreamStateClosed)
		return
	}

	switch streamErr.frameType {
	case FrameGoAway:
		if strm == nil {
			sc.writeGoAway(0, streamErr.Code(), streamErr.Error())
		} else {
			sc.writeGoAway(strm.ID(), streamErr.Code(), streamErr.Error())
		}
	case FrameResetStream:
		strm.resetByServer = true
		sc.writeReset(strm.ID(), streamErr.Code())
	}

	if strm != nil {
		strm.SetState(StreamStateClosed)
	}
}

func handleState(fr *FrameHeader, strm *Stream) {
	if fr.Type() == FrameResetStream {
		strm.SetState(StreamStateClosed)
		return
	}

	switch strm.State() {
	case StreamStateIdle:
		if fr.Type() == FrameHeaders {
			strm.SetState(StreamStateOpen)
			if endStreamReceived(fr, strm) {
				strm.SetState(StreamStateHalfClosed)
			}
		} // TODO: else push promise ...
	case StreamStateReserved:
		// TODO: ...
	case StreamStateOpen:
		if endStreamReceived(fr, strm) {
			strm.SetState(StreamStateHalfClosed)
		}
	case StreamStateHalfClosed:
		// a stream can only go from HalfClosed to Closed if the client
		// sends a ResetStream frame.
	case StreamStateClosed:
	}
}

// endStreamReceived reports whether the client half-closed the stream with
// this frame. An END_STREAM flag on a HEADERS frame only takes effect once
// its header (or trailer) block is complete: the request must not be
// dispatched while CONTINUATION or trailer fields are still to be decoded.
func endStreamReceived(fr *FrameHeader, strm *Stream) bool {
	if fr.Type() == FrameHeaders || fr.Type() == FrameContinuation {
		return strm.headersFinished && strm.endStreamPending
	}

	return fr.Flags().Has(FlagEndStream)
}

var logger = log.New(os.Stdout, "[HTTP/2] ", log.LstdFlags)

var ctxPool = sync.Pool{
	New: func() any {
		return &fasthttp.RequestCtx{}
	},
}

func (sc *serverConn) createStream(c net.Conn, frameType FrameType, strm *Stream) {
	ctx := ctxPool.Get().(*fasthttp.RequestCtx)
	ctx.Request.Reset()
	ctx.Response.Reset()

	ctx.Init2(c, sc.logger, false)

	strm.origType = frameType
	strm.startedAt = time.Now()
	strm.SetData(ctx)
}

func (sc *serverConn) handleFrame(strm *Stream, fr *FrameHeader) error {
	err := sc.verifyState(strm, fr)
	if err != nil {
		return err
	}

	switch fr.Type() {
	case FrameHeaders, FrameContinuation:
		if strm.State() >= StreamStateHalfClosed {
			return NewGoAwayError(ProtocolError, "received headers on a finished stream")
		}

		err = sc.handleHeaderFrame(strm, fr)
		if err != nil {
			return err
		}

		if fr.Flags().Has(FlagEndHeaders) {
			// headers are only finished if there's no previousHeaderBytes
			strm.headersFinished = len(strm.previousHeaderBytes) == 0
			if !strm.headersFinished {
				return NewGoAwayError(ProtocolError, "END_HEADERS received on an incomplete stream")
			}

			if strm.trailers {
				// the trailer section ended; an over-limit header list
				// skips the checks the same way the request headers do
				if !strm.tooLargeHeaders {
					if strm.headerViolation != "" {
						return NewResetStreamError(ProtocolError, strm.headerViolation)
					}

					// the body ended with the trailers: a content-length
					// not matching the DATA payloads is malformed
					// (RFC 9113, section 8.1.1)
					if !strm.tooLargeBody &&
						strm.expectedContentLength >= 0 &&
						strm.expectedContentLength != strm.recvBody {

						return NewResetStreamError(ProtocolError, "content-length header field does not match the DATA payload")
					}
				}

				return nil
			}

			// calling req.URI() triggers a URL parsing, so because of that we need to delay the URL parsing.
			strm.ctx.Request.URI().SetSchemeBytes(strm.scheme)

			// an over-limit header list skips the validation: fields were
			// discarded and the request is answered with 431 regardless
			if !strm.tooLargeHeaders {
				if err := validateRequestHeaders(strm); err != nil {
					return err
				}

				// a declared length over the limit rejects the request
				// before buffering anything
				if strm.expectedContentLength > int64(sc.maxRequestBodySize) {
					strm.tooLargeBody = true
				}

				// with StreamRequestBody the handler starts now and reads
				// the body while its DATA frames are still arriving;
				// bodyless requests and the ones already rejected (413)
				// keep the buffered path
				if sc.streamRequestBody && !strm.tooLargeBody && !strm.endStreamPending {
					sc.dispatchStream(strm)
				}
			}
		}
	case FrameData:
		if !strm.headersFinished {
			return NewGoAwayError(ProtocolError, "stream didn't end the headers")
		}

		if strm.State() >= StreamStateHalfClosed {
			return NewGoAwayError(StreamClosedError, "stream closed")
		}

		// a dispatched handler consumes the body through the pipe, and its
		// stream window is only refunded as the handler reads (that's the
		// backpressure); otherwise the window refills right away
		sc.applyDataFlowControl(fr, !strm.dispatched)

		data := fr.Body().(*Data).Data()
		strm.recvBody += int64(len(data))

		switch {
		case strm.dispatched:
			// same limit as the buffered path: the handler's reads fail
			// with ErrBodyTooLarge, and the withheld window refunds
			// stall the rest of the upload
			if !strm.tooLargeBody && strm.recvBody > int64(sc.maxRequestBodySize) {
				strm.tooLargeBody = true
				strm.body.closeWithError(fasthttp.ErrBodyTooLarge)
			}

			strm.body.write(data)
		case strm.sending:
			// the stream was already answered (an early response still
			// draining): the rest of the request body is discarded
		case strm.tooLargeBody:
			// drain the rest of the body without buffering it; the
			// flow-control accounting above keeps the windows correct
		case len(strm.ctx.Request.Body())+len(data) > sc.maxRequestBodySize:
			strm.tooLargeBody = true
			// release what has been buffered so far: the request is
			// going to be rejected without reaching the handler
			strm.ctx.Request.ResetBody()
		default:
			strm.ctx.Request.AppendBody(data)
		}

		// RFC 9113 (section 8.1.1): a request whose content-length doesn't
		// match the sum of the DATA payloads is malformed
		if fr.Flags().Has(FlagEndStream) &&
			!strm.tooLargeBody &&
			strm.expectedContentLength >= 0 &&
			strm.expectedContentLength != strm.recvBody {

			return NewResetStreamError(ProtocolError, "content-length header field does not match the DATA payload")
		}
	case FrameResetStream:
		if strm.State() == StreamStateIdle {
			return NewGoAwayError(ProtocolError, "RST_STREAM on idle stream")
		}
	case FramePriority:
		if strm.State() != StreamStateIdle && !strm.headersFinished {
			return NewGoAwayError(ProtocolError, "frame priority on an open stream")
		}

		if priorityFrame, ok := fr.Body().(*Priority); ok && priorityFrame.Stream() == strm.ID() {
			return NewGoAwayError(ProtocolError, "stream that depends on itself")
		}
	case FrameWindowUpdate:
		if strm.State() == StreamStateIdle {
			return NewGoAwayError(ProtocolError, "window update on idle stream")
		}

		win := int64(fr.Body().(*WindowUpdate).Increment())
		if win == 0 {
			return NewGoAwayError(ProtocolError, "window increment of 0")
		}

		if strm.window.Add(win)+sc.clientInitialWindow.Load() >= 1<<31-1 {
			return NewResetStreamError(FlowControlError, "window is above limits")
		}
	default:
		return NewGoAwayError(ProtocolError, "invalid frame")
	}

	return err
}

func (sc *serverConn) handleHeaderFrame(strm *Stream, fr *FrameHeader) error {
	if fr.Type() == FrameHeaders && strm.headersFinished {
		// a HEADERS frame after the request headers starts the trailer
		// section (RFC 9113, section 8.1), which reopens the header block
		strm.trailers = true
		strm.headersFinished = false

		// trailers must carry END_STREAM: without it the request is
		// malformed, but the block is still decoded so the HPACK tables
		// stay synchronized; the stream is reset once the block ends
		if !fr.Flags().Has(FlagEndStream) {
			strm.recordViolation("trailer HEADERS frame without END_STREAM")
		}
	}

	// END_STREAM only takes effect once the header block completes: the
	// stream state changes on the frame carrying END_HEADERS
	if fr.Type() == FrameHeaders && fr.Flags().Has(FlagEndStream) {
		strm.endStreamPending = true
	}

	if headerFrame, ok := fr.Body().(*Headers); ok && headerFrame.Stream() == strm.ID() {
		return NewGoAwayError(ProtocolError, "stream that depends on itself")
	}

	fragment := fr.Body().(FrameWithHeaders).Headers()

	// hard cap on the raw header block: a client streaming an endless
	// block through CONTINUATION frames (a CONTINUATION flood) must not
	// grow memory or keep the decoder busy indefinitely
	strm.headerBlockSize += len(fragment)
	if strm.headerBlockSize > sc.headerBlockCap() {
		return NewGoAwayError(EnhanceYourCalm, "header block too large")
	}

	b := append(strm.previousHeaderBytes, fragment...)
	hf := AcquireHeaderField()
	req := &strm.ctx.Request

	var err error

	strm.previousHeaderBytes = strm.previousHeaderBytes[:0]
	fieldsProcessed := 0

	for len(b) > 0 {
		pb := b

		b, err = sc.dec.nextField(hf, strm.headerBlockNum, fieldsProcessed, b)
		if err != nil {
			if errors.Is(err, ErrUnexpectedSize) && len(pb) > 0 {
				err = nil
				strm.previousHeaderBytes = append(strm.previousHeaderBytes, pb...)
			} else {
				err = NewGoAwayError(CompressionError, err.Error())
			}

			break
		}

		fieldsProcessed++

		// RFC 9113 (section 10.5): the size of a header list is the sum
		// of its field sizes: name length + value length + 32
		strm.headerListSize += len(hf.KeyBytes()) + len(hf.ValueBytes()) + 32
		if strm.headerListSize > sc.maxHeaderListSize {
			strm.tooLargeHeaders = true
		}

		if strm.tooLargeHeaders {
			// keep decoding so the HPACK tables stay synchronized, but
			// discard the fields: the request is answered with 431
			continue
		}

		k, v := hf.KeyBytes(), hf.ValueBytes()

		if strm.trailers {
			// trailer fields have their own rules (RFC 9113, section 8.1):
			// pseudo-header fields are forbidden, and so are the fields
			// listed in RFC 9110, section 6.5.1
			if hf.IsPseudo() {
				strm.recordViolation("pseudo-header field in trailer section")
				continue
			}

			if strm.dispatched {
				validateStreamedTrailerField(strm, k, v)
			} else {
				validateTrailerField(strm, req, k, v)
			}

			continue
		}

		if hf.IsPseudo() {
			if err = parsePseudoField(strm, req, k[1:], v); err != nil {
				break
			}

			continue
		}

		// a violation makes the request malformed, but the block keeps
		// being decoded so the HPACK tables stay synchronized; the stream
		// is reset once the block ends
		strm.regularHeadersSeen = true
		validateRegularField(strm, k, v)

		switch {
		case bytes.Equal(k, StringUserAgent):
			req.Header.SetUserAgentBytes(v)
		case bytes.Equal(k, StringContentType):
			req.Header.SetContentTypeBytes(v)
		default:
			req.Header.AddBytesKV(k, v)
		}
	}

	strm.headerBlockNum++

	return err
}

// headerBlockCap bounds the raw (compressed) size of a request's header
// block. It leaves room over the decoded limit so that requests moderately
// over it still get the graceful 431 instead of a connection error.
func (sc *serverConn) headerBlockCap() int {
	if c := sc.maxHeaderListSize * 4; c > 16384 {
		return c
	}

	return 16384
}

const (
	pseudoMethod = uint8(1) << iota
	pseudoScheme
	pseudoPath
	pseudoAuthority
)

// parsePseudoField handles a request pseudo-header field (RFC 9113,
// section 8.3.1). k comes without the leading ':'.
func parsePseudoField(strm *Stream, req *fasthttp.Request, k, v []byte) error {
	if strm.regularHeadersSeen {
		strm.recordViolation("pseudo-header field after a regular header field")
	}

	var seen uint8

	switch {
	case bytes.Equal(k, StringMethod[1:]):
		seen = pseudoMethod
		req.Header.SetMethodBytes(v)
	case bytes.Equal(k, StringPath[1:]):
		seen = pseudoPath
		if len(v) == 0 {
			strm.recordViolation("empty :path pseudo-header field")
		}

		req.Header.SetRequestURIBytes(v)
	case bytes.Equal(k, StringScheme[1:]):
		seen = pseudoScheme
		strm.scheme = append(strm.scheme[:0], v...)
	case bytes.Equal(k, StringAuthority[1:]):
		seen = pseudoAuthority
		req.Header.SetHostBytes(v)
		req.Header.AddBytesV("Host", v)
	default:
		return NewGoAwayError(ProtocolError, fmt.Sprintf("unknown header field %s", k))
	}

	if strm.pseudoSeen&seen != 0 {
		strm.recordViolation("duplicated pseudo-header field")
	}

	strm.pseudoSeen |= seen

	return nil
}

// validateRegularField checks a regular header field for the
// malformed-request conditions of RFC 9113, sections 8.2.1 to 8.2.2.
func validateRegularField(strm *Stream, k, v []byte) {
	if len(k) == 0 {
		strm.recordViolation("empty header field name")
		return
	}

	for _, c := range k {
		if 'A' <= c && c <= 'Z' {
			strm.recordViolation("uppercase header field name")
			return
		}
	}

	// the connection-specific header fields forbidden by section 8.2.2 and
	// the fields with checked values all start with one of these letters,
	// so most fields are done after the switch on the first byte
	switch k[0] {
	case 'c':
		if string(k) == "connection" {
			strm.recordViolation("connection-specific header field")
		} else if bytes.Equal(k, StringContentLength) {
			n, err := fasthttp.ParseUint(v)
			if err != nil {
				strm.recordViolation("invalid content-length header field")
			} else if strm.expectedContentLength >= 0 && strm.expectedContentLength != int64(n) {
				strm.recordViolation("duplicated content-length header field")
			} else {
				strm.expectedContentLength = int64(n)
			}
		}
	case 'k':
		if string(k) == "keep-alive" {
			strm.recordViolation("connection-specific header field")
		}
	case 'p':
		if string(k) == "proxy-connection" {
			strm.recordViolation("connection-specific header field")
		}
	case 't':
		if bytes.Equal(k, StringTE) {
			if !bytes.EqualFold(v, StringTrailers) {
				strm.recordViolation(`te header field with value other than "trailers"`)
			}
		} else if string(k) == "transfer-encoding" {
			strm.recordViolation("connection-specific header field")
		}
	case 'u':
		if string(k) == "upgrade" {
			strm.recordViolation("connection-specific header field")
		}
	}
}

// validateTrailerField checks and stores a request trailer field. The value
// lands in the header storage — like fasthttp does for HTTP/1.1 trailers —
// and the key is registered as a trailer, so handlers can tell trailers and
// headers apart through Request.Header.Trailers().
func validateTrailerField(strm *Stream, req *fasthttp.Request, k, v []byte) {
	for _, c := range k {
		if 'A' <= c && c <= 'Z' {
			strm.recordViolation("uppercase header field name")
			return
		}
	}

	// AddTrailerBytes rejects the fields that RFC 9110 (section 6.5.1)
	// forbids in a trailer section (framing, routing, authentication...)
	if err := req.Header.AddTrailerBytes(k); err != nil {
		strm.recordViolation("field not allowed in trailer section")
		return
	}

	req.Header.AddBytesKV(k, v)
}

// validateStreamedTrailerField checks and stashes a trailer field of a
// stream whose handler is already running: the handler owns the request
// header, so the field is parked on the body pipe and applied from the
// handler's side when the body reaches EOF. The forbidden-in-trailers
// check happens there too, surfacing as a body read error.
func validateStreamedTrailerField(strm *Stream, k, v []byte) {
	for _, c := range k {
		if 'A' <= c && c <= 'Z' {
			strm.recordViolation("uppercase header field name")
			return
		}
	}

	strm.body.addTrailer(k, v)
}

// validateRequestHeaders enforces the rules that can only be checked once
// the header block ends: mandatory pseudo-header fields (RFC 9113, section
// 8.3.1) and a content-length coherent with END_STREAM (section 8.1.1).
// Violations recorded while decoding are surfaced here as well, now that
// the HPACK state is synchronized: the malformed request resets the stream
// instead of killing the connection.
func validateRequestHeaders(strm *Stream) error {
	if strm.headerViolation == "" {
		switch {
		case strm.pseudoSeen&pseudoMethod == 0:
			strm.recordViolation("missing :method pseudo-header field")
		case bytes.Equal(strm.ctx.Request.Header.Method(), StringCONNECT):
			// CONNECT requests carry only :method and :authority
			if strm.pseudoSeen&(pseudoScheme|pseudoPath) != 0 {
				strm.recordViolation(":scheme or :path pseudo-header field on a CONNECT request")
			} else if strm.pseudoSeen&pseudoAuthority == 0 {
				strm.recordViolation("missing :authority pseudo-header field on a CONNECT request")
			}
		case strm.pseudoSeen&pseudoScheme == 0:
			strm.recordViolation("missing :scheme pseudo-header field")
		case strm.pseudoSeen&pseudoPath == 0:
			strm.recordViolation("missing :path pseudo-header field")
		}

		if strm.endStreamPending && strm.expectedContentLength > 0 {
			strm.recordViolation("content-length header field on a request without payload")
		}
	}

	if strm.headerViolation != "" {
		return NewResetStreamError(ProtocolError, strm.headerViolation)
	}

	return nil
}

func (sc *serverConn) verifyState(strm *Stream, fr *FrameHeader) error {
	switch strm.State() {
	case StreamStateIdle:
		if fr.Type() != FrameHeaders && fr.Type() != FramePriority {
			return NewGoAwayError(ProtocolError, "wrong frame on idle stream")
		}
	case StreamStateHalfClosed:
		if fr.Type() != FrameWindowUpdate && fr.Type() != FramePriority && fr.Type() != FrameResetStream {
			return NewGoAwayError(StreamClosedError, "wrong frame on half-closed stream")
		}
	default:
	}

	return nil
}

// dispatchStream starts the handler of a stream whose body is still in
// flight (Server.StreamRequestBody): the handler reads the body from a
// pipe the frame loop feeds, and the response is written once the handler
// comes back through handlerDone.
func (sc *serverConn) dispatchStream(strm *Stream) {
	strm.dispatched = true
	strm.body = acquireRequestBody(sc, strm.ID(), &strm.ctx.Request)

	ctx := strm.ctx
	ctx.Request.Header.SetProtocolBytes(StringHTTP2)
	ctx.Request.SetBodyStream(strm.body, int(strm.expectedContentLength))

	if sc.debug {
		sc.logger.Printf("Stream %d dispatched with the body in flight\n", strm.ID())
	}

	// hand the stream to a parked worker; only when none is idle does a
	// new one spawn. Workers are never awaited for: a bounded pool would
	// stall new requests behind handlers blocked on slow uploads.
	select {
	case sc.handlerTasks <- strm:
	default:
		go sc.handlerWorker(strm)
	}
}

// handlerWorkerIdleTime is how long a handler worker stays parked waiting
// for the connection's next streamed request before exiting.
const handlerWorkerIdleTime = 10 * time.Second

// handlerWorker runs dispatched handlers, then parks on handlerTasks to be
// reused by the next streamed request; it exits after sitting idle for
// handlerWorkerIdleTime or when the connection tears down.
func (sc *serverConn) handlerWorker(strm *Stream) {
	idle := time.NewTimer(handlerWorkerIdleTime)
	defer idle.Stop()

	for {
		sc.runHandler(strm)

		idle.Reset(handlerWorkerIdleTime)

		var ok bool
		select {
		case strm, ok = <-sc.handlerTasks:
			if !ok {
				return
			}
		case <-idle.C:
			return
		}
	}
}

// runHandler runs the handler of a dispatched stream and reports it back
// to the frame loop, which owns the response writing.
func (sc *serverConn) runHandler(strm *Stream) {
	defer func() {
		if err := recover(); err != nil {
			sc.logger.Printf("handler panicked: %s\n%s\n", err, debug.Stack())
			strm.ctx.Error("Internal Server Error", fasthttp.StatusInternalServerError)
		}

		sc.handlerDone <- strm
	}()

	sc.h(strm.ctx)
}

// handleEndRequest dispatches the finished request to the handler.
func (sc *serverConn) handleEndRequest(strm *Stream) {
	ctx := strm.ctx
	ctx.Request.Header.SetProtocolBytes(StringHTTP2)

	switch {
	case strm.tooLargeHeaders:
		// same as fasthttp: the error goes through the configured
		// ErrorHandler, which can customize the response
		if sc.errorHandler != nil {
			sc.errorHandler(ctx, ErrTooLargeHeaders)
		} else {
			ctx.Error("Too big request header", fasthttp.StatusRequestHeaderFieldsTooLarge)
		}
	case strm.tooLargeBody:
		if sc.errorHandler != nil {
			sc.errorHandler(ctx, fasthttp.ErrBodyTooLarge)
		} else {
			ctx.Error(fasthttp.ErrBodyTooLarge.Error(), fasthttp.StatusRequestEntityTooLarge)
		}
	default:
		sc.h(ctx)
	}

	sc.writeResponse(strm)
}

// writeResponse encodes and queues the response of a served stream:
// headers, body and the announced trailers. It must run on the
// handleStreams goroutine, which owns the HPACK encoder.
func (sc *serverConn) writeResponse(strm *Stream) {
	sc.applyEncTableSize()

	ctx := strm.ctx

	hasBody := ctx.Response.IsBodyStream() || len(ctx.Response.Body()) > 0
	// fields announced with Response.Header.SetTrailer/AddTrailer are sent
	// in a HEADERS frame after the body, and that frame ends the stream
	hasTrailer := len(ctx.Response.Header.PeekTrailerKeys()) > 0

	fr := AcquireFrameHeader()
	fr.SetStream(strm.ID())

	h := AcquireFrame(FrameHeaders).(*Headers)
	h.SetEndHeaders(true)
	h.SetEndStream(!hasBody && !hasTrailer)

	fr.SetBody(h)

	fasthttpResponseHeaders(h, &sc.enc, &ctx.Response)

	sc.writeFrame(fr)

	switch {
	case hasBody:
		// the body is flow controlled: it's queued here and pumped by
		// finishResponse as far as the peer's windows allow
		if ctx.Response.IsBodyStream() {
			strm.sendReader = ctx.Response.BodyStream()
			strm.sendSize = int64(ctx.Response.Header.ContentLength())
		} else {
			strm.sendBody = ctx.Response.Body()
		}

		strm.sendTrailer = hasTrailer
		strm.sending = true
	case hasTrailer:
		// a trailer-only response: HEADERS frames aren't flow controlled
		sc.writeTrailer(strm, &ctx.Response)
	}
}

// pumpSend queues as much of the pending response body as the peer's
// flow-control windows allow (RFC 9113, section 5.2), and the trailer
// HEADERS once the body is done. It reports whether the response has been
// fully queued; on false the rest waits for the next window event.
func (sc *serverConn) pumpSend(strm *Stream) bool {
	if !strm.sending {
		return true
	}

	var buf []byte
	if strm.sendReader != nil {
		buf = copyBufPool.Get().([]byte)
		defer copyBufPool.Put(buf) //nolint:staticcheck // buf is never resliced
	}

	for !strm.sendDone {
		// the next chunk, bounded by the frame size and both windows
		step := 1 << 14 // max frame size 16384
		if win := sc.streamSendWindow(strm); win < int64(step) {
			step = int(win)
		}
		if win := sc.clientWindow.Load(); win < int64(step) {
			step = int(win)
		}

		var chunk []byte

		switch {
		case strm.sendReader != nil && strm.sendSize != 0:
			if step <= 0 {
				return false
			}

			if strm.sendSize > 0 && int64(step) > strm.sendSize {
				step = int(strm.sendSize)
			}

			n, err := strm.sendReader.Read(buf[:step])
			chunk = buf[:n]

			if strm.sendSize > 0 {
				strm.sendSize -= int64(n)
			}

			// EOF, a read error or a stalled reader all end the body:
			// the client can't be left waiting on an open stream
			if err != nil || n == 0 || strm.sendSize == 0 {
				strm.sendReader = nil
				strm.sendDone = true
			}
		case strm.sendReader == nil && len(strm.sendBody) > 0:
			if step <= 0 {
				return false
			}

			if step > len(strm.sendBody) {
				step = len(strm.sendBody)
			}

			chunk = strm.sendBody[:step]
			strm.sendBody = strm.sendBody[step:]
			strm.sendDone = len(strm.sendBody) == 0
		default:
			// nothing (left) to send: only the closing empty DATA frame,
			// which consumes no window
			strm.sendDone = true
		}

		endStream := strm.sendDone && !strm.sendTrailer
		if len(chunk) > 0 || endStream {
			sc.sendDataFrame(strm.ID(), chunk, endStream)

			n := int64(len(chunk))
			strm.window.Add(-n)
			sc.clientWindow.Add(-n)
		}
	}

	if strm.sendTrailer {
		sc.writeTrailer(strm, &strm.ctx.Response)
		strm.sendTrailer = false
	}

	strm.sending = false

	return true
}

// sendDataFrame queues one DATA frame; the payload is copied into the
// frame, so chunk can be reused right away.
func (sc *serverConn) sendDataFrame(strmID uint32, chunk []byte, endStream bool) {
	fr := AcquireFrameHeader()
	fr.SetStream(strmID)

	data := AcquireFrame(FrameData).(*Data)
	data.SetEndStream(endStream)
	data.SetPadding(false)
	data.SetData(chunk)

	fr.SetBody(data)

	sc.writeFrame(fr)
}

// writeTrailer encodes the response fields announced as trailers into the
// HEADERS frame that ends the stream (RFC 9113, section 8.1). The values
// are the ones set on the response header under the announced keys.
func (sc *serverConn) writeTrailer(strm *Stream, res *fasthttp.Response) {
	sc.applyEncTableSize()

	fr := AcquireFrameHeader()
	fr.SetStream(strm.ID())

	h := AcquireFrame(FrameHeaders).(*Headers)
	h.SetEndHeaders(true)
	h.SetEndStream(true)

	fr.SetBody(h)

	hf := AcquireHeaderField()
	defer ReleaseHeaderField(hf)

	for _, k := range res.Header.PeekTrailerKeys() {
		hf.SetBytes(k, res.Header.PeekBytes(k))
		ToLower(hf.KeyBytes())
		h.AppendHeaderField(&sc.enc, hf, false)
	}

	sc.writeFrame(fr)
}

var (
	copyBufPool = sync.Pool{
		New: func() any {
			return make([]byte, 1<<14) // max frame size 16384
		},
	}
)

func (sc *serverConn) sendPingAndSchedule() {
	sc.writePing()

	sc.pingTimer.Reset(sc.pingInterval)
}

func (sc *serverConn) writeLoop() {
	buffered := 0

	for fr := range sc.writer {
		if fr == closeConnSentinel {
			_ = sc.bw.Flush()
			_ = sc.c.Close()
			continue
		}

		// mirror fasthttp.Server.WriteTimeout: the deadline is renewed
		// before every frame, so a large streamed response only fails when
		// a single frame can't be written in time (a stalled client), not
		// because the response as a whole outlasted the timeout
		if sc.writeTimeout > 0 {
			_ = sc.c.SetWriteDeadline(time.Now().Add(sc.writeTimeout))
		}

		_, err := fr.WriteTo(sc.bw)
		if err == nil && (len(sc.writer) == 0 || buffered > 10) {
			err = sc.bw.Flush()
			buffered = 0
		} else if err == nil {
			buffered++
		}

		ReleaseFrameHeader(fr)

		if err != nil {
			sc.logger.Printf("ERROR: writeLoop: %s\n", err)

			// closing the connection ends the readLoop and with it the
			// regular teardown; meanwhile keep draining the channel so a
			// large streamed response doesn't block handleStreams on a
			// writer nobody consumes anymore
			_ = sc.c.Close()

			for fr := range sc.writer {
				if fr != closeConnSentinel {
					ReleaseFrameHeader(fr)
				}
			}

			return
		}
	}
}

func (sc *serverConn) handleSettings(st *Settings) {
	st.CopyTo(&sc.clientS)

	// the HPACK encoder belongs to the handleStreams goroutine: park the
	// new table size for it instead of racing the response encoding
	sc.encTableSize.Store(int64(sc.clientS.HeaderTableSize()))

	// a changed INITIAL_WINDOW_SIZE applies to every stream, the open
	// ones retroactively (RFC 9113, section 6.9.2); the send windows
	// derive from this base, so storing it is the whole adjustment
	sc.clientInitialWindow.Store(int64(sc.clientS.MaxWindowSize()))
	sc.pokeWindows()

	fr := AcquireFrameHeader()

	stRes := AcquireFrame(FrameSettings).(*Settings)
	stRes.SetAck(true)

	fr.SetBody(stRes)

	sc.writeFrame(fr)
}

func fasthttpResponseHeaders(dst *Headers, hp *HPACK, res *fasthttp.Response) {
	hf := AcquireHeaderField()
	defer ReleaseHeaderField(hf)

	hf.SetKeyBytes(StringStatus)
	hf.SetValue(
		strconv.FormatInt(
			int64(res.Header.StatusCode()), 10,
		),
	)

	dst.AppendHeaderField(hp, hf, true)

	if !res.IsBodyStream() {
		res.Header.SetContentLength(len(res.Body()))
	}
	// Remove the Connection field
	res.Header.Del("Connection")
	// Remove the Transfer-Encoding field
	res.Header.Del("Transfer-Encoding")

	trailer := res.Header.PeekTrailerKeys()

	for k, v := range res.Header.All() {
		// fields announced as trailers travel in the HEADERS frame that
		// ends the stream, not with the response headers (the "trailer"
		// announcement itself is yielded by All and does get written)
		if isTrailerField(trailer, k) {
			continue
		}

		hf.SetBytes(k, v)
		ToLower(hf.KeyBytes())
		dst.AppendHeaderField(hp, hf, false)
	}
}

func isTrailerField(trailer [][]byte, k []byte) bool {
	for _, t := range trailer {
		if bytes.Equal(t, k) {
			return true
		}
	}

	return false
}
