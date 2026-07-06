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
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/valyala/fasthttp"
)

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

	// client's window
	// should be int64 because the user can try to overflow it
	clientWindow int64

	// our values
	maxWindow     int32
	currentWindow int32

	writer chan *FrameHeader
	reader chan *FrameHeader

	state connState
	// closeRef stores the last stream that was valid before sending a GOAWAY.
	// Thus, the number stored in closeRef is used to complete all the requests that were sent before
	// to gracefully close the connection with a GOAWAY.
	closeRef uint32

	// maxRequestTime is the max time of a request over one single stream
	maxRequestTime time.Duration
	pingInterval   time.Duration
	// maxIdleTime is the max time a client can be connected without sending any REQUEST.
	// As highlighted, PING/PONG frames are completely excluded.
	//
	// Therefore, a client that didn't send a request for more than `maxIdleTime` will see it's connection closed.
	maxIdleTime time.Duration

	// maxRequestBodySize limits how much of a request body is buffered,
	// mirroring fasthttp.Server.MaxRequestBodySize
	maxRequestBodySize int
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

// gracefulShutdown signals the connection to send a GOAWAY, serve the
// streams accepted so far and then close. It's safe to call it multiple
// times and from any goroutine.
func (sc *serverConn) gracefulShutdown() {
	sc.shutdownOnce.Do(func() {
		close(sc.shutdown)
	})
}

func (sc *serverConn) closeIdleConn() {
	sc.writeGoAway(0, NoError, "connection has been idle for a long time")
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
	sc.clientWindow = int64(sc.clientS.MaxWindowSize())

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

func (sc *serverConn) handlePing(ping *Ping) {
	fr := AcquireFrameHeader()
	ping.SetAck(true)
	fr.SetBody(ping)

	sc.writeFrame(fr)
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

func (sc *serverConn) readLoop() (err error) {
	defer func() {
		if err := recover(); err != nil {
			sc.logger.Printf("readLoop panicked: %s\n%s\n", err, debug.Stack())
		}
	}()

	var fr *FrameHeader

	for err == nil {
		fr, err = ReadFrameFromWithSize(sc.br, sc.clientS.frameSize)
		if err != nil {
			if errors.Is(err, ErrUnknownFrameType) {
				sc.writeGoAway(0, ProtocolError, "unknown frame type")
				err = nil
				continue
			}

			break
		}

		if fr.Stream() != 0 {
			err := sc.checkFrameWithStream(fr)
			if err != nil {
				sc.writeError(nil, err)
			} else {
				sc.reader <- fr
			}

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
				sc.writeGoAway(0, ProtocolError, "window increment of 0")
				// return
				continue
			}

			if atomic.AddInt64(&sc.clientWindow, win) >= 1<<31-1 {
				sc.writeGoAway(0, FlowControlError, "window is above limits")
			}
		case FramePing:
			ping := fr.Body().(*Ping)
			if !ping.IsAck() {
				sc.handlePing(ping)
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
			sc.writeGoAway(0, ProtocolError, "invalid frame")
		}

		ReleaseFrameHeader(fr)
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

	// closedStrms remembers the streams that already ended; the value
	// records whether the server reset them, in which case frames the
	// client sent before learning about the reset are ignored instead of
	// being a connection error
	closedStrms := make(map[uint32]bool)

	closeStream := func(strm *Stream) {
		if strm.origType == FrameHeaders {
			openStreams--
		}

		strmID := strm.ID()

		closedStrms[strm.ID()] = strm.resetByServer
		strms.Del(strm.ID())

		ctxPool.Put(strm.ctx)
		streamPool.Put(strm)

		if sc.debug {
			sc.logger.Printf("Stream destroyed %d. Open streams: %d\n", strmID, openStreams)
		}
	}

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
		if atomic.LoadInt32((*int32)(&sc.state)) != int32(connStateClosed) {
			sc.writeGoAway(sc.lastID, NoError, "graceful shutdown")
		}

		for _, strm := range strms {
			if strm.origType == FrameHeaders && strm.ID() <= sc.lastID {
				return
			}
		}

		sc.writeFrame(closeConnSentinel)
	}

loop:
	for {
		select {
		case <-closerCh:
			closerCh = nil
			// the GOAWAY has been queued by closeIdleConn already; closing
			// the connection through the writeLoop instead of breaking the
			// loop lets the regular teardown close sc.writer once nothing
			// can write to it anymore
			sc.writeFrame(closeConnSentinel)
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
			atomic.StoreInt32((*int32)(&sc.state), int32(connStateDraining))

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

			isClosing := atomic.LoadInt32((*int32)(&sc.state)) == int32(connStateClosed)

			var strm *Stream
			if fr.Stream() <= sc.lastID {
				strm = strms.Search(fr.Stream())
			}

			if strm == nil {
				// if the stream doesn't exist, create it

				if resetByServer, ok := closedStrms[fr.Stream()]; ok {
					switch {
					case resetByServer:
						// RFC 9113 (section 5.1): after sending RST_STREAM the
						// server MUST ignore the frames the client sent before
						// learning about the reset. Their DATA still counts
						// against the connection flow-control window.
						if fr.Type() == FrameData {
							sc.applyDataFlowControl(fr, false)
						}
					case fr.Type() == FramePriority, fr.Type() == FrameResetStream:
						// tolerated on any closed stream
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
					closedStrms[fr.Stream()] = true

					continue
				}

				if fr.Stream() < sc.lastID {
					sc.writeGoAway(fr.Stream(), ProtocolError, "stream ID is lower than the latest")
					continue
				}

				strm = NewStream(fr.Stream(), int32(sc.clientWindow))
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

			// a request over MaxRequestBodySize doesn't need the rest of
			// its body: answer with the 413 right away and ask the client
			// to stop sending with a RST_STREAM carrying NO_ERROR
			// (RFC 9113, section 8.1.1); the frames still in flight are
			// absorbed by the reset tolerance above
			if strm.tooLargeBody && strm.State() == StreamStateOpen {
				sc.handleEndRequest(strm)

				strm.resetByServer = true
				sc.writeReset(strm.ID(), NoError)
				strm.SetState(StreamStateClosed)
			}

			switch strm.State() {
			case StreamStateHalfClosed:
				sc.handleEndRequest(strm)
				// we fallthrough because once we send the response
				// the stream is already consumed and thus finished
				fallthrough
			case StreamStateClosed:
				closeStream(strm)
			}

			if isClosing {
				ref := atomic.LoadUint32(&sc.closeRef)
				// if there's no reference, then just close the connection
				if ref == 0 {
					break
				}

				// if we have a ref, then check that all streams previous to that ref are closed
				for _, strm := range strms {
					// if the stream is here, then it's not closed yet
					if strm.origType == FrameHeaders && strm.ID() <= ref {
						continue loop
					}
				}

				// all streams served: flush what's pending and close the
				// connection; readLoop then ends and the regular teardown
				// closes this loop through sc.reader
				sc.writeFrame(closeConnSentinel)
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
func (sc *serverConn) writeGoAwayFrame(strm uint32, code ErrorCode, message string) {
	ga := AcquireFrame(FrameGoAway).(*GoAway)

	fr := AcquireFrameHeader()

	ga.SetStream(strm)
	ga.SetCode(code)
	ga.SetData([]byte(message))

	fr.SetBody(ga)

	sc.writeFrame(fr)

	if sc.debug {
		sc.logger.Printf(
			"%s: GoAway(stream=%d, code=%s): %s\n",
			sc.c.RemoteAddr(), strm, code, message,
		)
	}
}

func (sc *serverConn) writeGoAway(strm uint32, code ErrorCode, message string) {
	sc.writeGoAwayFrame(strm, code, message)

	if strm != 0 {
		atomic.StoreUint32(&sc.closeRef, sc.lastID)
	}

	atomic.StoreInt32((*int32)(&sc.state), int32(connStateClosed))
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
	}

	switch strm.State() {
	case StreamStateIdle:
		if fr.Type() == FrameHeaders {
			strm.SetState(StreamStateOpen)
			if fr.Flags().Has(FlagEndStream) {
				strm.SetState(StreamStateHalfClosed)
			}
		} // TODO: else push promise ...
	case StreamStateReserved:
		// TODO: ...
	case StreamStateOpen:
		if fr.Flags().Has(FlagEndStream) {
			strm.SetState(StreamStateHalfClosed)
		} else if fr.Type() == FrameResetStream {
			strm.SetState(StreamStateClosed)
		}
	case StreamStateHalfClosed:
		// a stream can only go from HalfClosed to Closed if the client
		// sends a ResetStream frame.
		if fr.Type() == FrameResetStream {
			strm.SetState(StreamStateClosed)
		}
	case StreamStateClosed:
	}
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

			// calling req.URI() triggers a URL parsing, so because of that we need to delay the URL parsing.
			strm.ctx.Request.URI().SetSchemeBytes(strm.scheme)

			if err := validateRequestHeaders(strm, fr); err != nil {
				return err
			}

			// a declared length over the limit rejects the request before
			// buffering anything
			if strm.expectedContentLength > int64(sc.maxRequestBodySize) {
				strm.tooLargeBody = true
			}
		}
	case FrameData:
		if !strm.headersFinished {
			return NewGoAwayError(ProtocolError, "stream didn't end the headers")
		}

		if strm.State() >= StreamStateHalfClosed {
			return NewGoAwayError(StreamClosedError, "stream closed")
		}

		sc.applyDataFlowControl(fr, true)

		data := fr.Body().(*Data).Data()

		switch {
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
			strm.expectedContentLength != int64(len(strm.ctx.Request.Body())) {

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

		if atomic.AddInt64(&strm.window, win) >= 1<<31-1 {
			return NewResetStreamError(FlowControlError, "window is above limits")
		}
	default:
		return NewGoAwayError(ProtocolError, "invalid frame")
	}

	return err
}

func (sc *serverConn) handleHeaderFrame(strm *Stream, fr *FrameHeader) error {
	if strm.headersFinished && !fr.Flags().Has(FlagEndStream|FlagEndHeaders) {
		// TODO handle trailers
		return NewGoAwayError(ProtocolError, "stream not open")
	}

	if headerFrame, ok := fr.Body().(*Headers); ok && headerFrame.Stream() == strm.ID() {
		return NewGoAwayError(ProtocolError, "stream that depends on itself")
	}

	b := append(strm.previousHeaderBytes, fr.Body().(FrameWithHeaders).Headers()...)
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

		k, v := hf.KeyBytes(), hf.ValueBytes()

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

// validateRequestHeaders enforces the rules that can only be checked once
// the header block ends: mandatory pseudo-header fields (RFC 9113, section
// 8.3.1) and a content-length coherent with END_STREAM (section 8.1.1).
// Violations recorded while decoding are surfaced here as well, now that
// the HPACK state is synchronized: the malformed request resets the stream
// instead of killing the connection.
func validateRequestHeaders(strm *Stream, fr *FrameHeader) error {
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

		if fr.Flags().Has(FlagEndStream) && strm.expectedContentLength > 0 {
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

// handleEndRequest dispatches the finished request to the handler.
func (sc *serverConn) handleEndRequest(strm *Stream) {
	ctx := strm.ctx
	ctx.Request.Header.SetProtocolBytes(StringHTTP2)

	if strm.tooLargeBody {
		// same as fasthttp: the error goes through the configured
		// ErrorHandler, which can customize the response
		if sc.errorHandler != nil {
			sc.errorHandler(ctx, fasthttp.ErrBodyTooLarge)
		} else {
			ctx.Error(fasthttp.ErrBodyTooLarge.Error(), fasthttp.StatusRequestEntityTooLarge)
		}
	} else {
		sc.h(ctx)
	}

	hasBody := ctx.Response.IsBodyStream() || len(ctx.Response.Body()) > 0

	fr := AcquireFrameHeader()
	fr.SetStream(strm.ID())

	h := AcquireFrame(FrameHeaders).(*Headers)
	h.SetEndHeaders(true)
	h.SetEndStream(!hasBody)

	fr.SetBody(h)

	fasthttpResponseHeaders(h, &sc.enc, &ctx.Response)

	sc.writeFrame(fr)

	if hasBody {
		if ctx.Response.IsBodyStream() {
			streamWriter := acquireStreamWrite()
			streamWriter.strm = strm
			streamWriter.writer = sc.writer
			streamWriter.size = int64(ctx.Response.Header.ContentLength())
			_ = ctx.Response.BodyWriteTo(streamWriter)
			releaseStreamWrite(streamWriter)
		} else {
			sc.writeData(strm, ctx.Response.Body())
		}
	}
}

var (
	copyBufPool = sync.Pool{
		New: func() any {
			return make([]byte, 1<<14) // max frame size 16384
		},
	}
	streamWritePool = sync.Pool{
		New: func() any {
			return &streamWrite{}
		},
	}
)

type streamWrite struct {
	size    int64
	written int64
	strm    *Stream
	writer  chan<- *FrameHeader
}

func acquireStreamWrite() *streamWrite {
	v := streamWritePool.Get()
	if v == nil {
		return &streamWrite{}
	}
	return v.(*streamWrite)
}

func releaseStreamWrite(streamWrite *streamWrite) {
	streamWrite.Reset()
	streamWritePool.Put(streamWrite)
}

func (s *streamWrite) Reset() {
	s.size = 0
	s.written = 0
	s.strm = nil
	s.writer = nil
}

func (s *streamWrite) Write(body []byte) (n int, err error) {
	if (s.size <= 0 && s.written > 0) || (s.size > 0 && s.written >= s.size) {
		return 0, errors.New("writer closed")
	}

	step := 1 << 14 // max frame size 16384

	n = len(body)
	s.written += int64(n)

	end := s.size < 0 || s.written >= s.size
	for i := 0; i < n; i += step {
		if i+step >= n {
			step = n - i
		}

		fr := AcquireFrameHeader()
		fr.SetStream(s.strm.ID())

		data := AcquireFrame(FrameData).(*Data)
		data.SetEndStream(end && i+step == n)
		data.SetPadding(false)
		data.SetData(body[i : step+i])

		fr.SetBody(data)

		s.writer <- fr
	}

	return len(body), nil
}

func (s *streamWrite) ReadFrom(r io.Reader) (num int64, err error) {
	buf := copyBufPool.Get().([]byte)

	if s.size < 0 {
		lrSize := limitedReaderSize(r)
		if lrSize >= 0 {
			s.size = lrSize
		}
	}

	var n int
	for {
		n, err = r.Read(buf[0:])
		if n <= 0 && err == nil {
			err = errors.New("BUG: io.Reader returned 0, nil")
		}

		// A read may return data together with io.EOF, so the bytes must be
		// flushed before reacting to the error.
		eof := errors.Is(err, io.EOF)
		num += int64(n)
		// The stream ends when the reader is exhausted or the declared size
		// has been reached.
		end := eof || (s.size >= 0 && num >= s.size)

		if n > 0 || end {
			fr := AcquireFrameHeader()
			fr.SetStream(s.strm.ID())

			data := AcquireFrame(FrameData).(*Data)
			data.SetEndStream(end)
			data.SetPadding(false)
			data.SetData(buf[:n])
			fr.SetBody(data)

			s.writer <- fr
		}

		if end {
			// io.EOF is the expected, non-error end of the stream.
			if eof {
				err = nil
			}

			break
		}

		if err != nil {
			break
		}
	}

	copyBufPool.Put(buf)

	return num, err
}

func (sc *serverConn) writeData(strm *Stream, body []byte) {
	step := 1 << 14 // max frame size 16384
	if strm.window > 0 && step > int(strm.window) {
		step = int(strm.window)
	}

	for i := 0; i < len(body); i += step {
		if i+step >= len(body) {
			step = len(body) - i
		}

		fr := AcquireFrameHeader()
		fr.SetStream(strm.ID())

		data := AcquireFrame(FrameData).(*Data)
		data.SetEndStream(i+step == len(body))
		data.SetPadding(false)
		data.SetData(body[i : step+i])

		fr.SetBody(data)

		sc.writeFrame(fr)
	}
}

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
			// TODO: sc.writer.err <- err
			return
		}
	}
}

func (sc *serverConn) handleSettings(st *Settings) {
	st.CopyTo(&sc.clientS)
	sc.enc.SetMaxTableSize(sc.clientS.HeaderTableSize())

	// atomically update the new window
	atomic.StoreInt64(&sc.clientWindow, int64(sc.clientS.MaxWindowSize()))

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

	for k, v := range res.Header.All() {
		hf.SetBytes(k, v)
		ToLower(hf.KeyBytes())
		dst.AppendHeaderField(hp, hf, false)
	}
}

func limitedReaderSize(r io.Reader) int64 {
	lr, ok := r.(*io.LimitedReader)
	if !ok {
		return -1
	}
	return lr.N
}
