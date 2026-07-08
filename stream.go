package http2

import (
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/valyala/fasthttp"
)

type StreamState int8

const (
	StreamStateIdle StreamState = iota
	StreamStateReserved
	StreamStateOpen
	StreamStateHalfClosed
	StreamStateClosed
)

func (ss StreamState) String() string {
	switch ss {
	case StreamStateIdle:
		return "Idle"
	case StreamStateReserved:
		return "Reserved"
	case StreamStateOpen:
		return "Open"
	case StreamStateHalfClosed:
		return "HalfClosed"
	case StreamStateClosed:
		return "Closed"
	}

	return "IDK"
}

type Stream struct {
	id uint32
	// window tracks the peer's per-stream send window relative to its
	// INITIAL_WINDOW_SIZE: WINDOW_UPDATEs add to it and sent DATA
	// subtracts, so the available window is clientInitialWindow + window
	// at any moment — which is exactly the RFC 9113 (section 6.9.2)
	// semantics for INITIAL_WINDOW_SIZE changes, retroactive ones and
	// negative windows included.
	window              atomic.Int64
	state               StreamState
	ctx                 *fasthttp.RequestCtx
	scheme              []byte
	previousHeaderBytes []byte

	// keeps track of the number of header blocks received
	headerBlockNum int

	// original type
	origType  FrameType
	startedAt time.Time
	// headersFinished reports that no header block is currently open: the
	// last HEADERS frame (initial or trailer) received its END_HEADERS
	headersFinished bool
	// trailers marks that a trailer section started: the fields of the
	// current header block belong to the trailers (RFC 9113, section 8.1)
	trailers bool
	// endStreamPending remembers an END_STREAM flag seen on a HEADERS
	// frame: it only takes effect once the header block is complete, so
	// that requests ending in CONTINUATION or trailer frames aren't
	// dispatched before all their fields are decoded
	endStreamPending bool

	// dispatched marks a stream whose handler already runs on its own
	// goroutine, reading the body from the pipe while the DATA frames
	// are still arriving (Server.StreamRequestBody); the response is
	// written when the handler comes back through handlerDone. While
	// dispatched, the frame loop must not touch strm.ctx: the handler
	// owns it.
	dispatched bool
	// body is the pipe feeding a dispatched handler
	body *requestBody
	// recvBody counts the DATA payload bytes received on the stream
	recvBody int64

	// response send state, flow controlled by the peer's windows
	// (RFC 9113, section 5.2):
	//
	// sending marks a stream whose response body hasn't been fully
	// queued yet; the stream stays alive until the peer's windows let
	// the rest through
	sending bool
	// sendBody is the unsent remainder of a buffered response body
	sendBody []byte
	// sendReader sources a streamed response body; sendSize is what
	// remains of its declared size, or negative when unknown
	sendReader io.Reader
	sendSize   int64
	// sendDone marks the body fully queued, END_STREAM included
	sendDone bool
	// sendTrailer keeps the trailer HEADERS for after the body
	sendTrailer bool
	// afterSendReset asks for a NO_ERROR reset once the response has
	// drained: the request body was still in flight when the handler
	// answered
	afterSendReset bool

	// header validation state (RFC 9113, sections 8.1 to 8.3)
	pseudoSeen         uint8
	regularHeadersSeen bool
	headerViolation    string
	// expectedContentLength is the content-length header value,
	// -1 when the request doesn't carry one
	expectedContentLength int64
	// tooLargeBody marks a request over the server's MaxRequestBodySize:
	// it is answered with 413 without reaching the handler, and the stream
	// is reset with NO_ERROR to stop the rest of the upload
	tooLargeBody bool
	// headerListSize accumulates the decoded size of the request header
	// list as RFC 9113 (section 10.5) defines it: name length + value
	// length + 32 per field
	headerListSize int
	// headerBlockSize accumulates the raw (compressed) header block bytes
	// received across HEADERS and CONTINUATION frames
	headerBlockSize int
	// tooLargeHeaders marks a request whose header list exceeds the
	// server's limit: it is answered with 431 without reaching the handler
	tooLargeHeaders bool
	// resetByServer records that the server sent a RST_STREAM for this
	// stream: frames the client sent before learning about the reset must
	// be ignored instead of being treated as a connection error
	// (RFC 9113, section 5.1)
	resetByServer bool
}

// recordViolation stores the first malformed-request violation found while
// decoding a header block. The block keeps being decoded so the HPACK state
// stays synchronized; the stream is reset once the block ends.
func (s *Stream) recordViolation(msg string) {
	if s.headerViolation == "" {
		s.headerViolation = msg
	}
}

var streamPool = sync.Pool{
	New: func() any {
		return &Stream{}
	},
}

func NewStream(id uint32, win int32) *Stream {
	strm := streamPool.Get().(*Stream)
	strm.id = id
	strm.window.Store(int64(win))
	strm.state = StreamStateIdle
	strm.headersFinished = false
	strm.trailers = false
	strm.endStreamPending = false
	strm.dispatched = false
	strm.body = nil
	strm.recvBody = 0
	strm.sending = false
	strm.sendBody = nil
	strm.sendReader = nil
	strm.sendSize = 0
	strm.sendDone = false
	strm.sendTrailer = false
	strm.afterSendReset = false
	strm.startedAt = time.Time{}
	strm.previousHeaderBytes = strm.previousHeaderBytes[:0]
	strm.ctx = nil
	strm.scheme = append(strm.scheme[:0], "https"...)
	strm.origType = 0
	strm.headerBlockNum = 0
	strm.pseudoSeen = 0
	strm.regularHeadersSeen = false
	strm.headerViolation = ""
	strm.expectedContentLength = -1
	strm.tooLargeBody = false
	strm.headerListSize = 0
	strm.headerBlockSize = 0
	strm.tooLargeHeaders = false
	strm.resetByServer = false

	return strm
}

func (s *Stream) ID() uint32 {
	return s.id
}

func (s *Stream) SetID(id uint32) {
	s.id = id
}

func (s *Stream) State() StreamState {
	return s.state
}

func (s *Stream) SetState(state StreamState) {
	s.state = state
}

func (s *Stream) Window() int32 {
	return int32(s.window.Load())
}

func (s *Stream) SetWindow(win int32) {
	s.window.Store(int64(win))
}

func (s *Stream) IncrWindow(win int32) {
	s.window.Add(int64(win))
}

func (s *Stream) Ctx() *fasthttp.RequestCtx {
	return s.ctx
}

func (s *Stream) SetData(ctx *fasthttp.RequestCtx) {
	s.ctx = ctx
}
