package http2

import (
	"errors"
	"io"
	"sync"

	"github.com/valyala/fasthttp"
)

// errBodyStreamClosed terminates a request body pipe whose reader is gone:
// the handler finished (or closed the stream itself) before consuming the
// whole body.
var errBodyStreamClosed = errors.New("request body stream closed")

// bodyRefundThreshold batches the flow-control refunds of consumed body
// bytes: reads smaller than this accumulate before a WINDOW_UPDATE is sent.
const bodyRefundThreshold = 4 << 10

// bodyCompactThreshold caps the consumed prefix kept in the buffer: past
// it the unread bytes are moved down, so a long-lived stream doesn't grow
// the buffer by everything that ever went through it.
const bodyCompactThreshold = 32 << 10

// requestBody is the pipe connecting the connection's frame loop to a
// handler reading a streamed request body (Server.StreamRequestBody).
//
// The frame-loop side never blocks: the buffered bytes stay under the
// stream's receive window because the window is only refunded as the
// handler consumes them, which is also what makes the handler's reading
// pace the client's backpressure. The handler side blocks until data, the
// end of the body or an error arrives.
type requestBody struct {
	mu   sync.Mutex
	cond sync.Cond

	buf []byte
	off int

	// err ends the body once the buffered bytes are consumed: io.EOF for
	// a complete request, io.ErrUnexpectedEOF for resets and teardowns.
	// The first error wins.
	err error

	// pending accumulates consumed bytes until they're worth a refund
	pending int

	// trailer stashes the request trailer fields: the frame loop can't
	// write them into the request header the handler owns, so they're
	// applied from the handler's side once the body reaches EOF
	trailer [][2][]byte

	sc     *serverConn
	strmID uint32
	req    *fasthttp.Request
}

var requestBodyPool = sync.Pool{
	New: func() any {
		rb := &requestBody{}
		rb.cond.L = &rb.mu

		return rb
	},
}

// acquireRequestBody returns a body pipe ready for a stream.
func acquireRequestBody(sc *serverConn, strmID uint32, req *fasthttp.Request) *requestBody {
	rb := requestBodyPool.Get().(*requestBody)
	rb.sc = sc
	rb.strmID = strmID
	rb.req = req

	return rb
}

// releaseRequestBody recycles rb.
func releaseRequestBody(rb *requestBody) {
	rb.buf = rb.buf[:0]
	rb.off = 0
	rb.err = nil
	rb.pending = 0
	rb.trailer = rb.trailer[:0]
	rb.sc = nil
	rb.strmID = 0
	rb.req = nil

	requestBodyPool.Put(rb)
}

// releaseStreamBody detaches a stream's body pipe from its request and
// recycles it.
func releaseStreamBody(strm *Stream) {
	if strm.body == nil {
		return
	}

	strm.ctx.Request.ResetBody()

	releaseRequestBody(strm.body)
	strm.body = nil
}

// write appends a DATA payload for the handler. It never blocks, and the
// bytes are copied because the frame is released when the frame loop moves
// on. Writes after the pipe ended are dropped.
func (rb *requestBody) write(p []byte) {
	rb.mu.Lock()
	if rb.err == nil {
		rb.buf = append(rb.buf, p...)
		rb.cond.Signal()
	}
	rb.mu.Unlock()
}

// addTrailer stashes a trailer field until the EOF read applies it.
func (rb *requestBody) addTrailer(k, v []byte) {
	rb.mu.Lock()
	if rb.err == nil {
		rb.trailer = append(rb.trailer, [2][]byte{
			append([]byte(nil), k...),
			append([]byte(nil), v...),
		})
	}
	rb.mu.Unlock()
}

// closeWithError ends the body: the handler still consumes the buffered
// bytes, then its reads return err. The first error wins.
func (rb *requestBody) closeWithError(err error) {
	rb.mu.Lock()
	if rb.err == nil {
		rb.err = err
	}
	rb.cond.Broadcast()
	rb.mu.Unlock()
}

// Close lets fasthttp's body-stream release (Request.Reset) end the pipe.
func (rb *requestBody) Close() error {
	rb.closeWithError(errBodyStreamClosed)
	return nil
}

func (rb *requestBody) Read(p []byte) (int, error) {
	rb.mu.Lock()

	for rb.off == len(rb.buf) && rb.err == nil {
		rb.cond.Wait()
	}

	if rb.off < len(rb.buf) {
		n := copy(p, rb.buf[rb.off:])
		rb.off += n

		switch {
		case rb.off == len(rb.buf):
			rb.buf = rb.buf[:0]
			rb.off = 0
		case rb.off >= bodyCompactThreshold:
			rb.buf = append(rb.buf[:0], rb.buf[rb.off:]...)
			rb.off = 0
		}

		// the consumed bytes reopen the client's send window (RFC 9113,
		// section 5.2); refunds are batched, and pointless once the
		// stream is ending anyway
		refund := 0
		if rb.err == nil {
			rb.pending += n
			if rb.pending >= bodyRefundThreshold {
				refund, rb.pending = rb.pending, 0
			}
		}
		rb.mu.Unlock()

		if refund > 0 {
			rb.sc.updateWindow(rb.strmID, refund)
		}

		return n, nil
	}

	err := rb.err
	trailer := rb.trailer
	rb.trailer = nil
	rb.mu.Unlock()

	// the body is complete: apply the stashed trailer fields to the
	// request from the reader's side, the goroutine that owns it.
	// AddTrailerBytes rejects the fields RFC 9110 (section 6.5.1) forbids
	// in a trailer section; on a streamed body that surfaces as a read
	// error instead of the buffered path's stream reset.
	if errors.Is(err, io.EOF) {
		for _, kv := range trailer {
			if tErr := rb.req.Header.AddTrailerBytes(kv[0]); tErr != nil {
				rb.mu.Lock()
				rb.err = tErr
				rb.mu.Unlock()

				return 0, tErr
			}

			rb.req.Header.AddBytesKV(kv[0], kv[1])
		}
	}

	return 0, err
}
