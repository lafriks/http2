package http2

import "testing"

func BenchmarkValidateRegularField(b *testing.B) {
	strm := NewStream(1, 0)

	headers := [][2][]byte{
		{[]byte("accept"), []byte("text/html,application/xhtml+xml")},
		{[]byte("accept-encoding"), []byte("gzip, deflate, br")},
		{[]byte("accept-language"), []byte("en-US,en;q=0.9")},
		{[]byte("cookie"), []byte("session=abc123; theme=dark")},
		{[]byte("cache-control"), []byte("no-cache")},
		{[]byte("x-forwarded-for"), []byte("192.0.2.1")},
		{[]byte("content-length"), []byte("123")},
		{[]byte("te"), []byte("trailers")},
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, kv := range headers {
			validateRegularField(strm, kv[0], kv[1])
		}
		strm.headerViolation = ""
		strm.expectedContentLength = -1
	}
}
