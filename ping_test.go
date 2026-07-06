package http2

import "testing"

// A truncated HPACK integer whose continuation bytes run to the end of the
// buffer must not panic (previously sliced out of bounds at b[i+1:]).
func TestReadIntTruncatedNoPanic(t *testing.T) {
	cases := [][]byte{
		{0xFF, 0xFF},             // prefix all-ones + one dangling continuation byte
		{0xFF, 0x80, 0x80, 0x80}, // multiple dangling continuation bytes
		{0x7F},                   // prefix all-ones with nothing following
	}

	for _, b := range cases {
		rem, _ := readInt(7, b)
		if len(rem) > len(b) {
			t.Fatalf("remaining slice grew: %d > %d", len(rem), len(b))
		}
	}
}

// A header block that ends right after an indexed key (no value bytes) must
// surface an error instead of panicking on b[0].
func TestNextFieldTruncatedValueNoPanic(t *testing.T) {
	// Build directly (not via the pool) to avoid perturbing the shared
	// HPACK pool that other tests rely on.
	hp := &HPACK{
		maxTableSize:         defaultHeaderTableSize,
		maxTableSizeSettings: defaultHeaderTableSize,
	}
	hf := &HeaderField{}

	// 0x41 = literal header field with incremental indexing, name index 1,
	// with no value bytes following.
	if _, err := hp.Next(hf, []byte{0x41}); err == nil {
		t.Fatal("expected error for truncated literal value, got nil")
	}
}

// Ping.CopyTo must copy the receiver into the destination, including data.
func TestPingCopyTo(t *testing.T) {
	src := &Ping{}
	src.SetAck(true)
	src.SetData([]byte{1, 2, 3, 4, 5, 6, 7, 8})

	dst := &Ping{}
	src.CopyTo(dst)

	if !dst.IsAck() {
		t.Fatal("ack not copied to destination")
	}
	for i, b := range []byte{1, 2, 3, 4, 5, 6, 7, 8} {
		if dst.data[i] != b {
			t.Fatalf("data[%d] = %d, want %d", i, dst.data[i], b)
		}
	}
	// The source must be left unchanged.
	if !src.IsAck() {
		t.Fatal("source ack was mutated")
	}
}
