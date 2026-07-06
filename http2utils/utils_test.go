package http2utils

import "testing"

// CutPadding on a PADDED frame with an empty payload must return an error
// instead of panicking on payload[0].
func TestCutPaddingEmptyPayload(t *testing.T) {
	if _, err := CutPadding(nil, 0); err == nil {
		t.Fatal("expected error for empty padded payload, got nil")
	}
	if _, err := CutPadding([]byte{}, 0); err == nil {
		t.Fatal("expected error for empty padded payload, got nil")
	}
}

// A well-formed padded payload should still have its padding removed.
func TestCutPaddingValid(t *testing.T) {
	// [padLen=2][data=0xAA,0xBB][pad=0x00,0x00]
	payload := []byte{2, 0xAA, 0xBB, 0x00, 0x00}
	out, err := CutPadding(payload, len(payload))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 2 || out[0] != 0xAA || out[1] != 0xBB {
		t.Fatalf("unexpected data: %v", out)
	}
}
