package secrets

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestComputeContentHash_NoArgs(t *testing.T) {
	t.Parallel()
	emptyDigest := sha256.Sum256(nil)
	want := hex.EncodeToString(emptyDigest[:])
	if got := ComputeContentHash(); got != want {
		t.Errorf("ComputeContentHash() with no args: got %q, want %q", got, want)
	}
}

func TestComputeContentHash_NoArgsDiffersFromEmptySlice(t *testing.T) {
	t.Parallel()
	// A single zero-length slice still contributes its 8-byte length prefix
	// (all zeros), so it must differ from the no-args case.
	if ComputeContentHash() == ComputeContentHash(nil) {
		t.Fatalf("expected ComputeContentHash() and ComputeContentHash(nil) to differ")
	}
}

func TestComputeContentHash_KnownAnswer(t *testing.T) {
	t.Parallel()
	// Lock down the exact wire format (8-byte big-endian length prefix
	// followed by the value bytes) by hashing the same byte sequence by
	// hand and comparing. Any change to the hashing protocol will break
	// this test and force a deliberate update.
	values := [][]byte{[]byte("ca-cert-bytes"), []byte("ca-crl-bytes")}

	h := sha256.New()
	var lenBuf [8]byte
	for _, v := range values {
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(v)))
		_, _ = h.Write(lenBuf[:])
		_, _ = h.Write(v)
	}
	want := hex.EncodeToString(h.Sum(nil))

	if got := ComputeContentHash(values...); got != want {
		t.Errorf("ComputeContentHash(%q): got %q, want %q", values, got, want)
	}
}

func TestComputeContentHash_DistinguishesBoundaries(t *testing.T) {
	t.Parallel()
	// Without length-prefixing, ("ab", "") and ("a", "b") would produce
	// identical concatenated bytes and therefore identical digests.
	if ComputeContentHash([]byte("ab"), []byte("")) == ComputeContentHash([]byte("a"), []byte("b")) {
		t.Fatalf(`expected different digests for ("ab","") vs ("a","b")`)
	}
}

func TestComputeContentHash_PositionalOrderMatters(t *testing.T) {
	t.Parallel()
	// Argument order is part of the input — swapping must produce a
	// different digest so callers can distinguish e.g. (caCert, crl) from
	// (crl, caCert).
	a := []byte("first")
	b := []byte("second")
	if ComputeContentHash(a, b) == ComputeContentHash(b, a) {
		t.Fatalf("expected order-sensitive digest, but swapping arguments produced the same hash")
	}
}

func TestComputeContentHash_ChangesOnValueUpdate(t *testing.T) {
	t.Parallel()
	if ComputeContentHash([]byte("old-ca")) == ComputeContentHash([]byte("new-ca")) {
		t.Fatalf("expected different digests when value bytes change")
	}
}

func TestComputeContentHash_NilEqualsEmpty(t *testing.T) {
	t.Parallel()
	// nil and []byte{} are both zero-length so they must hash identically
	// (the length prefix is the same and there are no value bytes). This
	// pins the documented behaviour and prevents accidental divergence.
	if ComputeContentHash(nil) != ComputeContentHash([]byte{}) {
		t.Fatalf("expected nil and empty slice to hash identically")
	}
}
