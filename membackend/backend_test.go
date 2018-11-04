package membackend

import (
	"testing"
)

func TestMemBackend(t *testing.T) {
	// Create a memBackend
	b := New()

	// Try to verify a missing blob
	if ok, _ := b.Verify("foo", nil); ok {
		t.Fatalf("returned true on non-existent blob")
	}

	// Try to get a missing blob
	if _, err := b.Get("foo", nil); err == nil {
		t.Fatalf("expected error from Get(), but got none")
	}

	// Set a value in the store
	if err := b.Put("foo", []byte("bar"), nil); err != nil {
		t.Fatalf("err in Put(): %v", err)
	}

	// Retrieve that value
	data, err := b.Get("foo", nil)
	if err != nil {
		t.Fatalf("err in Get(): %v", err)
	}

	// Check for corruption
	if string(data) != "bar" {
		t.Fatalf("bad data returned from Get()")
	}
}
