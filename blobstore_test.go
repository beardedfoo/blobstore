package blobstore_test

import (
	"bytes"
	"crypto/rand"
	"io"
	"log"
	"testing"

	"github.com/beardedfoo/blobstore"
	"github.com/beardedfoo/blobstore/membackend"
	"github.com/beardedfoo/masterkey"
)

// Ensure the stored data is encrypted
func TestCrypto(t *testing.T) {
	// Create a random 4096-bit key
	m := make([]byte, 4096)
	if n, _ := io.ReadFull(rand.Reader, m); n != len(m) {
		t.Fatalf("error creating key material")
	}
	key := masterkey.New(m)

	// Create a memory backed blobstore using the key
	backend := membackend.New()
	b := blobstore.New(backend, key)

	// Generate some random plaintext
	plaintext := make([]byte, 1024)
	if n, _ := io.ReadFull(rand.Reader, plaintext); n != len(plaintext) {
		t.Fatalf("error creating plaintext")
	}
	log.Printf("plaintext: %v", plaintext)

	// Place the plaintext in the blobstore
	blobID, err := b.Put(plaintext)
	if err != nil {
		t.Fatalf("error uploading plaintext to blobstore: %v", err)
	}

	// Access the backend directly to retrieve the raw data stored
	stored, err := backend.Get(blobID, nil)
	if err != nil {
		t.Fatalf("error fetching data from backend: %v", err)
	}
	log.Printf("stored: %v", stored)

	// Check whether the stored data is the same as the raw data
	if bytes.Equal(plaintext, stored) {
		t.Fatalf("stored data does not differ from plaintext")
	}
}
