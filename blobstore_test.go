package blobstore

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/beardedfoo/blobstore/membackend"
	"github.com/beardedfoo/masterkey"
)

// Ensure the stored data is encrypted
func TestEncryptedBlobs(t *testing.T) {
	// Create a random 4096-bit key
	m := make([]byte, 4096)
	if n, _ := io.ReadFull(rand.Reader, m); n != len(m) {
		t.Fatalf("error creating key material")
	}
	key := masterkey.New(m)

	// Create a memory backed blobstore using the key
	backend := membackend.New()
	b := New(backend, key)

	// Generate some random plaintext
	plaintext := make([]byte, 1024)
	if n, _ := io.ReadFull(rand.Reader, plaintext); n != len(plaintext) {
		t.Fatalf("error creating plaintext")
	}
	t.Logf("plaintext: %v", plaintext)

	// Place the plaintext in the blobstore
	blobID, err := b.Put(plaintext)
	if err != nil {
		t.Fatalf("error uploading plaintext to blobstore: %v", err)
	}

	// Access the backend directly to retrieve the raw data stored
	ciphertext, err := backend.Get(blobID, nil)
	if err != nil {
		t.Fatalf("error fetching data from backend: %v", err)
	}
	t.Logf("ciphertext: %v", ciphertext)

	// Get the raw encrypted version of the blob
	expectedCiphertext, err := b.encrypt(blobID, plaintext)
	if err != nil {
		t.Fatalf("error encrypting plaintext: %v", err)
	}

	// Ensure the stored data matches the output of the encryption routine
	if !bytes.Equal(ciphertext, expectedCiphertext) {
		t.Fatalf("stored data does not match expected ciphertext")
	}
}

func TestGet(t *testing.T) {
	// Create a random 4096-bit key
	m := make([]byte, 4096)
	if n, _ := io.ReadFull(rand.Reader, m); n != len(m) {
		t.Fatalf("error creating key material")
	}
	key := masterkey.New(m)

	// Create a memory backed blobstore using the key
	backend := membackend.New()
	b := New(backend, key)

	// Generate some random plaintext
	plaintext := make([]byte, 1024)
	if n, _ := io.ReadFull(rand.Reader, plaintext); n != len(plaintext) {
		t.Fatalf("error creating plaintext")
	}
	t.Logf("plaintext: %v", plaintext)

	// Place the plaintext in the blobstore
	blobID, err := b.Put(plaintext)
	if err != nil {
		t.Fatalf("error uploading plaintext to blobstore: %v", err)
	}

	// Ensure the blob can be fetched
	downloaded, err := b.Get(blobID)
	if err != nil {
		t.Fatalf("failed to fetch blob: %v", err)
	}

	// Ensure the downloaded data is the same
	if !bytes.Equal(downloaded, plaintext) {
		t.Fatalf("downloaded data does not match plaintext")
	}
 }
 