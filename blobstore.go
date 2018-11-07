package blobstore

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/beardedfoo/blobstore/backend"
	"github.com/beardedfoo/masterkey"
)

// Authenticate hashing operations with a 256-bit sub-const hmacSubKeyID = "checksum"
const hmacSubKeyID = "checksum"
const hmacKeySize = 32

// New returns a Blobstore which uses HMAC-SHA-256 and ChaCha20
func New(b backend.Backend, key masterkey.MasterKey) Blobstore {
	return Blobstore{
		masterKey: key,
		backend: b,
	}
}

// Blobstore provides secure access to a blobstore through a backend storage implementation
type Blobstore struct {
	masterKey masterkey.MasterKey
	backend backend.Backend
}

func (b Blobstore) checksum(data []byte) (string, error) {
	// Get the key for HMAC operations
	hmacKey, err := b.masterKey.SubKey(hmacSubKeyID, hmacKeySize)
	if err != nil {
		return "", fmt.Errorf("error generating hmac material: %v", err)
	}

	// Compute the checksum of this data and return it
	checksum := hmac.New(sha256.New, hmacKey)
	io.Copy(checksum, bytes.NewReader(data))
	return hex.EncodeToString(checksum.Sum(nil)), nil
}

// Encrypt data to be stored in the blobstore
func (b Blobstore) encrypt(subKeyID string, plaintext []byte) ([]byte, error) {
	// Get the encryption key specified
	encKey, err := b.masterKey.SubKey(subKeyID, chacha20poly1305.KeySize)
	if err != nil {
		return nil, fmt.Errorf("error generating key material: %v", err)
	}
	
	// Create a new ChaCha20-Poly1305 cipher
	aead, err := chacha20poly1305.New(encKey)
	if err != nil {
		return nil, fmt.Errorf("error creating cipher: %v", err)
	}

	// Get the nonce for this blob, to be used with the cipher
	nonce, err := b.masterKey.SubKey("nonce-"+subKeyID, chacha20poly1305.NonceSize)
	if err != nil {
		return nil, fmt.Errorf("error generating nonce material: %v", err)
	}

	// Encrypt the data in AEAD mode
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt data stored by the blobstore
func (b Blobstore) decrypt(subKeyID string, ciphertext []byte) ([]byte, error) {
	encKey, err := b.masterKey.SubKey(subKeyID, chacha20poly1305.KeySize)
	if err != nil {
		return nil, fmt.Errorf("error generating key material: %v", err)
	}

	// Create a new ChaCha20-Poly1305 cipher
	aead, err := chacha20poly1305.New(encKey)
	if err != nil {
		return nil, fmt.Errorf("error creating cipher: %v", err)
	}

	// Get the nonce for this blob, to be used with the cipher
	nonce, err := b.masterKey.SubKey("nonce-"+subKeyID, chacha20poly1305.NonceSize)
	if err != nil {
		return nil, fmt.Errorf("error generating nonce material: %v", err)
	}

	// Decrypt the data in AEAD mode
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("error in cipher: %v", err)
	}
	return plaintext, nil
}

// Put encrypts and stores a blob, returning the blobID for the data
func (b Blobstore) Put(data []byte) (string, error) {
	// Use the checksum of the data as the blobID
	blobID, err := b.checksum(data)
	if err != nil {
		return "", fmt.Errorf("error computing checksum: %v", err)
	}

	// Check if the object is already in S3, if so we have nothing to do
	ok, err := b.backend.Verify(blobID, b.checksum)
	if err != nil {
		return "", fmt.Errorf("error checking for blob %v: %v", blobID, err)
	}
	if ok {
		return blobID, nil
	}

	// Encrypt the data
	ciphertext, err := b.encrypt(blobID, data)
	if err != nil {
		return "", fmt.Errorf("error encrypting blob: %v", err)
	}

	// Store the ciphertext in the backend
	if err := b.backend.Put(blobID, ciphertext, b.checksum); err != nil {
		return "", fmt.Errorf("backend error: %v", err)
	}

	return blobID, nil
}

// Get retrieves and decrypts a blob from storage
func (b Blobstore) Get(blobID string) ([]byte, error) {
	// Fetch the ciphertext from storage
	ciphertext, err := b.backend.Get(blobID, b.checksum)

	// Decrypt the blob
	plaintext, err := b.decrypt(blobID, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("error decrypting blob: %v", err)
	}

	// Verify the downloaded data against the blobID
	checksum, err := b.checksum(plaintext)
	if err != nil {
		return nil, fmt.Errorf("error computing checksum: %v", err)
	}
	if checksum != blobID {
		return nil, fmt.Errorf("bad checksum `in blob %v: %v", blobID, checksum)
	}

	return plaintext, nil
}
