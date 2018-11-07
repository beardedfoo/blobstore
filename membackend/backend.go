// Package membackend provides an in-memory storage backend for a blobstore
package membackend

import (
	"fmt"

	"github.com/beardedfoo/blobstore/backend"
)

// New returns a new volatile memory backend for a blobstore
func New() backend.Backend {
	backend := memBackend(make(map[string][]byte))
	return &backend
}

// Use a map to store blobs in memory
type memBackend map[string][]byte

// Get returns a stored blob
func (b memBackend) Get(blobID string, _ backend.MACFunc) ([]byte, error) {
	if _, ok := b[blobID]; !ok {
		return nil, fmt.Errorf("no such blobID in map")
	}
	return b[blobID], nil
}

// Put sets the value for a blob in the store
func (b memBackend) Put(blobID string, data []byte, _ backend.MACFunc) error {
	b[blobID] = data
	return nil
}

// Verify returns true with no error if a blob is stored
func (b memBackend) Verify(blobID string, _ backend.MACFunc) (bool, error) {
	_, ok := b[blobID]
	return ok, nil
}
