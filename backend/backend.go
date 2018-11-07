// Package backend provides common definitions for blobstore backends
package backend

// MACFunc defines how a blobstore will pass a utility function to the backends for computing secure hashes
type MACFunc func(data []byte) (checksum string, err error)

// Backend interfaces provide blob storage
type Backend interface {
	// Verify returns true with no error if the blob `blobID` is correctly stored
	Verify(blobID string, m MACFunc) (ok bool, err error)

	// Put places a blob into storage
	Put(blobID string, data []byte, m MACFunc) error

	// Get retrieves a blob from storage
	Get(blobID string, m MACFunc) (data []byte, err error)
}
