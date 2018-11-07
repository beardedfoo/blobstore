package backend

// MACFunc defines functions which generate MAC's using secure hashes
type MACFunc func(data []byte) (checksum string, err error)

// Backend interfaces provide blob storage
type Backend interface {
	// Verify returns true with no error if the blob `blobID` is correctly stored
	Verify(blobID string, checksumCallback MACFunc) (ok bool, err error)

	// Put places a blob into storage
	Put(blobID string, data []byte, checksumCallback MACFunc) error

	// Get retrieves a blob from storage
	Get(blobID string, checksum MACFunc) (data []byte, err error)
}
