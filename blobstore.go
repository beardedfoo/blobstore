package blobstore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/s3"

	"github.com/apexskier/cryptoPadding"
)

// Use a library for plaintext padding
var pkcs7 cryptoPadding.PKCS7

// This is the content-type sent to S3
const contentType = "application/octet-stream"

// The key in which etag HMAC data is stored in object metadata
const etagHmacMetadataKey = "Etag-Hmac"

// ErrCodeS3KeyNotFound defines the error code for when S3 keys are missing
const ErrCodeS3KeyNotFound = "NotFound"

// New returns a Blobstore which uses HMAC-SHA-256 and AES-256-CBC
func New(bucket string, svc *s3.S3, key string) (Blobstore, error) {
	// Decode the encryption key
	binKey, err := hex.DecodeString(key)
	if err != nil {
		return nil, err
	}

	// Ensure 256-bit encryption is used
	if len(binKey) != 32 {
		return nil, fmt.Errorf("key size must be 256-bits")
	}

	// Build the block cipher on the specified key
	blockCipher, err := aes.NewCipher(binKey)
	if err != nil {
		return nil, fmt.Errorf("error creating blockCipher: %v", err)
	}

	return s3Blobstore{
		bucket: bucket,
		s3:     svc,
		hasher: hmac.New(sha256.New, binKey),
		block:  blockCipher,
	}, nil
}

// Blobstore objects allow uploading and downloading of binary blobs
type Blobstore interface {
	Has(blobID string) (exists bool, err error)
	Put(data []byte) (blobID string, err error)
	Get(blobID string) (data []byte, err error)
}

// s3Blobstore allows access to an S3 bucket as an encrypted blobstore
type s3Blobstore struct {
	bucket string
	s3     *s3.S3
	key    []byte
	hasher hash.Hash
	block  cipher.Block
}

// Upload data into the blobstore, returning the blobID for the data
func (b s3Blobstore) Put(data []byte) (string, error) {
	// Ensure the block size is right
	if b.block.BlockSize() != 16 {
		return "", fmt.Errorf("unexpected cipher block size: %v", b.block.BlockSize())
	}

	// Compute the checksum of this data and use it as the blobID
	b.hasher.Reset()
	io.Copy(b.hasher, bytes.NewReader(data))
	blobID := hex.EncodeToString(b.hasher.Sum(nil))

	// Check if the object is already in S3, if so we have nothing to do
	exists, err := b.Has(blobID)
	if err != nil {
		return "", fmt.Errorf("error checking for blob %v: %v", blobID, err)
	}
	if exists {
		return blobID, nil
	}

	// Apply PKCS#7 padding to the plaintext to allow for irregular block sizes
	ciphertext, err := pkcs7.Pad(data, b.block.BlockSize())
	if err != nil {
		return "", fmt.Errorf("PKCS#7 error: %v", err)
	}

	// Make an IV for CBC mode
	iv := make([]byte, b.block.BlockSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("error generating iv: %v", err)
	}

	// Encrypt the data with CBC mode
	mode := cipher.NewCBCEncrypter(b.block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	// Prepend the IV to the ciphertext
	ciphertext = append(iv, ciphertext...)

	// Compute the expected ETag from S3 to validate the upload later
	ciphertextMD5 := md5.Sum(ciphertext)
	validETag := hex.EncodeToString(ciphertextMD5[:])

	// Compute the HMAC for the ETag, to allow authentication of the data without downloading it
	b.hasher.Reset()
	io.Copy(b.hasher, bytes.NewReader(ciphertextMD5[:]))
	etagHMAC := b.hasher.Sum(nil)

	// Include the etagHmac encoded in hex as metadata for the S3 object
	metadata := map[string]*string{
		etagHmacMetadataKey: aws.String(hex.EncodeToString(etagHMAC)),
	}

	// Upload the ciphertext to S3
	resp, err := b.s3.PutObject(&s3.PutObjectInput{
		Bucket:               aws.String(b.bucket),
		Key:                  aws.String(blobID),
		ACL:                  aws.String("private"),
		Body:                 bytes.NewReader(ciphertext),
		ContentLength:        aws.Int64(int64(len(ciphertext))),
		ContentType:          aws.String(contentType),
		ContentDisposition:   aws.String("attachment"),
		ServerSideEncryption: aws.String("AES256"),
		Metadata:             metadata,
	})
	if err != nil {
		return "", fmt.Errorf("PutObject failed: %v", err)
	}

	// Check that the returned ETag is correct (should be the MD5)
	if validETag != strings.Trim(*resp.ETag, "\"") {
		return "", fmt.Errorf("invalid etag after upload")
	}

	return blobID, nil
}

func (b s3Blobstore) Has(blobID string) (bool, error) {
	// Download the metadata from S3
	resp, err := b.s3.HeadObject(&s3.HeadObjectInput{
		Bucket: aws.String(b.bucket),
		Key:    aws.String(blobID),
	})

	// Process any error from the head request
	if err != nil {
		// It is acceptable and expected that this could error because of missing keys
		if awsErr, ok := err.(awserr.Error); ok {
			// If the key is missing from the s3 bucket return false indicating the blob is not present
			if awsErr.Code() == ErrCodeS3KeyNotFound {
				return false, nil
			}
		}
		return false, fmt.Errorf("HeadObject failed for blob %v: %v", blobID, err)
	}

	// Calculate the etag HMAC for this blob
	etagBytes, err := hex.DecodeString(strings.Trim(*resp.ETag, "\""))
	if err != nil {
		return false, fmt.Errorf("error decoding ETag %v: %v", *resp.ETag, err)
	}
	b.hasher.Reset()
	io.Copy(b.hasher, bytes.NewReader(etagBytes))
	validEtagHmac := hex.EncodeToString(b.hasher.Sum(nil))

	// Authenticate the blob using the etag HMAC metadata
	if _, ok := resp.Metadata[etagHmacMetadataKey]; !ok {
		return false, fmt.Errorf("missing etag HMAC metadata for blob %v: %v", blobID, resp.Metadata)
	}
	etagHmac := *resp.Metadata[etagHmacMetadataKey]
	if validEtagHmac != etagHmac {
		return false, fmt.Errorf("bad etagHmac for blob %v: %v != %v", blobID, etagHmac, validEtagHmac)
	}

	return true, nil
}

func (b s3Blobstore) Get(blobID string) ([]byte, error) {
	// Download the data from S3
	resp, err := b.s3.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(b.bucket),
		Key:    aws.String(blobID),
	})

	// To prevent a memory leak, close any response body received
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	// Process any error from the data download
	if err != nil {
		return nil, fmt.Errorf("GetObject failed for blob %v: %v", blobID, err)
	}

	// Read the data from the body
	encryptedBlob, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read body from GetObject call: %v", err)
	}

	// Calculate the etag HMAC for this blob
	etagBytes, err := hex.DecodeString(strings.Trim(*resp.ETag, "\""))
	if err != nil {
		return nil, fmt.Errorf("error decoding ETag %v: %v", *resp.ETag, err)
	}
	b.hasher.Reset()
	io.Copy(b.hasher, bytes.NewReader(etagBytes))
	validEtagHmac := hex.EncodeToString(b.hasher.Sum(nil))

	// Authenticate the blob using the etag-hmac metadata
	if _, ok := resp.Metadata[etagHmacMetadataKey]; !ok {
		return nil, fmt.Errorf("missing etag HMAC metadata for blob %v: %v", blobID, resp.Metadata)
	}
	etagHmac := *resp.Metadata[etagHmacMetadataKey]
	if validEtagHmac != etagHmac {
		return nil, fmt.Errorf("bad etagHmac for blob %v: %v != %v", blobID, etagHmac, validEtagHmac)
	}

	// Separate the encrypted blob into the IV & ciphertext
	iv := encryptedBlob[:b.block.BlockSize()]
	ciphertext := encryptedBlob[b.block.BlockSize():]

	// Perform CBC decryption
	mode := cipher.NewCBCDecrypter(b.block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	// Reverse PKCS#7 padding to allow for irregular block sizes
	plaintext, err := pkcs7.Unpad(ciphertext, b.block.BlockSize())
	if err != nil {
		return nil, fmt.Errorf("PCKS#7 error: %v", err)
	}

	// Verify the downloaded data against the blobID
	b.hasher.Reset()
	io.Copy(b.hasher, bytes.NewReader(plaintext))
	checksum := hex.EncodeToString(b.hasher.Sum(nil))
	if checksum != blobID {
		return nil, fmt.Errorf("bad checksum in blob %v: %v", blobID, checksum)
	}

	return plaintext, nil
}
