package s3backend

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/s3"

	"github.com/beardedfoo/blobstore/backend"
)

// This is the content-type sent to S3
const contentType = "application/octet-stream"

// The key in which etag HMAC data is stored in object metadata
const etagMacMetadataKey = "Etag-Mac"

// ErrCodeS3KeyNotFound defines the error code for when S3 keys are missing
const ErrCodeS3KeyNotFound = "NotFound"

// New creates and returns a new blobstore backend in S3
func New(bucket string, svc *s3.S3) backend.Backend {
	return s3Backend{bucket: bucket, svc: svc}
}

// s3Backend is an S3 storage backend for beardedfoo/blobstore
type s3Backend struct {
	bucket string
	svc     *s3.S3
}

// Put uploads a blob into the S3 bucket
func (b s3Backend) Put(blobID string, data []byte, macCallback backend.MACFunc) (error) {
	// Compute the expected ETag from S3 to validate the upload later
	ciphertextMD5 := md5.Sum(data)
	validETag := hex.EncodeToString(ciphertextMD5[:])

	// Compute the HMAC for the ETag, to allow authentication of the data without downloading it
	etagMAC, err := macCallback(ciphertextMD5[:])
	if err != nil {
		return fmt.Errorf("error generating etagMAC: %v", err)
	}

	// Include the etagMAC as metadata for the S3 object
	metadata := map[string]*string{
		etagMacMetadataKey: aws.String(etagMAC),
	}

	// Upload the ciphertext to S3
	resp, err := b.svc.PutObject(&s3.PutObjectInput{
		Bucket:               aws.String(b.bucket),
		Key:                  aws.String(blobID),
		ACL:                  aws.String("private"),
		Body:                 bytes.NewReader(data),
		ContentLength:        aws.Int64(int64(len(data))),
		ContentType:          aws.String(contentType),
		ContentDisposition:   aws.String("attachment"),
		ServerSideEncryption: aws.String("AES256"),
		Metadata:             metadata,
	})
	if err != nil {
		return fmt.Errorf("PutObject failed: %v", err)
	}

	// Check that the returned ETag is correct (should be the MD5)
	if validETag != strings.Trim(*resp.ETag, "\"") {
		return fmt.Errorf("invalid etag after upload")
	}

	return nil
}

// Verify returns true with no error if the blob `blobID` is stored intact in the S3 bucket
func (b s3Backend) Verify(blobID string, macCallback backend.MACFunc) (bool, error) {
	// Download the metadata from S3
	resp, err := b.svc.HeadObject(&s3.HeadObjectInput{
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

	// Calculate the etag MAC (an authenticated checksum) for this blob
	etagBytes, err := hex.DecodeString(strings.Trim(*resp.ETag, "\""))
	if err != nil {
		return false, fmt.Errorf("error decoding ETag %v: %v", *resp.ETag, err)
	}
	validEtagMac, err := macCallback(etagBytes)
	if err != nil {
		return false, fmt.Errorf("error in macCallback: %v", err)
	}

	// Authenticate the blob using the etag MAC metadata
	if _, ok := resp.Metadata[etagMacMetadataKey]; !ok {
		return false, fmt.Errorf("missing etag HMAC metadata for blob %v: %v", blobID, resp.Metadata)
	}
	etagMac := *resp.Metadata[etagMacMetadataKey]
	if validEtagMac != etagMac {
		return false, fmt.Errorf("bad etagMac for blob %v: %v != %v", blobID, etagMac, validEtagMac)
	}

	return true, nil
}

// Get retrieves a blob from S3
func (b s3Backend) Get(blobID string, macCallback backend.MACFunc) ([]byte, error) {
	// Download the data from S3
	resp, err := b.svc.GetObject(&s3.GetObjectInput{
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
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read body from GetObject call: %v", err)
	}

	// Calculate the etag HMAC for this blob
	etagBytes, err := hex.DecodeString(strings.Trim(*resp.ETag, "\""))
	if err != nil {
		return nil, fmt.Errorf("error decoding ETag %v: %v", *resp.ETag, err)
	}
	validEtagMac, err := macCallback(etagBytes)
	if err != nil {
		return nil, fmt.Errorf("error in macCallback: %v", err)
	}

	// Authenticate the blob using the etag-hmac metadata
	if _, ok := resp.Metadata[etagMacMetadataKey]; !ok {
		return nil, fmt.Errorf("missing etag HMAC metadata for blob %v: %v", blobID, resp.Metadata)
	}
	etagMac := *resp.Metadata[etagMacMetadataKey]
	if validEtagMac != etagMac {
		return nil, fmt.Errorf("bad etagMac for blob %v: %v != %v", blobID, etagMac, validEtagMac)
	}

	return data, nil
}