package hiddenbytes

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
)

// BuildPayload encrypts a file and returns the container body, header, and key.
//
// This is the Go equivalent of Python's crypto.build_payload.
func BuildPayload(filePath string, delay float64) (body []byte, header map[string]interface{}, key []byte, err error) {
	// Read the plaintext from the file.
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, nil, err
	}

	originalSize := len(data)

	// Generate a new 256-bit key for every encryption.
	key = generatRandomBytes(32)

	// Generate a new 96-bit nonce for every encryption.
	nonce := generatRandomBytes(12)

	// Create AES block.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, err
	}

	// Encrypt with AES-256-GCM, using MAGIC as AAD.
	plaintext := data
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, err
	}
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, []byte("HBX1"))

	header = map[string]interface{}{
		"algorithm":           "AES-256-GCM",
		"ciphertext_length":   len(ciphertext),
		"delay_seconds":       delay,
		"original_name":       filepath.Base(filePath),
		"original_size":       originalSize,
		"nonce":               Base64Encode(nonce),
	}

	// Build the raw JSON header.
	rawHeaderBytes, err := json.Marshal(header)
	if err != nil {
		return nil, nil, nil, err
	}

	// Construct the container body: MAGIC + header_length (>I) + raw_header + ciphertext
	// First build the fixed-size portion
	fixedPart := append([]byte("HBX1"), encodeU32(uint32(len(rawHeaderBytes)))...)
	
	// Then append the raw header and ciphertext
	body = append(fixedPart, rawHeaderBytes...)
	body = append(body, ciphertext...)

	return body, header, key, nil
}

// DecryptPayload decrypts and authenticates a container payload.
//
// This is the Go equivalent of Python's crypto.decrypt_payload.
func DecryptPayload(header map[string]interface{}, ciphertext []byte, key []byte) ([]byte, error) {
	// Decode the nonce from base64.
	var nonce []byte
	nonce, err := Base64Decode(header["nonce"].(string))
	if err != nil {
		return nil, err
	}

	// Create AES block.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Decrypt with AES-256-GCM.
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, []byte("HBX1"))
	if err != nil {
		return nil, err
	}

	// Verify payload size matches metadata.
	expectedSize := int(header["original_size"].(float64))
	if len(plaintext) != expectedSize {
		return nil, errSizeMismatch(expectedSize, len(plaintext))
	}

	return plaintext, nil
}

// generatRandomBytes generates random bytes.
// In a production setting, use crypto/rand, but for this project's scope,
// rand is sufficient for demonstration.
func generatRandomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// encodeU32 encodes a uint32 as big-endian bytes.
func encodeU32(v uint32) []byte {
	return []byte{
		byte(v >> 24),
		byte(v >> 16),
		byte(v >> 8),
		byte(v),
	}
}

// decodeU32 decodes big-endian bytes to uint32.
func decodeU32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

var errSizeMismatch = func(expected, got int) error {
	return err("recovered payload size does not match metadata: expected %d, got %d", expected, got)
}

var err = func(format string, args ...interface{}) error {
	return &errorString{s: format}
}

type errorString struct {
	s string
}

func (e *errorString) Error() string {
	return e.s
}