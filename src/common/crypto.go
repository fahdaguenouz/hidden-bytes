package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
)

// BuildPayload encrypts a file and returns the container body, header, and key.
// The container format is: MAGIC + header_length (>I) + raw_header + ciphertext.
func BuildPayload(filePath string, delay float64) ([]byte, map[string]interface{}, []byte, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, nil, err
	}

	originalSize := len(data)

	key := generateRandomBytes(32)
	nonce := generateRandomBytes(12)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, data, []byte(MAGIC))

	header := map[string]interface{}{
		"algorithm":           "AES-256-GCM",
		"ciphertext_length":   len(ciphertext),
		"delay_seconds":       delay,
		"original_name":       filepath.Base(filePath),
		"original_size":       originalSize,
		"nonce":               Base64Encode(nonce),
	}

	rawHeaderBytes, err := json.Marshal(header)
	if err != nil {
		return nil, nil, nil, err
	}

	if len(rawHeaderBytes) > MAX_HEADER_SIZE {
		return nil, nil, nil, errHeaderTooLarge
	}

	headerLen := uint32(len(rawHeaderBytes))

	body := make([]byte, 0, 4+len(rawHeaderBytes)+len(ciphertext))
	body = append(body, []byte(MAGIC)...)
	body = append(body, encodeU32(headerLen)...)
	body = append(body, rawHeaderBytes...)
	body = append(body, ciphertext...)

	return body, header, key, nil
}

// DecryptPayload decrypts and authenticates a container payload.
func DecryptPayload(header map[string]interface{}, ciphertext []byte, key []byte) ([]byte, error) {
	nonce, err := Base64Decode(header["nonce"].(string))
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, []byte(MAGIC))
	if err != nil {
		return nil, err
	}

	expectedSize := int(header["original_size"].(float64))
	if len(plaintext) != expectedSize {
		return nil, errSizeMismatch(expectedSize, len(plaintext))
	}

	return plaintext, nil
}

// generateRandomBytes generates cryptographically random bytes.
func generateRandomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
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

// errSizeMismatch returns an error when payload size doesn't match metadata.
func errSizeMismatch(expected, got int) error {
	return errGeneric("recovered payload size does not match metadata: expected %d, got %d", expected, got)
}

// errGeneric returns a formatted error.
func errGeneric(format string, args ...interface{}) error {
	return &errorString{s: format}
}

type errorString struct {
	s string
}

func (e *errorString) Error() string {
	return e.s
}

var errHeaderTooLarge = errGeneric("header is too large: %d bytes", MAX_HEADER_SIZE)

// ReadContainerHeader reads and validates the HBX1 header from a file.
func ReadContainerHeader(path string) (map[string]interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseContainerHeader(data)
}

// parseContainerHeader extracts and validates the header from container data.
func parseContainerHeader(data []byte) (map[string]interface{}, error) {
	if len(data) < 8 {
		return nil, errGeneric("file too short: minimum 8 bytes for magic + header length")
	}

	if string(data[:4]) != MAGIC {
		return nil, errGeneric("invalid magic bytes: expected %s", MAGIC)
	}

	headerLen := decodeU32(data[4:8])
	if headerLen > MAX_HEADER_SIZE {
		return nil, errGeneric("header is too large: %d bytes", headerLen)
	}

	if len(data) < 8+int(headerLen) {
		return nil, errGeneric("file truncated: header extends beyond file")
	}

	var header map[string]interface{}
	if err := json.Unmarshal(data[8:8+int(headerLen)], &header); err != nil {
		return nil, errGeneric("invalid JSON header")
	}

	return header, nil
}