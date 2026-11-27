package hiddenbytes

import (
	"encoding/base64"
	"encoding/hex"
)

// Base64Encode encodes bytes as ASCII Base64 string.
func Base64Encode(value []byte) string {
	return base64.StdEncoding.EncodeToString(value)
}

// Base64Decode decodes ASCII Base64 string to bytes, safely validating the input.
func Base64Decode(value string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(value)
}

// HexEncode encodes bytes as ASCII hex string.
func HexEncode(value []byte) string {
	return hex.EncodeToString(value)
}

// HexDecode decodes ASCII hex string to bytes.
func HexDecode(value string) ([]byte, error) {
	return hex.DecodeString(value)
}