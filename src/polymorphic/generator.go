package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	hiddenbytes "hidden-bytes/src/common"
)

// PolymorphicGenerator generates polymorphic programs with encrypted payloads.
type PolymorphicGenerator struct {
	key       []byte
	nonce     []byte
	ciphertext []byte
	keyBase64 string
	nonceBase64 string
}

// NewPolymorphicGenerator creates a new generator with the given payload.
func NewPolymorphicGenerator(payload []byte) *PolymorphicGenerator {
	g := &PolymorphicGenerator{}
	g.encryptPayload(payload)
	return g
}

// encryptPayload encrypts the payload using AES-256-GCM.
func (g *PolymorphicGenerator) encryptPayload(payload []byte) {
	key := make([]byte, hiddenbytes.KEY_SIZE)
	_, _ = rand.Read(key)

	nonce := make([]byte, hiddenbytes.NONCE_SIZE)
	_, _ = rand.Read(nonce)

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	g.ciphertext = aesgcm.Seal(nil, nonce, payload, []byte(hiddenbytes.MAGIC))

	g.key = key
	g.nonce = nonce
	g.keyBase64 = hiddenbytes.Base64Encode(key)
	g.nonceBase64 = hiddenbytes.Base64Encode(nonce)
}

// KeyBase64 returns the base64-encoded encryption key.
func (g *PolymorphicGenerator) KeyBase64() string {
	return g.keyBase64
}

// NonceBase64 returns the base64-encoded nonce.
func (g *PolymorphicGenerator) NonceBase64() string {
	return g.nonceBase64
}

// Ciphertext returns the base64-encoded ciphertext.
func (g *PolymorphicGenerator) Ciphertext() string {
	return base64.StdEncoding.EncodeToString(g.ciphertext)
}

// DecryptPayload decrypts the ciphertext using the embedded key.
func (g *PolymorphicGenerator) DecryptPayload() ([]byte, error) {
	block, err := aes.NewCipher(g.key)
	if err != nil {
		return nil, fmt.Errorf("error creating cipher: %v", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error creating GCM: %v", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(g.nonceBase64)
	if err != nil {
		return nil, fmt.Errorf("error decoding nonce: %v", err)
	}

	plaintext, err := aesgcm.Open(nil, nonce, g.ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("error decrypting: %v", err)
	}

	return plaintext, nil
}

// GenerateSourceTemplate returns a source code template for the polymorphic program.
func (g *PolymorphicGenerator) GenerateSourceTemplate() string {
	return fmt.Sprintf(`package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"os"
)

const (
	PAYLOAD_CIPHERTEXT = "%s"
	PAYLOAD_NONCE = "%s"
	PAYLOAD_KEY = "%s"
)

func main() {
	key, _ := base64.StdEncoding.DecodeString(PAYLOAD_KEY)
	nonce, _ := base64.StdEncoding.DecodeString(PAYLOAD_NONCE)

	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating cipher: %%v\n", err)
		os.Exit(1)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating GCM: %%v\n", err)
		os.Exit(1)
	}

	ciphertext, _ := base64.StdEncoding.DecodeString(PAYLOAD_CIPHERTEXT)
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error decrypting payload: %%v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Payload decrypted successfully: %%d bytes\n", len(plaintext))
}
`, g.Ciphertext(), g.NonceBase64(), g.KeyBase64())
}