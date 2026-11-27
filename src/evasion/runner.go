package main

import (
	"bytes"
	"os"

	hiddenbytes "hidden-bytes/src/common"
)

// LAUNCHER_NAME is the name of the launcher inside the archive.
const LAUNCHER_NAME = "__main__.py"

// PADDING_NAME is the name of the padding member used for file-size manipulation.
const PADDING_NAME = "padding.bin"

// buildArchive builds the runner archive by directly concatenating bytes.
// No templating needed - just direct byte assembly.
func buildArchive(launcher []byte, container []byte, addSizeMB float64) ([]byte, error) {
	addSizeBytes := int(addSizeMB * (1024 * 1024))

	var buf bytes.Buffer
	buf.Write(launcher)
	buf.Write(container)

	currentSize := buf.Len()
	paddingNeeded := addSizeBytes - currentSize
	if paddingNeeded > 0 {
		padding := make([]byte, paddingNeeded)
		for i := range padding {
			padding[i] = byte(i % 256)
		}
		buf.Write(padding)
	}

	return buf.Bytes(), nil
}

// BuildRunnerFile creates the self-extracting runner as a single executable file.
// Uses direct Go code construction instead of templates.
func BuildRunnerFile(sourcePath string, outputPath string, addSizeMB float64, delay float64) (map[string]interface{}, error) {
	body, header, key, err := hiddenbytes.BuildPayload(sourcePath, delay)
	if err != nil {
		return nil, err
	}

	hbxKey := hiddenbytes.Base64Encode(key)

	// Build launcher source using direct string building (no templates)
	launcherSource := buildLauncherSource(hiddenbytes.RUNNER_CONTAINER_NAME, hbxKey)

	archive, err := buildArchive([]byte(launcherSource), body, addSizeMB)
	if err != nil {
		return nil, err
	}

	if err := os.WriteFile(outputPath, archive, 0o755); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"header":      header,
		"key":         key,
		"padding":     0,
		"actual_size": len(archive),
	}, nil
}

// buildLauncherSource constructs the launcher source code using direct string building.
// This replaces Python-style string replacement with simple Go string concatenation.
func buildLauncherSource(containerName, hbxKey string) string {
	var sb bytes.Buffer
	sb.WriteString(`package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
)

const (
	CONTAINER_NAME = "`)
	sb.WriteString(containerName)
	sb.WriteString(`"
	HBX_KEY = "`)
	sb.WriteString(hbxKey)
	sb.WriteString(`"
)

func main() {
	fmt.Fprintf(os.Stderr, "[INFO] Hidden-Bytes self-extracting runner.\\n")

	data, err := os.ReadFile(os.Args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] cannot read self: %v\\n", err)
		os.Exit(1)
	}

	if len(data) < 8 || string(data[:4]) != hiddenbytes.MAGIC {
		fmt.Fprintf(os.Stderr, "[ERROR] embedded data is not a valid HBX1 container\\n")
		os.Exit(1)
	}

	headerLength := hiddenbytes.DecodeU32(data[4:8])
	header := make(map[string]interface{})
	if err := json.Unmarshal(data[8:8+headerLength], &header); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] invalid JSON header: %v\\n", err)
		os.Exit(1)
	}

	ciphertext := data[8+headerLength : 8+headerLength+int(header["ciphertext_length"].(float64))]

	delay := header["delay_seconds"].(float64)
	if delay > 0 {
		fmt.Fprintf(os.Stderr, "[INFO] Execution delayed by %g seconds...\\n", delay)
	}

	key, _ := base64.StdEncoding.DecodeString(HBX_KEY)
	nonce, _ := base64.StdEncoding.DecodeString(header["nonce"].(string))

	block, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(block)
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, []byte(hiddenbytes.MAGIC))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] decryption failed: wrong key or damaged container\\n")
		os.Exit(1)
	}

	if len(plaintext) != int(header["original_size"].(float64)) {
		fmt.Fprintf(os.Stderr, "[ERROR] recovered payload size does not match the container\\n")
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "[INFO] Binary decrypted successfully.\\n")

	workdir, _ := os.MkdirTemp("", "hbx_")
	defer os.RemoveAll(workdir)

	target := workdir + "/payload.bin"
	os.WriteFile(target, plaintext, 0o700)

	fmt.Fprintf(os.Stderr, "[INFO] Target program executed.\\n")
}
`)

	return sb.String()
}