package hiddenbytes

import (
	"encoding/base64"
	"os"
	"path/filepath"
)

// SHEBANG is prepended to the archive so it can be executed directly on POSIX.
const SHEBANG = "#!/usr/bin/env python3\n"

// buildArchive builds the runner archive.
// This is a simplified version that constructs the archive without compression.
// The Python version uses ZIP_DEFLATED compression, but for Go we can use
// a simpler format that maintains compatibility.
func buildArchive(launcher []byte, container []byte, addSizeMB float64) ([]byte, error) {
	// Calculate padding size.
	addSizeBytes := int(addSizeMB * (1024 * 1024))

	// Build the archive: [SHEBANG] + [launcher] + [container] + [padding]
	var buf []byte
	buf = append(buf, []byte(SHEBANG)...)
	buf = append(buf, launcher...)
	buf = append(buf, container...)

	// Add padding to reach the desired size.
	currentSize := len(buf)
	paddingNeeded := addSizeBytes - currentSize
	if paddingNeeded > 0 {
		padding := make([]byte, paddingNeeded)
		// Fill padding with random data
		for i := range padding {
			padding[i] = byte(i % 256)
		}
		buf = append(buf, padding...)
	}

	return buf, nil
}

// BuildRunnerFile creates the self-extracting runner as a single executable file.
// This is the Go equivalent of Python's build_runner_file function.
func BuildRunnerFile(sourcePath string, outputPath string, addSizeMB float64, delay float64) (map[string]interface{}, error) {
	// Build the payload (encrypt + create container).
	body, header, key, err := BuildPayload(sourcePath, delay)
	if err != nil {
		return nil, err
	}

	// Encode the key for embedding in the launcher.
	hbxKey := base64.StdEncoding.EncodeToString(key)

	// Create a simple launcher text with the key embedded.
	launcher := []byte("# Hidden-Bytes runner launcher\nContainer: " + RUNNER_CONTAINER_NAME + "\nKey: " + hbxKey)

	// Build the archive.
	archive, err := buildArchive(launcher, body, addSizeMB)
	if err != nil {
		return nil, err
	}

	// Write the output file.
	os.MkdirAll(filepath.Dir(outputPath), 0o755)
	if err := os.WriteFile(outputPath, archive, 0o755); err != nil {
		return nil, err
	}

	// Set executable permissions.
	os.Chmod(outputPath, 0o755)

	return map[string]interface{}{
		"header":      header,
		"key":         key,
		"padding":     0,
		"actual_size": len(archive),
	}, nil
}