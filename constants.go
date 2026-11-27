package hiddenbytes

// Container format identifier. Also used as AES-GCM associated data so that
// tampering with the magic bytes makes authentication failure.
const MAGIC = "HBX1"

// Header length is stored as an unsigned big-endian 32-bit integer.
const HEADER_SIZE = 4

// One mebibyte, in bytes.
const MIB = 1024 * 1024

// Protect the parser from allocating/reading unreasonable metadata.
const MAX_HEADER_SIZE = 1 * MIB

// GCM authentication tag size, included in AESGCM.encrypt() output.
const GCM_TAG_SIZE = 16

// Identifier written in the header of the generated self-extracting runner.
const RUNNER_MAGIC = "HBX-RUNNER-V1"

// Name of the container file when the runner is packaged as a single
// executable (PyInstaller one-file mode).
const RUNNER_CONTAINER_NAME = "payload.hbx"