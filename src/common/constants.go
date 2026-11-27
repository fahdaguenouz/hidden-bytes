package common

// Container format identifier. Used as AES-GCM associated data so that
// tampering with magic bytes makes authentication fail.
const MAGIC = "HBX1"

// Header length is stored as an unsigned big-endian 32-bit integer.
const HEADER_SIZE = 4

// One mebibyte, in bytes.
const MIB = 1024 * 1024

// Protect the parser from allocating/reading unreasonable metadata.
const MAX_HEADER_SIZE = 1 * MIB

// GCM authentication tag size, included in AESGCM output.
const GCM_TAG_SIZE = 16

// Identifier written in the header of the generated self-extracting runner.
const RUNNER_MAGIC = "HBX-RUNNER-V1"

// Name of the container file when packaged as a single executable.
const RUNNER_CONTAINER_NAME = "payload.hbx"

// Size of the AES-256 encryption key in bytes.
const KEY_SIZE = 32

// Size of the AES-GCM nonce in bytes.
const NONCE_SIZE = 12

// Maximum delay in seconds allowed for execution delay.
const MAX_DELAY_SECONDS = 86400

// Maximum --add-size value, in MiB.
const MAX_ADD_SIZE_MB = 2 * 1024