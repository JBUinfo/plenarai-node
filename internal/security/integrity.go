package security

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
)

// ExpectedHash is set at build time via ldflags.
// When building: go build -ldflags "-X github.com/plenarai/cli/internal/security.ExpectedHash=abc123..."
var ExpectedHash string

// VerifyBinaryIntegrity checks if the running binary has been modified.
// If ExpectedHash is empty (dev build), the check is skipped.
func VerifyBinaryIntegrity() error {
	if ExpectedHash == "" {
		return nil // dev build, skip check
	}

	execPath, err := os.Executable()
	if err != nil {
		return nil // can't determine path, skip
	}

	data, err := os.ReadFile(execPath)
	if err != nil {
		return nil // can't read binary, skip
	}

	hash := sha256.Sum256(data)
	actualHash := hex.EncodeToString(hash[:])

	if actualHash != ExpectedHash {
		return fmt.Errorf("binary integrity check failed: binary has been modified")
	}

	return nil
}

// ComputeHash returns the SHA-256 hash of the running binary.
// Used during build to generate the expected hash.
func ComputeHash() (string, error) {
	execPath, err := os.Executable()
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(execPath)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}
