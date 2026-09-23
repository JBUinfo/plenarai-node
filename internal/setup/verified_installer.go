package setup

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Installation is opt-in with a separately reviewed digest. Never obtain the
// expected hash from the same unauthenticated installer response.
func verifiedOllamaInstaller(url, pattern string) (path string, err error) {
	expected := strings.ToLower(strings.TrimSpace(os.Getenv("PLENARAI_OLLAMA_INSTALLER_SHA256")))
	decoded, decodeErr := hex.DecodeString(expected)
	if decodeErr != nil || len(decoded) != sha256.Size {
		return "", fmt.Errorf("automatic Ollama installation requires a trusted PLENARAI_OLLAMA_INSTALLER_SHA256; use the pinned llama.cpp setup or install Ollama manually: %s", InstallInstructions())
	}
	client := &http.Client{Timeout: 30 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	const maxInstallerBytes int64 = 4 << 30
	if resp.StatusCode != http.StatusOK || resp.ContentLength > maxInstallerBytes {
		return "", fmt.Errorf("installer download rejected")
	}
	file, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}
	path = file.Name()
	defer func() {
		file.Close()
		if err != nil {
			os.Remove(path)
		}
	}()
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(file, hash), io.LimitReader(resp.Body, maxInstallerBytes+1))
	if err != nil {
		return path, err
	}
	if n > maxInstallerBytes || hex.EncodeToString(hash.Sum(nil)) != expected {
		return path, fmt.Errorf("installer integrity verification failed")
	}
	if err = file.Close(); err != nil {
		return path, err
	}
	return path, nil
}
