// Package update implements self-updating from GitHub Releases.
package update

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/plenarai/cli/internal/config"
)

var httpClient = &http.Client{Timeout: 60 * time.Second}

type Release struct {
	TagName string  `json:"tag_name"`
	Assets  []Asset `json:"assets"`
}

type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// LatestRelease fetches the newest published release from GitHub.
func LatestRelease() (*Release, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", config.ReleaseRepo)
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("could not reach GitHub: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub returned status %d", resp.StatusCode)
	}
	var rel Release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, err
	}
	return &rel, nil
}

// AssetName returns the release asset name for this OS/arch.
func AssetName() string {
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	return fmt.Sprintf("plenarai-%s-%s%s", runtime.GOOS, runtime.GOARCH, ext)
}

func isNewer(latest, current string) bool {
	l := strings.TrimPrefix(latest, "v")
	c := strings.TrimPrefix(current, "v")
	return l != "" && l != c
}

// CheckAvailable returns the latest tag if it differs from the running version.
// Dev builds never report an update.
func CheckAvailable() (string, bool) {
	if config.Version == "dev" {
		return "", false
	}
	rel, err := LatestRelease()
	if err != nil || !isNewer(rel.TagName, config.Version) {
		return "", false
	}
	return rel.TagName, true
}

// SelfUpdate downloads the latest release binary, verifies its checksum and
// replaces the running executable. Returns a human-readable status message.
func SelfUpdate() (string, error) {
	rel, err := LatestRelease()
	if err != nil {
		return "", err
	}
	if config.Version != "dev" && !isNewer(rel.TagName, config.Version) {
		return fmt.Sprintf("already up to date (%s)", config.Version), nil
	}

	assetName := AssetName()
	var binURL, sumURL string
	for _, a := range rel.Assets {
		switch a.Name {
		case assetName:
			binURL = a.BrowserDownloadURL
		case "checksums.txt":
			sumURL = a.BrowserDownloadURL
		}
	}
	if binURL == "" {
		return "", fmt.Errorf("release %s has no binary for %s", rel.TagName, assetName)
	}
	if sumURL == "" {
		return "", fmt.Errorf("release %s has no checksums.txt, refusing unverified update", rel.TagName)
	}

	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(exePath); err == nil {
		exePath = resolved
	}

	tmpPath := exePath + ".new"
	sum, err := downloadFile(binURL, tmpPath)
	if err != nil {
		return "", err
	}
	defer os.Remove(tmpPath)

	expected, err := expectedChecksum(sumURL, assetName)
	if err != nil {
		return "", err
	}
	if sum != expected {
		return "", fmt.Errorf("checksum mismatch for %s: refusing update", assetName)
	}

	// Rename dance: a running executable can't be overwritten on Windows, but it can be renamed
	oldPath := exePath + ".old"
	os.Remove(oldPath)
	if err := os.Rename(exePath, oldPath); err != nil {
		return "", fmt.Errorf("could not move current binary: %w", err)
	}
	if err := os.Rename(tmpPath, exePath); err != nil {
		os.Rename(oldPath, exePath) // roll back
		return "", fmt.Errorf("could not install new binary: %w", err)
	}
	os.Remove(oldPath) // fails on Windows while running; cleaned up on next start

	return fmt.Sprintf("updated %s -> %s", config.Version, rel.TagName), nil
}

// CleanupOldBinary removes the leftover .old file from a previous update.
func CleanupOldBinary() {
	if exePath, err := os.Executable(); err == nil {
		os.Remove(exePath + ".old")
	}
}

func downloadFile(url, dest string) (string, error) {
	resp, err := httpClient.Get(url)
	if err != nil {
		return "", fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed: status %d", resp.StatusCode)
	}

	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), resp.Body)
	closeErr := f.Close()
	if err != nil {
		return "", err
	}
	if closeErr != nil {
		return "", closeErr
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func expectedChecksum(sumURL, assetName string) (string, error) {
	resp, err := httpClient.Get(sumURL)
	if err != nil {
		return "", fmt.Errorf("could not download checksums: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == assetName {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("no checksum entry for %s", assetName)
}
