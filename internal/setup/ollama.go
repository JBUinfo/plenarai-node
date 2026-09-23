package setup

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const DefaultOllamaURL = "http://localhost:11434"

var ollamaProbeClient = &http.Client{Timeout: 3 * time.Second}
var ollamaPullClient = &http.Client{Timeout: 30 * time.Minute}

// IsOllamaInstalled checks if ollama binary is available in PATH or in common install paths.
func IsOllamaInstalled() bool {
	if _, err := exec.LookPath("ollama"); err == nil {
		return true
	}
	// Fallback: check common install locations (PATH may be stale in current shell)
	for _, p := range commonOllamaPaths() {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

func commonOllamaPaths() []string {
	switch runtime.GOOS {
	case "windows":
		home, _ := os.UserHomeDir()
		return []string{
			filepath.Join(home, "AppData", "Local", "Programs", "Ollama", "ollama.exe"),
			`C:\Program Files\Ollama\ollama.exe`,
			`C:\Program Files (x86)\Ollama\ollama.exe`,
		}
	case "darwin":
		return []string{
			"/Applications/Ollama.app/Contents/Resources/ollama",
			"/usr/local/bin/ollama",
			"/opt/homebrew/bin/ollama",
		}
	case "linux":
		return []string{
			"/usr/local/bin/ollama",
			"/usr/bin/ollama",
		}
	}
	return nil
}

// IsOllamaRunning checks if the ollama API is reachable.
func IsOllamaRunning(url string) bool {
	if url == "" {
		url = DefaultOllamaURL
	}
	resp, err := ollamaProbeClient.Get(url + "/api/tags")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// InstallInstructions returns the platform-specific command to install ollama.
func InstallInstructions() string {
	switch runtime.GOOS {
	case "linux":
		return "Review the installation instructions at https://ollama.com/download/linux"
	case "darwin":
		return "Download from https://ollama.com/download/mac\nOr: brew install ollama"
	case "windows":
		return "Download from https://ollama.com/download/windows"
	default:
		return "Visit https://ollama.com/download"
	}
}

// TryInstall attempts to install ollama automatically on the current platform.
func TryInstall() error {
	switch runtime.GOOS {
	case "linux":
		return installLinux()
	case "windows":
		return installWindows()
	case "darwin":
		return installMac()
	default:
		return fmt.Errorf("auto-install not supported on %s. %s", runtime.GOOS, InstallInstructions())
	}
}

func installLinux() error {
	installer, err := verifiedOllamaInstaller("https://ollama.com/install.sh", "plenarai-ollama-*.sh")
	if err != nil {
		return err
	}
	defer os.Remove(installer)
	// Run install script with stdin/stdout passthrough (it may prompt for sudo)
	cmd := exec.Command("sh", installer)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("install failed: %w", err)
	}

	// install.sh sets up a systemd service that runs ollama serve.
	// If systemd is not available (containers, WSL, etc.), start manually.
	time.Sleep(2 * time.Second)
	if !IsOllamaRunning(DefaultOllamaURL) {
		fmt.Println("Starting ollama serve in background...")
		if err := startDetached("ollama", "serve"); err != nil {
			fmt.Println("Warning: could not auto-start ollama. Run manually: ollama serve")
		} else {
			time.Sleep(3 * time.Second)
		}
	}
	return nil
}

func installWindows() error {
	tempFile, err := verifiedOllamaInstaller("https://ollama.com/download/OllamaSetup.exe", "plenarai-ollama-*.exe")
	if err != nil {
		return err
	}
	defer os.Remove(tempFile)

	fmt.Println("Running installer (silent mode)...")
	cmd := exec.Command(tempFile, "/VERYSILENT", "/NORESTART", "/SUPPRESSMSGBOXES")
	if err := cmd.Run(); err != nil {
		fmt.Println("Silent install failed, opening interactive installer...")
		cmd = exec.Command(tempFile)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("installer failed: %w", err)
		}
	}
	os.Remove(tempFile)

	// The installer auto-launches the Ollama UI. Kill it and disable autostart.
	time.Sleep(2 * time.Second)
	fmt.Println("Disabling Ollama UI...")
	exec.Command("taskkill", "/F", "/IM", "ollama app.exe").Run()
	exec.Command("taskkill", "/F", "/IM", "Ollama.exe").Run()
	exec.Command("reg", "delete", `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "/v", "Ollama", "/f").Run()

	// Start ollama serve as a detached background process (no UI, no window)
	fmt.Println("Starting ollama serve in background...")
	home, _ := os.UserHomeDir()
	ollamaExe := filepath.Join(home, "AppData", "Local", "Programs", "Ollama", "ollama.exe")
	if err := startDetached(ollamaExe, "serve"); err != nil {
		fmt.Printf("Warning: could not start ollama serve. Run manually: \"%s\" serve\n", ollamaExe)
	} else {
		time.Sleep(3 * time.Second) // give it time to bind the port
	}

	fmt.Println("Ollama installed and running headless (no UI).")
	return nil
}

func installMac() error {
	if _, err := exec.LookPath("brew"); err == nil {
		cmd := exec.Command("brew", "install", "ollama")
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("brew install failed: %w", err)
		}

		// Start ollama as a brew background service (no UI, persists across reboots)
		fmt.Println("Starting ollama as a background service...")
		exec.Command("brew", "services", "start", "ollama").Run()
		time.Sleep(2 * time.Second)

		// Fallback: if brew services didn't work, start detached
		if !IsOllamaRunning(DefaultOllamaURL) {
			if err := startDetached("ollama", "serve"); err != nil {
				fmt.Println("Warning: could not auto-start ollama. Run manually: ollama serve")
			} else {
				time.Sleep(3 * time.Second)
			}
		}
		return nil
	}
	return fmt.Errorf("brew not found. Install brew or download manually: %s", InstallInstructions())
}

// Model represents an ollama model entry.
type Model struct {
	Name       string `json:"name"`
	Size       int64  `json:"size"`
	ModifiedAt string `json:"modified_at"`
}

// ListModels returns all locally installed models.
func ListModels(url string) ([]Model, error) {
	if url == "" {
		url = DefaultOllamaURL
	}
	resp, err := ollamaProbeClient.Get(url + "/api/tags")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Models []Model `json:"models"`
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Ollama returned status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil {
		return nil, err
	}
	return result.Models, nil
}

// PullModel downloads a model via ollama API. Prints progress to stdout.
func PullModel(url, modelName string) error {
	if url == "" {
		url = DefaultOllamaURL
	}
	payload, err := json.Marshal(map[string]interface{}{"name": modelName, "stream": true})
	if err != nil {
		return err
	}
	body := strings.NewReader(string(payload))
	resp, err := ollamaPullClient.Post(url+"/api/pull", "application/json", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	var lastStatus string
	var lastUpdate time.Time
	var lastShownPct int

	for {
		var progress struct {
			Status    string `json:"status"`
			Completed int64  `json:"completed"`
			Total     int64  `json:"total"`
		}
		if err := decoder.Decode(&progress); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		if DefaultProgressMode == ProgressOff {
			continue
		}

		now := time.Now()
		throttle := now.Sub(lastUpdate) < 200*time.Millisecond && progress.Completed < progress.Total

		switch DefaultProgressMode {
		case ProgressUI:
			if throttle {
				continue
			}
			if progress.Total > 0 {
				pct := int(float64(progress.Completed) / float64(progress.Total) * 100)
				barWidth := 30
				filled := pct * barWidth / 100
				bar := strings.Repeat("=", filled) + strings.Repeat(" ", barWidth-filled)
				fmt.Printf("\r%s [%s] %3d%% (%s / %s)        ",
					progress.Status, bar, pct, formatBytes(progress.Completed), formatBytes(progress.Total))
				if progress.Completed >= progress.Total && progress.Total > 0 {
					fmt.Println()
				}
			} else {
				fmt.Printf("\r%s                                                          ", progress.Status)
			}
		case ProgressQuiet:
			pct := 0
			if progress.Total > 0 {
				pct = int(float64(progress.Completed) / float64(progress.Total) * 100)
			}
			if progress.Status != lastStatus {
				fmt.Println(progress.Status)
				lastStatus = progress.Status
				lastShownPct = -1
			}
			if progress.Total > 0 && (pct/10 != lastShownPct/10 || progress.Completed >= progress.Total) {
				fmt.Printf("  %d%% (%s / %s)\n", pct, formatBytes(progress.Completed), formatBytes(progress.Total))
				lastShownPct = pct
			}
		}
		lastUpdate = now
	}
	if DefaultProgressMode == ProgressUI {
		fmt.Println()
	}
	return nil
}

// SuggestedModels returns a curated list of models good for PlenarAI nodes.
func SuggestedModels() []string {
	return []string{
		"llama3",    // Meta Llama 3 8B - good general-purpose
		"phi3",      // Microsoft Phi-3 - fast, small
		"mistral",   // Mistral 7B - solid quality
		"gemma2:2b", // Google Gemma 2B - very fast on low-end hardware
		"qwen2.5",   // Alibaba Qwen - strong reasoning
	}
}
