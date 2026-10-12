package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/spf13/viper"

	"github.com/plenarai/cli/internal/config"
)

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

const (
	configDirMode  os.FileMode = 0o700
	configFileMode os.FileMode = 0o600
	configFileName             = "config.yaml"
)

func ConfigDir() string {
	// A separate directory gives each local participant its own credentials,
	// node key and engine settings without changing the OS user's home directory.
	if dir := os.Getenv("PLENARAI_CONFIG_DIR"); dir != "" {
		return filepath.Clean(dir)
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".plenarai")
}

func Login(email, password string) (*TokenPair, error) {
	body, _ := json.Marshal(map[string]string{"email": email, "password": password})
	resp, err := http.Post(config.ServerURL+"/v0/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("too many requests or failed attempts; wait up to 15 minutes and try again")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("login failed (status %d)", resp.StatusCode)
	}

	var tokens TokenPair
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		return nil, err
	}

	return &tokens, nil
}

func SaveTokens(tokens *TokenPair) error {
	path, err := configPath(true)
	if err != nil {
		return err
	}

	viper.Set("access_token", tokens.AccessToken)
	viper.Set("refresh_token", tokens.RefreshToken)
	viper.SetConfigPermissions(configFileMode)
	if err := viper.WriteConfigAs(path); err != nil {
		return err
	}
	return secureNativeConfigPermissions(path, false)
}

func LoadTokens() (*TokenPair, error) {
	path, err := configPath(false)
	if err != nil {
		return nil, fmt.Errorf("not logged in")
	}
	viper.SetConfigFile(path)

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("not logged in")
	}

	at := viper.GetString("access_token")
	rt := viper.GetString("refresh_token")
	if at == "" {
		return nil, fmt.Errorf("not logged in")
	}

	return &TokenPair{AccessToken: at, RefreshToken: rt}, nil
}

func AuthHeader() (string, error) {
	tokens, err := LoadTokens()
	if err != nil {
		return "", err
	}
	return "Bearer " + tokens.AccessToken, nil
}

// Refresh exchanges the current refresh token for a new token pair.
func Refresh() error {
	tokens, err := LoadTokens()
	if err != nil {
		return err
	}
	if tokens.RefreshToken == "" {
		return fmt.Errorf("no refresh token")
	}

	body, _ := json.Marshal(map[string]string{"refresh_token": tokens.RefreshToken})
	resp, err := http.Post(config.ServerURL+"/v0/auth/refresh", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("refresh request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("refresh failed (status %d) - login again", resp.StatusCode)
	}

	var newTokens TokenPair
	if err := json.NewDecoder(resp.Body).Decode(&newTokens); err != nil {
		return err
	}
	return SaveTokens(&newTokens)
}

// DoAuthenticated runs an HTTP request, automatically refreshing the token
// once on 401. The req must have a fresh body each time it's called.
func DoAuthenticated(buildReq func() (*http.Request, error)) (*http.Response, error) {
	req, err := buildReq()
	if err != nil {
		return nil, err
	}
	header, err := AuthHeader()
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", header)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}

	// 401 - try to refresh and retry once
	resp.Body.Close()
	if err := Refresh(); err != nil {
		return nil, err
	}
	req2, err := buildReq()
	if err != nil {
		return nil, err
	}
	header2, _ := AuthHeader()
	req2.Header.Set("Authorization", header2)
	return http.DefaultClient.Do(req2)
}

// SaveConfig persists current viper state to the config file.
func SaveConfig() error {
	path, err := configPath(true)
	if err != nil {
		return err
	}
	viper.SetConfigPermissions(configFileMode)
	if err := viper.WriteConfigAs(path); err != nil {
		return err
	}
	return secureNativeConfigPermissions(path, false)
}

// LoadConfig reads the config file if present. Silent on missing file.
func LoadConfig() {
	path, err := configPath(false)
	if err != nil {
		return
	}
	viper.SetConfigFile(path)
	_ = viper.ReadInConfig()
}

// configPath validates the participant's config directory and file before any
// read or write. The write path also tightens permissions on existing objects;
// this does not configure platform-specific ACLs on Windows.
func configPath(prepareForWrite bool) (string, error) {
	return SecretPath(configFileName, prepareForWrite)
}

// SecretPath applies the same directory, symlink and native ACL checks as tokens.
func SecretPath(name string, prepareForWrite bool) (string, error) {
	if filepath.Base(name) != name || name == "." || name == "" {
		return "", fmt.Errorf("invalid secret filename")
	}
	dir := ConfigDir()
	if err := validateConfigDirForSecrets(dir); err != nil {
		return "", err
	}
	if prepareForWrite {
		if info, err := os.Lstat(dir); err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return "", fmt.Errorf("config directory must not be a symlink: %s", dir)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		if err := os.MkdirAll(dir, configDirMode); err != nil {
			return "", err
		}
	}

	info, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("config directory must not be a symlink: %s", dir)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("config path is not a directory: %s", dir)
	}
	if prepareForWrite {
		if err := os.Chmod(dir, configDirMode); err != nil {
			return "", fmt.Errorf("secure config directory: %w", err)
		}
	}
	if err := secureNativeConfigPermissions(dir, true); err != nil {
		return "", fmt.Errorf("secure config directory: %w", err)
	}

	path := filepath.Join(dir, name)
	fileInfo, err := os.Lstat(path)
	if err == nil {
		if fileInfo.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("config file must not be a symlink: %s", path)
		}
		if !fileInfo.Mode().IsRegular() {
			return "", fmt.Errorf("config path is not a regular file: %s", path)
		}
		if prepareForWrite {
			if err := os.Chmod(path, configFileMode); err != nil {
				return "", fmt.Errorf("secure config file: %w", err)
			}
		}
		if err := secureNativeConfigPermissions(path, false); err != nil {
			return "", fmt.Errorf("secure config file: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	return path, nil
}

// SecureSecretFile refuses links/special files and applies native ACLs.
func SecureSecretFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("secret must be a regular file")
	}
	if err = os.Chmod(path, 0600); err != nil {
		return err
	}
	return secureNativeConfigPermissions(path, false)
}

func validateConfigDirForSecrets(dir string) error {
	if !filepath.IsAbs(dir) || filepath.Dir(dir) == dir {
		return fmt.Errorf("config directory must be an absolute, non-root path")
	}
	if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
		return fmt.Errorf("config directory must not be a repository root")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if cwd, err := os.Getwd(); err == nil {
		if dirInfo, dirErr := os.Stat(dir); dirErr == nil {
			if cwdInfo, cwdErr := os.Stat(cwd); cwdErr == nil && os.SameFile(dirInfo, cwdInfo) {
				return fmt.Errorf("config directory must not be the working directory")
			}
		}
	}
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		if dirInfo, dirErr := os.Stat(dir); dirErr == nil {
			if homeInfo, homeErr := os.Stat(home); homeErr == nil && os.SameFile(dirInfo, homeInfo) {
				return fmt.Errorf("config directory must not be the home directory")
			}
		}
	}
	return nil
}

// Logout revokes the refresh token server-side (best effort) and removes saved tokens.
func Logout() error {
	LoadConfig()
	if rt := viper.GetString("refresh_token"); rt != "" {
		body, _ := json.Marshal(map[string]string{"refresh_token": rt})
		if resp, err := http.Post(config.ServerURL+"/v0/auth/logout", "application/json", bytes.NewReader(body)); err == nil {
			resp.Body.Close()
		}
	}
	viper.Set("access_token", "")
	viper.Set("refresh_token", "")
	return SaveConfig()
}
