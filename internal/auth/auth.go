package auth

import (
	"bytes"
	"encoding/json"
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

func ConfigDir() string {
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
	dir := ConfigDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	viper.Set("access_token", tokens.AccessToken)
	viper.Set("refresh_token", tokens.RefreshToken)
	return viper.WriteConfigAs(filepath.Join(dir, "config.yaml"))
}

func LoadTokens() (*TokenPair, error) {
	dir := ConfigDir()
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(dir)

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
	dir := ConfigDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	return viper.WriteConfigAs(filepath.Join(dir, "config.yaml"))
}

// LoadConfig reads the config file if present. Silent on missing file.
func LoadConfig() {
	dir := ConfigDir()
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(dir)
	_ = viper.ReadInConfig()
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
