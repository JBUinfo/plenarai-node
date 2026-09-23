// Package config holds CLI-wide build-time configuration.
//
// ServerURL is set at build time via ldflags:
//
//	go build -ldflags "-X github.com/plenarai/cli/internal/config.ServerURL=https://api.example.com"
package config

import (
	"fmt"
	"net/url"
	"os"
)

// ServerURL is the PlenarAI backend URL. Override at build time.
var ServerURL = "http://localhost:8080"

// Version is the CLI version, injected at release build time (e.g. v1.2.0).
var Version = "dev"

// ReleaseRepo is the GitHub repo that hosts CLI releases.
const ReleaseRepo = "JBUinfo/plenarai-node"

// ValidateServerURL rejects plain http to non-local hosts unless
// PLENARAI_ALLOW_INSECURE=1: tokens and questions would travel cleartext.
func ValidateServerURL() error {
	u, err := url.Parse(ServerURL)
	if err != nil {
		return fmt.Errorf("invalid server URL %q: %w", ServerURL, err)
	}
	if u.Scheme == "https" {
		return nil
	}
	host := u.Hostname()
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return nil
	}
	if os.Getenv("PLENARAI_ALLOW_INSECURE") == "1" {
		return nil
	}
	return fmt.Errorf("refusing plain http to %s: credentials would travel unencrypted (set PLENARAI_ALLOW_INSECURE=1 to override)", host)
}
