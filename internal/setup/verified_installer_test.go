package setup

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestInstallerRequiresTrustedDigest(t *testing.T) {
	t.Setenv("PLENARAI_OLLAMA_INSTALLER_SHA256", "")
	if _, err := verifiedOllamaInstaller("http://127.0.0.1:1/unreachable", "audit-installer-*"); err == nil {
		t.Fatal("unverified installer accepted")
	}
}

func TestInstallerVerifiesBytesAndStatus(t *testing.T) {
	const body = "synthetic installer, never executed"
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(body)))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/error" {
			w.WriteHeader(503)
		}
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()
	t.Setenv("PLENARAI_OLLAMA_INSTALLER_SHA256", digest)
	path, err := verifiedOllamaInstaller(server.URL, "audit-installer-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)
	if _, err := verifiedOllamaInstaller(server.URL+"/error", "audit-installer-*"); err == nil {
		t.Fatal("HTTP error accepted")
	}
	t.Setenv("PLENARAI_OLLAMA_INSTALLER_SHA256", fmt.Sprintf("%064d", 0))
	badPath, err := verifiedOllamaInstaller(server.URL, "audit-installer-*")
	if err == nil {
		t.Fatal("wrong digest accepted")
	}
	if _, err := os.Stat(badPath); !os.IsNotExist(err) {
		t.Fatal("failed installer retained")
	}
}
