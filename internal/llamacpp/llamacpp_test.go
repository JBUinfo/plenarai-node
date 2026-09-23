package llamacpp

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestHTTPDownloadWritesCompleteBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		fmt.Fprint(w, "model-bytes")
	}))
	defer server.Close()

	dest := filepath.Join(t.TempDir(), "model.part")
	if err := httpDownload(server.URL, dest); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "model-bytes" {
		t.Fatalf("downloaded %q, want model-bytes", data)
	}
}

func TestHTTPDownloadRejectsOversizedDeclaredBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(maxModelDownloadSize+1))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not the full model"))
	}))
	defer server.Close()

	dest := filepath.Join(t.TempDir(), "model.part")
	if err := httpDownload(server.URL, dest); err == nil {
		t.Fatal("httpDownload accepted an oversized declared body")
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatalf("partial destination still exists, stat error: %v", err)
	}
}

func TestHTTPDownloadRejectsTruncatedBodyAndCleansPartial(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "32")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("short"))
	}))
	defer server.Close()

	dest := filepath.Join(t.TempDir(), "model.part")
	if err := httpDownload(server.URL, dest); err == nil {
		t.Fatal("httpDownload accepted a truncated body")
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatalf("partial destination still exists, stat error: %v", err)
	}
}
