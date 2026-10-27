// Package httpgzip compresses large JSON request bodies sent to the PlenarAI
// server. Responses need nothing here: Go's transport already asks for gzip
// and decompresses it transparently.
package httpgzip

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Smaller bodies gain little and still pay the gzip header.
const minBytes = 1024

type transport struct {
	base http.RoundTripper
	host string
}

// Install wraps http.DefaultTransport so every client that relies on it
// gzips JSON bodies of at least 1 KiB sent to serverURL's host. Requests to
// GitHub, llama.cpp or Ollama are left untouched.
func Install(serverURL string) {
	u, err := url.Parse(serverURL)
	if err != nil || u.Host == "" {
		return
	}
	http.DefaultTransport = &transport{base: http.DefaultTransport, host: u.Host}
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host != t.host || req.Body == nil || req.Body == http.NoBody ||
		req.Header.Get("Content-Encoding") != "" ||
		!strings.HasPrefix(req.Header.Get("Content-Type"), "application/json") {
		return t.base.RoundTrip(req)
	}
	raw, err := io.ReadAll(req.Body)
	req.Body.Close()
	if err != nil {
		return nil, err
	}
	body, encoded := raw, false
	if len(raw) >= minBytes {
		var buf bytes.Buffer
		w := gzip.NewWriter(&buf)
		if _, err = w.Write(raw); err == nil && w.Close() == nil && buf.Len() < len(raw) {
			body, encoded = buf.Bytes(), true
		}
	}
	// A RoundTripper must not modify the caller's request.
	out := req.Clone(req.Context())
	out.Body = io.NopCloser(bytes.NewReader(body))
	out.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	out.ContentLength = int64(len(body))
	if encoded {
		out.Header.Set("Content-Encoding", "gzip")
	}
	return t.base.RoundTrip(out)
}
