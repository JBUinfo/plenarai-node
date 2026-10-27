package httpgzip

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTransportGzipsLargeJSONForTheServerOnly(t *testing.T) {
	type seen struct {
		encoding string
		body     string
	}
	var got seen
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reader io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			zr, err := gzip.NewReader(r.Body)
			if err != nil {
				t.Errorf("gzip: %v", err)
				return
			}
			reader = zr
		}
		body, _ := io.ReadAll(reader)
		got = seen{r.Header.Get("Content-Encoding"), string(body)}
	}))
	defer server.Close()
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = seen{r.Header.Get("Content-Encoding"), ""}
	}))
	defer other.Close()

	tr := &transport{base: http.DefaultTransport, host: strings.TrimPrefix(server.URL, "http://")}
	client := &http.Client{Transport: tr}
	large := `{"messages":"` + strings.Repeat("contexto ", 500) + `"}`
	for _, tc := range []struct {
		url, contentType, body, encoding string
	}{
		{server.URL, "application/json", large, "gzip"},
		{server.URL, "application/json", `{"small":true}`, ""},
		{server.URL, "text/plain", large, ""},
		{other.URL, "application/json", large, ""},
	} {
		got = seen{}
		resp, err := client.Post(tc.url, tc.contentType, bytes.NewReader([]byte(tc.body)))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if got.encoding != tc.encoding {
			t.Fatalf("%s %s %d bytes: encoding %q, want %q", tc.url, tc.contentType, len(tc.body), got.encoding, tc.encoding)
		}
		if tc.url == server.URL && got.body != tc.body {
			t.Fatal("server received a different body")
		}
	}
}
