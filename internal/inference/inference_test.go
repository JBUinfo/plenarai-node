package inference

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"testing"
	"time"
)

func TestChatReturnsAssistantContent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/chat/completions" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"choices":[{"message":{"content":"hello"}}]}`)
	}))
	defer server.Close()

	got, err := (&Server{BaseURL: server.URL}).Chat("system", "user")
	if err != nil {
		t.Fatal(err)
	}
	if got != "hello" {
		t.Fatalf("Chat() = %q, want hello", got)
	}
}

func TestChatRejectsOversizedDeclaredResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(maxChatResponseSize+1))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	if _, err := (&Server{BaseURL: server.URL}).Chat("system", "user"); err == nil {
		t.Fatal("Chat accepted a response above its size limit")
	}
}

func TestWaitHealthyRejectsOversizedDeclaredResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(maxHealthResponseSize+1))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	s := &Server{cmd: &exec.Cmd{}, BaseURL: server.URL}
	if err := s.waitHealthy(550 * time.Millisecond); err == nil {
		t.Fatal("waitHealthy accepted an oversized health response")
	}
}

func TestValidateContextWindowUsesRenderedPromptTokens(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/apply-template":
			fmt.Fprint(w, `{"prompt":"rendered by the model template"}`)
		case "/tokenize":
			fmt.Fprint(w, `{"tokens":[1,2,3]}`)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	s := &Server{BaseURL: server.URL, ContextWindowTokens: 4}
	messages := []Message{{Role: "system", Content: "system"}, {Role: "user", Content: "message"}}
	if err := s.validateContextWindow(context.Background(), messages, 2); err == nil {
		t.Fatal("accepted a prompt plus output reserve beyond the local context window")
	}
	if err := s.validateContextWindow(context.Background(), messages, 1); err != nil {
		t.Fatalf("valid prompt rejected: %v", err)
	}
}
