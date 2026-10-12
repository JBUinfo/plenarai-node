package inference

import (
	"context"
	"encoding/json"
	"errors"
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

func TestUnlimitedOutputStillChecksContextAndOmitsTokenCeiling(t *testing.T) {
	var preflight bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/apply-template":
			fmt.Fprint(w, `{"prompt":"rendered"}`)
		case "/tokenize":
			preflight = true
			fmt.Fprint(w, `{"tokens":[1,2,3]}`)
		case "/v1/chat/completions":
			var body map[string]any
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				t.Error("invalid body")
			}
			if _, ok := body["max_tokens"]; ok {
				t.Error("platform token ceiling was sent")
			}
			if !preflight {
				t.Error("unlimited generation skipped context validation")
			}
			fmt.Fprint(w, `{"choices":[{"message":{"content":"complete answer"}}]}`)
		default:
			t.Error("unexpected endpoint")
		}
	}))
	defer server.Close()
	s := &Server{BaseURL: server.URL, ContextWindowTokens: 4}
	if _, err := s.ChatMessages(context.Background(), []Message{{Role: "user", Content: "hello"}}, GenerationOptions{}); err != nil {
		t.Fatal(err)
	}
	s.ContextWindowTokens = 3
	if _, err := s.ChatMessages(context.Background(), []Message{{Role: "user", Content: "hello"}}, GenerationOptions{}); !errors.Is(err, ErrContextWindowExceeded) {
		t.Fatal("full input window allowed generation")
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
	var windowErr *ContextWindowError
	if _, err := s.validateContextWindow(context.Background(), messages, 2); !errors.As(err, &windowErr) || windowErr.PromptTokens != 3 || !errors.Is(err, ErrContextWindowExceeded) {
		t.Fatalf("accepted or misreported a prompt beyond the local context window: %v", err)
	}
	if n, err := s.validateContextWindow(context.Background(), messages, 1); err != nil || n != 3 {
		t.Fatalf("valid prompt rejected or miscounted: %d %v", n, err)
	}
}
