package secureworker

import (
	"context"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"github.com/plenarai/cli/internal/inference"
	"github.com/plenarai/cli/internal/opaque"
	"github.com/plenarai/cli/internal/securework"
	"github.com/plenarai/cli/internal/security"
	"strings"
	"time"
)

type OpaqueContext struct {
	Messages []inference.Message `json:"messages"`
}

// OpaqueAnswer is the plaintext sealed for the client. Usage and the window
// failure reason stay inside the ciphertext; the backend never sees them.
type OpaqueAnswer struct {
	Text                string           `json:"text,omitempty"`
	Usage               *inference.Usage `json:"usage,omitempty"`
	Reason              string           `json:"reason,omitempty"`
	ContextWindowTokens int              `json:"context_window_tokens,omitempty"`
}
type CompleteChatWithUsage func(context.Context, []inference.Message, inference.GenerationOptions) (string, inference.Usage, error)

func ProcessOpaque(ctx context.Context, key *ecdh.PrivateKey, raw json.RawMessage, prompt string, complete CompleteChatWithUsage) (out opaque.Response, err error) {
	security.DoSecret(func() { out, err = processOpaque(ctx, key, raw, prompt, complete) })
	return
}
func processOpaque(ctx context.Context, key *ecdh.PrivateKey, raw json.RawMessage, prompt string, complete CompleteChatWithUsage) (opaque.Response, error) {
	if len(raw) > 2<<20 {
		return opaque.Response{}, ErrInvalidRequest
	}
	var job struct {
		WorkKind string         `json:"work_kind"`
		Request  opaque.Request `json:"request"`
	}
	if json.Unmarshal(raw, &job) != nil || job.WorkKind != opaque.WorkKind || job.Request.Header.Live(time.Now()) != nil {
		return opaque.Response{}, ErrInvalidRequest
	}
	r := job.Request
	body, shared, err := opaque.OpenRequest(r, key)
	if err != nil {
		return opaque.Response{}, ErrInvalidRequest
	}
	defer opaque.Zero(body)
	defer opaque.Zero(shared)
	ctx, cancel := context.WithDeadline(ctx, time.Unix(r.Header.ExpiresAt, 0))
	defer cancel()
	signer := securework.SigningKey(key.Bytes())
	defer opaque.Zero(signer)
	fail := func(code string) (opaque.Response, error) {
		return opaque.SealResponse(r, shared, []byte("{}"), "failed", code, signer)
	}
	var input OpaqueContext
	if json.Unmarshal(body, &input) != nil || len(input.Messages) == 0 || len(input.Messages) > inference.MaxConversationMessages-1 {
		return fail("invalid_context")
	}
	total := len(prompt)
	for i, m := range input.Messages {
		if m.Content == "" || (m.Role != "user" && m.Role != "assistant") || (i == len(input.Messages)-1 && m.Role != "user") {
			return fail("invalid_context")
		}
		total += len(m.Content)
		if total > 512<<10 {
			return fail("invalid_context")
		}
	}
	messages := append([]inference.Message{{Role: "system", Content: prompt}}, input.Messages...)
	text, usage, err := complete(ctx, messages, inference.GenerationOptions{})
	if err != nil {
		var window *inference.ContextWindowError
		if errors.As(err, &window) {
			body, _ := json.Marshal(OpaqueAnswer{Reason: "context_window_exceeded", Usage: &inference.Usage{PromptTokens: window.PromptTokens}, ContextWindowTokens: window.Window})
			defer opaque.Zero(body)
			return opaque.SealResponse(r, shared, body, "failed", "invalid_context", signer)
		}
		if errors.Is(err, inference.ErrContextWindowExceeded) || errors.Is(err, inference.ErrInvalidMessages) {
			return fail("invalid_context")
		}
		return fail("inference_failed")
	}
	if len(text) > opaque.MaxAnswer {
		return fail("output_too_large")
	}
	if strings.TrimSpace(text) == "" {
		return fail("inference_failed")
	}
	result, _ := json.Marshal(OpaqueAnswer{Text: text, Usage: &usage})
	defer opaque.Zero(result)
	return opaque.SealResponse(r, shared, result, "completed", "", signer)
}
