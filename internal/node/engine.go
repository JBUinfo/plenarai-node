package node

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/plenarai/cli/internal/crypto"
	"github.com/plenarai/cli/internal/inference"
	"github.com/plenarai/cli/logger"
)

// engine runs completions either through the bundled llama-server (llama.cpp)
// or through a legacy local Ollama instance. Question content stays on the
// machine in both cases.
type engine struct {
	llama       *inference.Server
	model       string // ollama model tag (legacy path)
	ollamaURL   string
	displayName string
}

func (e *engine) complete(system, user string) string {
	out, err := e.completeSafe(system, user)
	if err != nil {
		logger.Log.Error("local model request failed", "error", err)
		return "" // Legacy scoring treats an empty result as abstention.
	}
	return out
}

func (e *engine) completeSafe(system, user string) (string, error) {
	if e.llama != nil {
		return e.llama.ChatMessages(context.Background(), []inference.Message{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		}, inference.GenerationOptions{})
	}
	return e.queryOllamaSafe(system + "\n\n" + user)
}

// completeMessages is the role-aware engine boundary used by conversation
// work. The legacy Ollama adapter is intentionally excluded until its chat
// contract is verified; isolated questions continue through complete.
func (e *engine) completeMessages(ctx context.Context, messages []inference.Message, options inference.GenerationOptions) (string, error) {
	if e.llama == nil {
		return "", inference.ErrRoleAwareChatUnsupported
	}
	return e.llama.ChatMessages(ctx, messages, options)
}

// completeMessagesWithUsage is used by encrypted chat, whose client calibrates
// its token estimate from the engine's own measurements.
func (e *engine) completeMessagesWithUsage(ctx context.Context, messages []inference.Message, options inference.GenerationOptions) (string, inference.Usage, error) {
	if e.llama == nil {
		return "", inference.Usage{}, inference.ErrRoleAwareChatUnsupported
	}
	return e.llama.ChatMessagesWithUsage(ctx, messages, options)
}

// queryOllamaSafe is the legacy single-prompt Ollama path (/api/generate).
func (e *engine) queryOllamaSafe(prompt string) (string, error) {
	if e.model == "" {
		e.model = "llama3"
	}

	body := []byte(fmt.Sprintf(`{"model":%q,"prompt":%q,"stream":false}`, e.model, prompt))
	defer crypto.ZeroBytes(body)

	request, err := http.NewRequest(http.MethodPost, e.ollamaURL+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 3 * time.Minute}).Do(request)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ollama returned HTTP %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	defer crypto.ZeroBytes(respBody)

	var result struct {
		Response string `json:"response"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", err
	}
	if strings.TrimSpace(result.Response) == "" {
		return "", fmt.Errorf("ollama returned an empty response")
	}
	return result.Response, nil
}
