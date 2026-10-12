// Package inference manages the local llama-server child process and talks to
// its HTTP API. The server binds to localhost only; question content never
// leaves the machine.
package inference

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/plenarai/cli/logger"
)

// Server is a running llama-server child process.
type Server struct {
	cmd                 *exec.Cmd
	BaseURL             string
	ContextWindowTokens int
}

// Message is the role-aware input accepted by the local chat engine.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Usage is what the local engine measured for one generation. CachedTokens is
// zero when the engine does not report prompt-cache reuse.
type Usage struct {
	PromptTokens     int    `json:"prompt_tokens"`
	CompletionTokens int    `json:"completion_tokens,omitempty"`
	CachedTokens     int    `json:"cached_tokens,omitempty"`
	FinishReason     string `json:"finish_reason,omitempty"`
}

// GenerationOptions contains bounded generation controls. Zero values leave
// the engine default in place.
type GenerationOptions struct {
	Temperature float64
	TopP        float64
}

const (
	healthRequestTimeout = 2 * time.Second
	// maxHealthResponseSize is only a safety bound; health responses are not
	// otherwise used by the client.
	maxHealthResponseSize      int64 = 1 << 20
	chatRequestTimeout               = 5 * time.Minute
	inferencePreflightTimeout        = 10 * time.Second
	maxChatResponseSize        int64 = 16 << 20
	DefaultContextWindowTokens       = 4096
	MaxContextWindowTokens           = 32768
	MaxConversationMessages          = 128
)

var (
	healthClient = &http.Client{Timeout: healthRequestTimeout}
	chatClient   = &http.Client{Timeout: chatRequestTimeout}
)

var (
	ErrInvalidMessages          = errors.New("inference: invalid chat messages")
	ErrRoleAwareChatUnsupported = errors.New("inference: role-aware chat is unsupported by this adapter")
	ErrGeneration               = errors.New("inference: generation failed")
	ErrContextWindowExceeded    = errors.New("inference: chat context exceeds local window")
)

// Start launches llama-server with the given model on a free localhost port
// and waits until its health endpoint responds.
func Start(serverBin, modelPath string) (*Server, error) {
	return StartWithContextWindow(serverBin, modelPath, DefaultContextWindowTokens)
}

// StartWithContextWindow lets a node reserve a larger local window when its
// model and memory permit it. The observed /props value is announced to peers.
func StartWithContextWindow(serverBin, modelPath string, contextWindowTokens int) (*Server, error) {
	if contextWindowTokens < DefaultContextWindowTokens || contextWindowTokens > MaxContextWindowTokens {
		return nil, fmt.Errorf("context window must be between %d and %d tokens", DefaultContextWindowTokens, MaxContextWindowTokens)
	}
	port, err := freePort()
	if err != nil {
		return nil, fmt.Errorf("no free port: %w", err)
	}

	cmd := exec.Command(serverBin,
		"--model", modelPath,
		"--host", "127.0.0.1",
		"--port", fmt.Sprint(port),
		"--ctx-size", fmt.Sprint(contextWindowTokens),
	)
	// Route engine output to the OS log sink so it never pollutes the TUI.
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("could not start llama-server: %w", err)
	}

	s := &Server{
		cmd:                 cmd,
		BaseURL:             fmt.Sprintf("http://127.0.0.1:%d", port),
		ContextWindowTokens: DefaultContextWindowTokens,
	}
	if err := s.waitHealthy(60 * time.Second); err != nil {
		s.Stop()
		return nil, err
	}
	if err := s.loadProperties(); err != nil {
		s.Stop()
		return nil, err
	}
	return s, nil
}

func (s *Server) loadProperties() error {
	ctx, cancel := context.WithTimeout(context.Background(), healthRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.BaseURL+"/props", nil)
	if err != nil {
		return fmt.Errorf("could not inspect llama-server context window: %w", err)
	}
	resp, err := healthClient.Do(req)
	if err != nil {
		return fmt.Errorf("could not inspect llama-server context window: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("llama-server properties returned status %d", resp.StatusCode)
	}
	if resp.ContentLength > maxHealthResponseSize {
		return fmt.Errorf("llama-server properties exceed the %d-byte limit", maxHealthResponseSize)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxHealthResponseSize+1))
	if err != nil {
		return fmt.Errorf("could not read llama-server properties: %w", err)
	}
	if int64(len(body)) > maxHealthResponseSize {
		return fmt.Errorf("llama-server properties exceed the %d-byte limit", maxHealthResponseSize)
	}
	var properties struct {
		DefaultGenerationSettings struct {
			ContextWindowTokens int `json:"n_ctx"`
		} `json:"default_generation_settings"`
	}
	if err := json.Unmarshal(body, &properties); err != nil {
		return fmt.Errorf("invalid llama-server properties: %w", err)
	}
	if properties.DefaultGenerationSettings.ContextWindowTokens <= 0 {
		return fmt.Errorf("llama-server reported an invalid context window")
	}
	s.ContextWindowTokens = properties.DefaultGenerationSettings.ContextWindowTokens
	return nil
}

func (s *Server) waitHealthy(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s.cmd.ProcessState != nil && s.cmd.ProcessState.Exited() {
			return fmt.Errorf("llama-server exited during startup")
		}
		ctx, cancel := context.WithTimeout(context.Background(), healthRequestTimeout)
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, s.BaseURL+"/health", nil)
		var resp *http.Response
		err := reqErr
		if reqErr == nil {
			resp, err = healthClient.Do(req)
		}
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK && resp.ContentLength <= maxHealthResponseSize {
				cancel()
				return nil
			}
		}
		cancel()
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("llama-server did not become healthy within %s", timeout)
}

// Stop terminates the child process best effort.
func (s *Server) Stop() {
	if s.cmd == nil || s.cmd.Process == nil {
		return
	}
	_ = s.cmd.Process.Kill()
	_, _ = s.cmd.Process.Wait()
	logger.Log.Info("llama-server stopped")
}

// Chat preserves the isolated-question wrapper while using the same role-aware
// llama-server endpoint as conversation work.
func (s *Server) Chat(system, user string) (string, error) {
	return s.ChatMessages(context.Background(), []Message{
		{Role: "system", Content: system},
		{Role: "user", Content: user},
	}, GenerationOptions{})
}

// ChatMessages sends role-aware messages to llama-server. The GGUF chat
// template is applied server-side; roles are never flattened into delimiters.
func (s *Server) ChatMessages(ctx context.Context, messages []Message, options GenerationOptions) (string, error) {
	text, _, err := s.ChatMessagesWithUsage(ctx, messages, options)
	return text, err
}

// ChatMessagesWithUsage also returns the engine's own measurements. PromptTokens
// comes from the same template/tokenizer preflight that guards the window.
func (s *Server) ChatMessagesWithUsage(ctx context.Context, messages []Message, options GenerationOptions) (string, Usage, error) {
	var usage Usage
	if err := validateMessages(messages, options); err != nil {
		return "", usage, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if s.ContextWindowTokens > 0 {
		prompt, err := s.validateContextWindow(ctx, messages, 1)
		if err != nil {
			return "", usage, err
		}
		usage.PromptTokens = prompt
	}
	requestBody := struct {
		Messages    []Message `json:"messages"`
		Stream      bool      `json:"stream"`
		CachePrompt bool      `json:"cache_prompt"`
		Temperature float64   `json:"temperature,omitempty"`
		TopP        float64   `json:"top_p,omitempty"`
	}{
		Messages:    messages,
		Stream:      false,
		CachePrompt: true,
		Temperature: options.Temperature,
		TopP:        options.TopP,
	}
	body, err := json.Marshal(requestBody)
	if err != nil {
		return "", usage, fmt.Errorf("%w: encode request: %v", ErrGeneration, err)
	}

	requestCtx, cancel := context.WithTimeout(ctx, chatRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, s.BaseURL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", usage, fmt.Errorf("%w: create request: %v", ErrGeneration, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := chatClient.Do(req)
	if err != nil {
		return "", usage, fmt.Errorf("%w: %v", ErrGeneration, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", usage, fmt.Errorf("%w: llama-server returned status %d", ErrGeneration, resp.StatusCode)
	}
	if resp.ContentLength > maxChatResponseSize {
		return "", usage, fmt.Errorf("%w: response exceeds the %d-byte limit", ErrGeneration, maxChatResponseSize)
	}
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, maxChatResponseSize+1))
	if err != nil {
		return "", usage, fmt.Errorf("%w: read llama-server response: %v", ErrGeneration, err)
	}
	if int64(len(responseBody)) > maxChatResponseSize {
		return "", usage, fmt.Errorf("%w: response exceeds the %d-byte limit", ErrGeneration, maxChatResponseSize)
	}

	var parsed struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
		// cache_n is reported by recent llama-server builds; absent means zero.
		Timings struct {
			CacheN int `json:"cache_n"`
		} `json:"timings"`
	}
	if err := json.Unmarshal(responseBody, &parsed); err != nil {
		return "", usage, fmt.Errorf("%w: invalid response: %v", ErrGeneration, err)
	}
	if len(parsed.Choices) == 0 {
		return "", usage, fmt.Errorf("%w: llama-server returned no choices", ErrGeneration)
	}
	usage.CompletionTokens = max(0, parsed.Usage.CompletionTokens)
	usage.CachedTokens = max(0, parsed.Timings.CacheN)
	usage.FinishReason = parsed.Choices[0].FinishReason
	if usage.FinishReason != "stop" && usage.FinishReason != "length" {
		usage.FinishReason = ""
	}
	return parsed.Choices[0].Message.Content, usage, nil
}

// PromptOverheadTokens measures the system prompt plus chat-template framing
// that this engine adds before any client message.
func (s *Server) PromptOverheadTokens(system string) (int, error) {
	n, err := s.countPromptTokens(context.Background(), []Message{{Role: "system", Content: system}, {Role: "user", Content: "x"}})
	return max(0, n-1), err
}

// ContextWindowError reports the measured prompt so a client can recalibrate.
type ContextWindowError struct {
	PromptTokens, OutputTokens, Window int
}

func (e *ContextWindowError) Error() string {
	return fmt.Sprintf("%v: prompt=%d output_reserve=%d window=%d", ErrContextWindowExceeded, e.PromptTokens, e.OutputTokens, e.Window)
}
func (e *ContextWindowError) Unwrap() error { return ErrContextWindowExceeded }

// validateContextWindow asks the same local llama-server that will generate the
// answer to render its chat template and tokenize that rendered prompt. This
// catches template overhead and tokenizer differences before inference starts.
func (s *Server) validateContextWindow(ctx context.Context, messages []Message, outputTokens int) (int, error) {
	if s.ContextWindowTokens <= 0 || outputTokens < 0 || outputTokens > s.ContextWindowTokens {
		return 0, ErrContextWindowExceeded
	}
	prompt, err := s.countPromptTokens(ctx, messages)
	if err != nil {
		return 0, err
	}
	if prompt+outputTokens > s.ContextWindowTokens {
		return prompt, &ContextWindowError{PromptTokens: prompt, OutputTokens: outputTokens, Window: s.ContextWindowTokens}
	}
	return prompt, nil
}

// countPromptTokens renders messages with the model template and tokenizes the
// result with the model tokenizer.
func (s *Server) countPromptTokens(ctx context.Context, messages []Message) (int, error) {
	preflightCtx, cancel := context.WithTimeout(ctx, inferencePreflightTimeout)
	defer cancel()
	promptBody, err := json.Marshal(struct {
		Messages []Message `json:"messages"`
	}{Messages: messages})
	if err != nil {
		return 0, fmt.Errorf("%w: encode template request: %v", ErrGeneration, err)
	}
	req, err := http.NewRequestWithContext(preflightCtx, http.MethodPost, s.BaseURL+"/apply-template", bytes.NewReader(promptBody))
	if err != nil {
		return 0, fmt.Errorf("%w: create template request: %v", ErrGeneration, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := chatClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("%w: apply chat template: %v", ErrGeneration, err)
	}
	promptResponse, err := readBoundedResponse(resp)
	if err != nil {
		return 0, fmt.Errorf("%w: apply chat template: %v", ErrGeneration, err)
	}
	var rendered struct {
		Prompt string `json:"prompt"`
	}
	if err := json.Unmarshal(promptResponse, &rendered); err != nil || rendered.Prompt == "" {
		return 0, fmt.Errorf("%w: llama-server returned an invalid chat template", ErrGeneration)
	}

	tokenBody, err := json.Marshal(struct {
		Content    string `json:"content"`
		AddSpecial bool   `json:"add_special"`
	}{Content: rendered.Prompt, AddSpecial: true})
	if err != nil {
		return 0, fmt.Errorf("%w: encode tokenize request: %v", ErrGeneration, err)
	}
	tokenReq, err := http.NewRequestWithContext(preflightCtx, http.MethodPost, s.BaseURL+"/tokenize", bytes.NewReader(tokenBody))
	if err != nil {
		return 0, fmt.Errorf("%w: create tokenize request: %v", ErrGeneration, err)
	}
	tokenReq.Header.Set("Content-Type", "application/json")
	tokenResp, err := chatClient.Do(tokenReq)
	if err != nil {
		return 0, fmt.Errorf("%w: tokenize chat prompt: %v", ErrGeneration, err)
	}
	tokenResponse, err := readBoundedResponse(tokenResp)
	if err != nil {
		return 0, fmt.Errorf("%w: tokenize chat prompt: %v", ErrGeneration, err)
	}
	var tokenized struct {
		Tokens []int `json:"tokens"`
	}
	if err := json.Unmarshal(tokenResponse, &tokenized); err != nil {
		return 0, fmt.Errorf("%w: invalid tokenizer response: %v", ErrGeneration, err)
	}
	return len(tokenized.Tokens), nil
}

func readBoundedResponse(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("llama-server returned status %d", resp.StatusCode)
	}
	if resp.ContentLength > maxChatResponseSize {
		return nil, fmt.Errorf("response exceeds the %d-byte limit", maxChatResponseSize)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxChatResponseSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxChatResponseSize {
		return nil, fmt.Errorf("response exceeds the %d-byte limit", maxChatResponseSize)
	}
	return body, nil
}

const (
	maxChatRequestBytes = 1 << 20
)

func validateMessages(messages []Message, options GenerationOptions) error {
	if len(messages) == 0 || len(messages) > MaxConversationMessages ||
		options.Temperature < 0 || options.Temperature > 2 ||
		options.TopP < 0 || options.TopP > 1 {
		return ErrInvalidMessages
	}
	totalBytes := 0
	for _, message := range messages {
		if message.Content == "" || strings.TrimSpace(message.Role) != message.Role {
			return ErrInvalidMessages
		}
		switch message.Role {
		case "system", "user", "assistant":
		default:
			return ErrInvalidMessages
		}
		totalBytes += len(message.Role) + len(message.Content)
		if totalBytes > maxChatRequestBytes {
			return ErrInvalidMessages
		}
	}
	return nil
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
