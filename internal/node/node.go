package node

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/spf13/viper"

	"github.com/plenarai/cli/internal/auth"
	"github.com/plenarai/cli/internal/config"
	"github.com/plenarai/cli/internal/crypto"
	"github.com/plenarai/cli/internal/inference"
	"github.com/plenarai/cli/internal/opaque"
	"github.com/plenarai/cli/internal/securework"
	"github.com/plenarai/cli/internal/security"
	"github.com/plenarai/cli/internal/update"
	"github.com/plenarai/cli/logger"
)

type Config struct {
	PromptFile          string
	ConfigDir           string
	Model               string
	OllamaURL           string
	ModelPath           string // custom GGUF; when set, the bundled llama-server is used
	ContextWindowTokens int    // local llama.cpp context window; zero uses the default
	ScoreOnly           bool   // judge answers but never respond to questions
}

type wsMessage struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

type questionPayload struct {
	ProtocolVersion      int    `json:"protocol_version"`
	WorkKind             string `json:"work_kind,omitempty"`
	QuestionID           string `json:"question_id"`
	ContextID            string `json:"context_id,omitempty"`
	ContextSchemaVersion int    `json:"context_schema_version,omitempty"`
	AssignmentDigest     string `json:"assignment_digest,omitempty"`
	EncryptedContext     []byte `json:"encrypted_context,omitempty"`
	EncryptedQuestion    []byte `json:"encrypted_question"`
	EncryptedKey         []byte `json:"encrypted_key"`
	ServerPublicKey      []byte `json:"server_public_key"`
}

const (
	questionQueueCapacity = 64
	scoreQueueCapacity    = 32
)

func Run(cfg Config) error {
	// Generation ends at EOS or the model's context boundary, without a platform token cap.
	if cfg.ContextWindowTokens == 0 {
		cfg.ContextWindowTokens = inference.DefaultContextWindowTokens
	}
	if cfg.ContextWindowTokens < inference.DefaultContextWindowTokens || cfg.ContextWindowTokens > inference.MaxContextWindowTokens {
		return fmt.Errorf("context-window-tokens must be between %d and %d", inference.DefaultContextWindowTokens, inference.MaxContextWindowTokens)
	}
	// Anti-debugging check
	if err := security.CheckDebugger(); err != nil {
		return err
	}

	// Binary integrity check
	if err := security.VerifyBinaryIntegrity(); err != nil {
		return err
	}

	// Start periodic memory scrubbing (every 30 seconds)
	security.StartPeriodicScrub(30 * time.Second)

	if _, err := auth.LoadTokens(); err != nil {
		return fmt.Errorf("not logged in: %w", err)
	}

	privKey, err := crypto.LoadOrGenerateKey(cfg.ConfigDir)
	if err != nil {
		return fmt.Errorf("key generation failed: %w", err)
	}

	// Register public key with server
	if err := registerPublicKey(privKey.PublicKey().Bytes()); err != nil {
		return fmt.Errorf("failed to register public key: %w", err)
	}
	fmt.Println("Public key registered with server.")
	fmt.Println("Security class: standard (secure protocol enabled; host confidentiality is not hardware-verified).")

	// Verify stake before connecting
	if err := verifyStake(); err != nil {
		return fmt.Errorf("stake required: %w", err)
	}

	// Prepare the inference engine before going online.
	displayModel := cfg.Model
	if cfg.ModelPath == "" {
		if saved := viper.GetString("llama.model_path"); saved != "" {
			cfg.ModelPath = saved
		}
	}
	if cfg.ModelPath == "" && cfg.ContextWindowTokens != inference.DefaultContextWindowTokens {
		return fmt.Errorf("generation limits require a local GGUF model")
	}
	eng := &engine{model: cfg.Model, ollamaURL: cfg.OllamaURL}
	if cfg.ModelPath != "" {
		serverBin := viper.GetString("llama.server_bin")
		if serverBin == "" {
			return fmt.Errorf("llama-server not configured; run 'plenarai setup' first")
		}
		fmt.Println("Starting local model engine...")
		srv, err := inference.StartWithContextWindow(serverBin, cfg.ModelPath, cfg.ContextWindowTokens)
		if err != nil {
			return err
		}
		defer srv.Stop()
		eng.llama = srv
		displayModel = strings.TrimSuffix(filepath.Base(cfg.ModelPath), ".gguf")
		fmt.Printf("Local engine ready (%s).\n", displayModel)
	} else {
		// Legacy Ollama mode: fail fast with actionable guidance instead of
		// cryptic per-request errors once the node is online.
		if err := probeOllama(cfg.OllamaURL); err != nil {
			return err
		}
		fmt.Printf("Using legacy Ollama engine at %s (model: %s).\n", cfg.OllamaURL, displayModel)
	}

	// Report which model this node runs so rankings/profiles can show it.
	go reportModel(displayModel)

	promptTemplate, err := loadPromptFile(cfg.PromptFile)
	if err != nil {
		return fmt.Errorf("failed to load prompt: %w", err)
	}

	wsURL := strings.Replace(config.ServerURL, "http", "ws", 1) + "/v0/ws/node"

	if cfg.ScoreOnly {
		fmt.Println("Score-only mode: this node judges answers but does not respond to questions.")
	}
	contextWindowTokens := inference.DefaultContextWindowTokens
	if eng.llama != nil && eng.llama.ContextWindowTokens > 0 {
		contextWindowTokens = eng.llama.ContextWindowTokens
	}
	capabilities := nodeCapabilities(displayModel, cfg, contextWindowTokens)
	if eng.llama != nil && capabilities.ContextWindowTokens > 0 {
		// Encrypted-chat clients budget with this; the tokenizer still decides.
		if overhead, e := eng.llama.PromptOverheadTokens(promptTemplate); e == nil && overhead < capabilities.ContextWindowTokens {
			capabilities.PromptOverheadTokens = overhead
		}
	}
	if cfg.ModelPath != "" && !cfg.ScoreOnly {
		capabilities.Capabilities = append(capabilities.Capabilities, opaque.Capability)
		capabilities.OpaqueSigningKey = []byte(securework.SigningKey(privKey.Bytes()).Public().(ed25519.PublicKey))
		fmt.Printf("Provider identity fingerprint: %s\\n", opaque.Fingerprint(privKey.PublicKey().Bytes(), capabilities.OpaqueSigningKey))
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	conn := NewSafeConn(nil)
	questionJobs := make(chan json.RawMessage, questionQueueCapacity)
	scoreJobs := make(chan json.RawMessage, scoreQueueCapacity)

	// Non-blocking update notice so long-running nodes learn about new releases
	go func() {
		if tag, ok := update.CheckAvailable(); ok {
			fmt.Printf("New version available: %s. Run 'plenarai update' after stopping the node.\n", tag)
		}
	}()

	go func() {
		for data := range questionJobs {
			if cfg.ScoreOnly {
				logger.Log.Info("score-only mode: ignoring question")
				continue
			}
			handleQuestion(conn, privKey, data, eng, promptTemplate)
		}
	}()
	go func() {
		for data := range scoreJobs {
			handleScoreRequest(conn, privKey, data, eng)
		}
	}()

	return runNode(conn, wsURL, quit, questionJobs, scoreJobs, capabilities)
}

// runNode keeps the node online: it dials with a fresh token, serves until the
// connection drops and reconnects with exponential backoff until Ctrl+C.
func runNode(conn *SafeConn, wsURL string, quit <-chan os.Signal, questionJobs, scoreJobs chan json.RawMessage, capabilities securework.CapabilityAnnouncement) error {
	backoff := 2 * time.Second
	for {
		rawConn, err := dial(wsURL)
		if err != nil {
			logger.Log.Warn("connection failed", "error", err)
		} else {
			if old := conn.Swap(rawConn); old != nil {
				old.Close()
			}
			if err := announceCapabilities(conn, capabilities); err != nil {
				logger.Log.Warn("could not announce node capabilities", "error", err)
				_ = conn.Close()
			} else {
				fmt.Println("Connected as node. Waiting for questions...")
				backoff = 2 * time.Second

				disconnected := make(chan error, 1)
				go func() {
					disconnected <- pumpMessages(conn, questionJobs, scoreJobs)
				}()

				select {
				case serr := <-disconnected:
					if !isExpectedClose(serr) {
						logger.Log.Warn("connection lost; reconnecting", "error", serr)
						fmt.Println("Connection lost; reconnecting...")
					}
				case <-quit:
					shutdownConn(conn)
					return nil
				}
			}
		}

		select {
		case <-quit:
			shutdownConn(conn)
			return nil
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func nodeCapabilities(modelName string, cfg Config, contextWindowTokens int) securework.CapabilityAnnouncement {
	engine := "ollama"
	if cfg.ModelPath != "" {
		engine = "llama.cpp"
	}
	capabilities := securework.CapabilityAnnouncement{
		ProtocolVersion: securework.CapabilityProtocolVersion,
		Capabilities:    []string{securework.CapabilityQuestionV1},
		ModelID:         modelName,
		Engine:          engine,
		Template:        "question-v1",
		MaxPayloadBytes: securework.MaxNodePayloadBytes,
	}
	if cfg.ModelPath != "" {
		capabilities.Capabilities = append(capabilities.Capabilities, securework.CapabilityConversationContext)
		capabilities.Template = "chat-v1"
		capabilities.ContextWindowTokens = contextWindowTokens
		capabilities.SupportsRoles = true
	}
	return capabilities
}

func announceCapabilities(conn *SafeConn, capabilities securework.CapabilityAnnouncement) error {
	payload, err := json.Marshal(capabilities)
	if err != nil {
		return err
	}
	data, err := json.Marshal(wsMessage{Type: "capabilities", Data: payload})
	if err != nil {
		return err
	}
	return conn.WriteMessage(websocket.TextMessage, data)
}

// shutdownConn sends a polite close frame best effort.
func shutdownConn(conn *SafeConn) {
	fmt.Println("\nShutting down node...")
	if c := conn.Swap(nil); c != nil {
		c.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(3*time.Second))
		c.Close()
	}
}

// probeOllama verifies a legacy Ollama instance is reachable before the node
// goes online, so misconfiguration surfaces as a clear startup error.
func probeOllama(baseURL string) error {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(baseURL + "/api/version")
	if err != nil {
		return fmt.Errorf("no inference engine available: nothing answered at %s (legacy Ollama mode).\nRun 'plenarai setup' to install the bundled llama.cpp engine, or start Ollama with 'ollama serve'", baseURL)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("legacy Ollama at %s answered with status %d; run 'plenarai setup' to switch to the bundled engine", baseURL, resp.StatusCode)
	}
	return nil
}

func isExpectedClose(err error) bool {
	var ce *websocket.CloseError
	if !errors.As(err, &ce) {
		return false
	}
	return ce.Code == websocket.CloseNormalClosure || ce.Code == websocket.CloseGoingAway
}

func dial(wsURL string) (*websocket.Conn, error) {
	// Long-lived nodes outlive access tokens; refresh before each attempt.
	if rerr := auth.Refresh(); rerr != nil {
		logger.Log.Warn("token refresh failed; trying stored token", "error", rerr)
	}
	wsHeader, err := auth.AuthHeader()
	if err != nil {
		return nil, err
	}
	headers := http.Header{}
	headers.Set("Authorization", wsHeader)
	c, resp, err := websocket.DefaultDialer.Dial(wsURL, headers)
	if err != nil && resp != nil {
		switch resp.StatusCode {
		case http.StatusTooManyRequests:
			return nil, fmt.Errorf("rejected: too many node connections from your IP (server limit reached)")
		case http.StatusUnauthorized:
			return nil, fmt.Errorf("session expired: run 'plenarai login' again")
		default:
			return nil, fmt.Errorf("connection rejected with status %d", resp.StatusCode)
		}
	}
	return c, err
}

// pumpMessages reads from the connection and dispatches jobs until an error.
func pumpMessages(conn *SafeConn, questionJobs, scoreJobs chan json.RawMessage) error {
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return err
		}

		var msg wsMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			logger.Log.Warn("invalid message", "error", err)
			continue
		}

		switch msg.Type {
		case "question", "opaque_question":
			questionJobs <- msg.Data
		case "score_request":
			scoreJobs <- msg.Data
		case "result":
			fmt.Printf("Result received: %s\n", string(msg.Data))
		case "error":
			fmt.Printf("Server error: %s\n", string(msg.Data))
		}
	}
}

func registerPublicKey(publicKey []byte) error {
	body, _ := json.Marshal(map[string][]byte{"public_key": publicKey})
	resp, err := auth.DoAuthenticated(func() (*http.Request, error) {
		req, err := http.NewRequest(http.MethodPost, config.ServerURL+"/v0/users/me/public-key", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	return nil
}

// reportMinCost publishes this node's minimum accepted question price.
func reportMinCost(minCost float64) {
	body, _ := json.Marshal(map[string]float64{"min_cost": minCost})
	resp, err := auth.DoAuthenticated(func() (*http.Request, error) {
		req, err := http.NewRequest(http.MethodPost, config.ServerURL+"/v0/node/min-cost", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	})
	if err != nil {
		logger.Log.Warn("could not report min cost", "error", err)
		return
	}
	defer resp.Body.Close()
}

// reportModel publishes the model identifier this node runs. Best effort:
// a failure only means rankings/profiles show an older or empty value.
func reportModel(modelName string) {
	if modelName == "" {
		return
	}
	body, _ := json.Marshal(map[string]string{"model_name": modelName})
	resp, err := auth.DoAuthenticated(func() (*http.Request, error) {
		req, err := http.NewRequest(http.MethodPost, config.ServerURL+"/v0/node/model", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	})
	if err != nil {
		logger.Log.Warn("could not report model name", "error", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		logger.Log.Warn("model report rejected", "status", resp.StatusCode)
	}
}

func verifyStake() error {
	resp, err := auth.DoAuthenticated(func() (*http.Request, error) {
		return http.NewRequest(http.MethodGet, config.ServerURL+"/v0/node/stake", nil)
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result struct {
		StakeAmount float64 `json:"stake_amount"`
		IsSuspended bool    `json:"is_suspended"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	if result.IsSuspended {
		return fmt.Errorf("your node is suspended. Run 'plenarai node --stake N' to add credits and unsuspend")
	}
	if result.StakeAmount < 5.0 {
		return fmt.Errorf("minimum 5.0 credits stake required (current: %.1f). Run 'plenarai node --stake 5' to deposit", result.StakeAmount)
	}
	return nil
}

func loadPromptFile(path string) (string, error) {
	if path == "" {
		return "You are a helpful AI assistant. Answer the following question accurately and concisely.", nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
