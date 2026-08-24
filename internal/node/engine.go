package node

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/plenarai/cli/internal/crypto"
	"github.com/plenarai/cli/internal/inference"
	"github.com/plenarai/cli/logger"
)

// engine runs completions either through the bundled llama-server (llama.cpp)
// or through a legacy local Ollama instance. Question content stays on the
// machine in both cases.
type engine struct {
	llama      *inference.Server
	model      string // ollama model tag (legacy path)
	ollamaURL  string
	displayName string
}

func (e *engine) complete(system, user string) string {
	if e.llama != nil {
		out, err := e.llama.Chat(system, user)
		if err != nil {
			logger.Log.Error("local model request failed", "error", err)
			return fmt.Sprintf("Error: local AI model failed (%v)", err)
		}
		return out
	}
	return e.queryOllama(system + "\n\n" + user)
}

// queryOllama is the legacy single-prompt Ollama path (/api/generate).
func (e *engine) queryOllama(prompt string) string {
	if e.model == "" {
		e.model = "llama3"
	}

	body := []byte(fmt.Sprintf(`{"model":%q,"prompt":%q,"stream":false}`, e.model, prompt))
	defer crypto.ZeroBytes(body)

	resp, err := http.Post(e.ollamaURL+"/api/generate", "application/json", bytes.NewReader(body))
	if err != nil {
		logger.Log.Error("ollama request failed", "error", err)
		return fmt.Sprintf("Error: could not reach local AI model (%v)", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "Error: failed to read AI response"
	}
	defer crypto.ZeroBytes(respBody)

	var result struct {
		Response string `json:"response"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "Error: invalid AI response format"
	}
	return result.Response
}
