// Package inference manages the local llama-server child process and talks to
// its HTTP API. The server binds to localhost only; question content never
// leaves the machine.
package inference

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"time"

	"github.com/plenarai/cli/logger"
)

// Server is a running llama-server child process.
type Server struct {
	cmd     *exec.Cmd
	BaseURL string
}

// Start launches llama-server with the given model on a free localhost port
// and waits until its health endpoint responds.
func Start(serverBin, modelPath string) (*Server, error) {
	port, err := freePort()
	if err != nil {
		return nil, fmt.Errorf("no free port: %w", err)
	}

	cmd := exec.Command(serverBin,
		"--model", modelPath,
		"--host", "127.0.0.1",
		"--port", fmt.Sprint(port),
		"--ctx-size", "4096",
	)
	// Route engine output to the OS log sink so it never pollutes the TUI.
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("could not start llama-server: %w", err)
	}

	s := &Server{cmd: cmd, BaseURL: fmt.Sprintf("http://127.0.0.1:%d", port)}
	if err := s.waitHealthy(60 * time.Second); err != nil {
		s.Stop()
		return nil, err
	}
	return s, nil
}

func (s *Server) waitHealthy(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s.cmd.ProcessState != nil && s.cmd.ProcessState.Exited() {
			return fmt.Errorf("llama-server exited during startup")
		}
		resp, err := http.Get(s.BaseURL + "/health")
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
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

// Chat sends a system+user turn to llama-server's chat endpoint and returns
// the assistant reply. The GGUF chat template is applied server-side.
func (s *Server) Chat(system, user string) (string, error) {
	body, _ := json.Marshal(map[string]interface{}{
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
		"stream":      false,
		"cache_prompt": true,
	})

	resp, err := http.Post(s.BaseURL+"/v1/chat/completions", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("llama-server returned status %d", resp.StatusCode)
	}

	var parsed struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return "", err
	}
	if len(parsed.Choices) == 0 {
		return "", fmt.Errorf("llama-server returned no choices")
	}
	return parsed.Choices[0].Message.Content, nil
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
