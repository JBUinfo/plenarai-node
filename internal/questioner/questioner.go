package questioner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/plenarai/cli/internal/auth"
	"github.com/plenarai/cli/internal/config"
)

type AskResponse struct {
	QuestionID    string `json:"id"`
	Status        string `json:"status"`
	QueuePosition int    `json:"queue_position,omitempty"`
}

type QuestionResult struct {
	Status string  `json:"status"`
	Answer string  `json:"answer"`
	Score  float64 `json:"score"`
}

func Ask(question, nodeID string) (*AskResponse, error) {
	payload := map[string]string{"question": question}
	if nodeID != "" {
		payload["target_node_id"] = nodeID
	}
	body, _ := json.Marshal(payload)
	resp, err := auth.DoAuthenticated(func() (*http.Request, error) {
		req, err := http.NewRequest(http.MethodPost, config.ServerURL+"/v0/questions", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	})
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		var apiError struct {
			Error string `json:"error"`
		}
		if json.NewDecoder(resp.Body).Decode(&apiError) == nil && apiError.Error != "" {
			return nil, fmt.Errorf("%s", formatQuestionError(apiError.Error))
		}
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	var result AskResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func formatQuestionError(message string) string {
	if strings.EqualFold(strings.TrimSpace(message), "insufficient credits") {
		return fmt.Sprintf("insufficient credits. Buy more credits at %s", strings.TrimRight(config.ServerURL, "/")+"/wallet")
	}
	return message
}

func PollResult(questionID string) (*QuestionResult, error) {
	resp, err := auth.DoAuthenticated(func() (*http.Request, error) {
		return http.NewRequest(http.MethodGet, config.ServerURL+"/v0/questions/"+questionID, nil)
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("poll failed (status %d)", resp.StatusCode)
	}

	var result QuestionResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}
