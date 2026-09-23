package conversationer

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/plenarai/cli/internal/auth"
	"github.com/plenarai/cli/internal/config"
)

type Conversation struct {
	ID             string  `json:"id"`
	Revision       int64   `json:"revision"`
	NextMessageSeq int64   `json:"next_message_seq"`
	ActiveTurnID   *string `json:"active_turn_id,omitempty"`
	Title          string  `json:"title,omitempty"`
}

type Message struct {
	ID             string `json:"id"`
	ConversationID string `json:"conversation_id"`
	MessageSeq     int64  `json:"message_seq"`
	Role           string `json:"role"`
	Content        string `json:"content"`
	Provenance     string `json:"provenance"`
}

type Constraint struct {
	ID              string  `json:"id"`
	ConversationID  string  `json:"conversation_id,omitempty"`
	Text            string  `json:"text"`
	SourceMessageID *string `json:"source_message_id,omitempty"`
	Revision        int64   `json:"revision"`
	Provenance      string  `json:"provenance"`
	CreatedAt       string  `json:"created_at,omitempty"`
}

type ConstraintInput struct {
	Text            string `json:"text"`
	SourceMessageID string `json:"source_message_id,omitempty"`
}

type ContextBudgetMetadata struct {
	TokenBudget               int    `json:"token_budget"`
	ByteBudget                int    `json:"byte_budget"`
	MessageBudget             int    `json:"message_budget"`
	ReservedTokens            int    `json:"reserved_tokens"`
	ReservedBytes             int    `json:"reserved_bytes"`
	OutputReserveTokens       int    `json:"output_reserve_tokens"`
	EstimatedTokens           int    `json:"estimated_tokens"`
	Bytes                     int    `json:"bytes"`
	Messages                  int    `json:"messages"`
	TokenEstimateKind         string `json:"token_estimate_kind"`
	OmittedHistory            bool   `json:"omitted_history"`
	IncludedExchangeCount     int    `json:"included_exchange_count"`
	OmittedExchangeCount      int    `json:"omitted_exchange_count"`
	OmittedExchangeCountExact bool   `json:"omitted_exchange_count_exact"`
}

type ContextPreview struct {
	SchemaVersion       int                   `json:"schema_version"`
	ContextID           string                `json:"context_id"`
	ConversationID      string                `json:"conversation_id"`
	TurnID              string                `json:"turn_id"`
	BaseRevision        int64                 `json:"base_revision"`
	PolicyVersion       string                `json:"policy_version"`
	PromptVersion       string                `json:"prompt_version"`
	SourceMessageIDs    []string              `json:"source_message_ids"`
	ExplicitConstraints []Constraint          `json:"explicit_constraints"`
	RecentMessages      []Message             `json:"recent_messages"`
	CurrentMessage      Message               `json:"current_message"`
	BudgetMetadata      ContextBudgetMetadata `json:"budget_metadata"`
}

type TurnRequest struct {
	ExpectedRevision     int64   `json:"expected_revision"`
	Message              string  `json:"message"`
	Mode                 string  `json:"mode"`
	TargetNodeID         string  `json:"target_node_id,omitempty"`
	MinimumSecurityClass string  `json:"minimum_security_class,omitempty"`
	CostCredits          float64 `json:"cost,omitempty"`
}

const MaxTurnMessageBytes = 8192

// PendingTurn is written before the HTTP request so a lost response can be
// reconciled with the exact same idempotency key after a CLI restart. The
// message itself is kept in memory only; the sidecar stores its digest and
// request metadata so it cannot become a second plaintext history.
type PendingTurn struct {
	IdempotencyKey string
	Request        TurnRequest
	MessageDigest  string
}

const pendingTurnRecordVersion = 1

type pendingTurnRecord struct {
	Version              int     `json:"version"`
	IdempotencyKey       string  `json:"idempotency_key"`
	ExpectedRevision     int64   `json:"expected_revision"`
	MessageDigest        string  `json:"message_digest"`
	Mode                 string  `json:"mode"`
	TargetNodeID         string  `json:"target_node_id,omitempty"`
	MinimumSecurityClass string  `json:"minimum_security_class,omitempty"`
	CostCredits          float64 `json:"cost,omitempty"`
}

// APIError means the server returned an HTTP response for the request. A
// transport error has no APIError and therefore remains retryable with the
// same idempotency key.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("server returned status %d", e.StatusCode)
	}
	return fmt.Sprintf("server returned %d: %s", e.StatusCode, e.Message)
}

// Definitive reports whether the server explicitly rejected the submission.
// Gateway and rate-limit responses remain pending because a POST may have
// reached the backend even when the client did not receive a successful reply.
func (e *APIError) Definitive() bool {
	if e == nil || e.StatusCode < http.StatusBadRequest || e.StatusCode >= http.StatusInternalServerError {
		return false
	}
	switch e.StatusCode {
	case http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests:
		return false
	default:
		return true
	}
}

func IsDefinitiveAPIError(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Definitive()
}

func MessageDigest(message string) string {
	digest := sha256.Sum256([]byte(message))
	return hex.EncodeToString(digest[:])
}

type TurnReceipt struct {
	ConversationID string `json:"conversation_id"`
	Revision       int64  `json:"revision"`
	MessageID      string `json:"message_id"`
	TurnID         string `json:"turn_id"`
	QuestionID     string `json:"question_id"`
	State          string `json:"state"`
}

type Turn struct {
	ID          string  `json:"id"`
	State       string  `json:"state"`
	FailureCode *string `json:"failure_code,omitempty"`
	CompletedAt *string `json:"completed_at,omitempty"`
}

type TurnView struct {
	Conversation Conversation `json:"conversation"`
	Message      Message      `json:"message"`
	Turn         Turn         `json:"turn"`
	Assistant    *Message     `json:"assistant,omitempty"`
	QuestionID   string       `json:"question_id"`
}

func Create(title string) (*Conversation, error) {
	var result Conversation
	err := request(http.MethodPost, "/v0/conversations", map[string]string{"title": title}, nil, &result, http.StatusCreated)
	return &result, err
}

func Get(conversationID string) (*Conversation, error) {
	var result Conversation
	err := request(http.MethodGet, "/v0/conversations/"+url.PathEscape(conversationID), nil, nil, &result, http.StatusOK)
	return &result, err
}

func History(conversationID string, limit int) ([]Message, error) {
	var result []Message
	path := fmt.Sprintf("/v0/conversations/%s/messages?limit=%d", url.PathEscape(conversationID), limit)
	err := request(http.MethodGet, path, nil, nil, &result, http.StatusOK)
	return result, err
}

func Constraints(conversationID string) ([]Constraint, error) {
	var result []Constraint
	err := request(http.MethodGet, "/v0/conversations/"+url.PathEscape(conversationID)+"/constraints", nil, nil, &result, http.StatusOK)
	return result, err
}

func ReplaceConstraints(conversationID string, expectedRevision int64, constraints []ConstraintInput) (*Conversation, []Constraint, error) {
	var result struct {
		Conversation Conversation `json:"conversation"`
		Constraints  []Constraint `json:"constraints"`
	}
	err := request(http.MethodPut, "/v0/conversations/"+url.PathEscape(conversationID)+"/constraints", map[string]interface{}{
		"expected_revision": expectedRevision,
		"constraints":       constraints,
	}, nil, &result, http.StatusOK)
	return &result.Conversation, result.Constraints, err
}

func PreviewContext(conversationID, message string, modes ...string) (*ContextPreview, error) {
	var result ContextPreview
	input := map[string]string{"message": message}
	if len(modes) > 0 {
		input["mode"] = modes[0]
	}
	err := request(http.MethodPost, "/v0/conversations/"+url.PathEscape(conversationID)+"/context-preview", input, nil, &result, http.StatusOK)
	return &result, err
}

func PreviewContextFor(conversationID, message, mode, targetNodeID, minimumSecurityClass string, costCredits float64) (*ContextPreview, error) {
	var result ContextPreview
	input := map[string]interface{}{
		"message": message,
		"mode":    mode,
		"cost":    costCredits,
	}
	if targetNodeID != "" {
		input["target_node_id"] = targetNodeID
	}
	if minimumSecurityClass != "" {
		input["minimum_security_class"] = minimumSecurityClass
	}
	err := request(http.MethodPost, "/v0/conversations/"+url.PathEscape(conversationID)+"/context-preview", input, nil, &result, http.StatusOK)
	return &result, err
}

func DeleteConversation(conversationID string) error {
	return request(http.MethodDelete, "/v0/conversations/"+url.PathEscape(conversationID), nil, nil, nil, http.StatusNoContent)
}

func CreateTurn(conversationID, idempotencyKey string, input TurnRequest) (*TurnReceipt, error) {
	var result TurnReceipt
	err := request(http.MethodPost, "/v0/conversations/"+url.PathEscape(conversationID)+"/turns", input, map[string]string{
		"Idempotency-Key": idempotencyKey,
	}, &result, http.StatusAccepted)
	return &result, err
}

// ReconcileTurn finds a turn accepted under an idempotency key without
// resending its message. A 204 means the server has no record of the key.
func ReconcileTurn(conversationID, idempotencyKey string) (*TurnReceipt, bool, error) {
	var result TurnReceipt
	path := "/v0/conversations/" + url.PathEscape(conversationID) + "/turns/by-idempotency/" + url.PathEscape(idempotencyKey)
	err := request(http.MethodGet, path, nil, nil, &result, http.StatusOK, http.StatusNoContent)
	if err != nil {
		return nil, false, err
	}
	if result.TurnID == "" {
		return nil, false, nil
	}
	return &result, true, nil
}

func GetTurn(conversationID, turnID string) (*TurnView, error) {
	var result TurnView
	err := request(http.MethodGet, "/v0/conversations/"+url.PathEscape(conversationID)+"/turns/"+url.PathEscape(turnID), nil, nil, &result, http.StatusOK)
	return &result, err
}

func NewIdempotencyKey() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16]), nil
}

func SavePendingTurn(conversationID string, pending PendingTurn) error {
	if strings.TrimSpace(pending.IdempotencyKey) == "" || strings.TrimSpace(pending.Request.Message) == "" || len(pending.Request.Message) > MaxTurnMessageBytes {
		return errors.New("invalid pending conversation turn")
	}
	digest := MessageDigest(pending.Request.Message)
	if pending.MessageDigest != "" && pending.MessageDigest != digest {
		return errors.New("pending conversation turn message digest mismatch")
	}
	path, err := pendingTurnPath(conversationID, true)
	if err != nil {
		return err
	}
	data, err := json.Marshal(pendingTurnRecord{
		Version:              pendingTurnRecordVersion,
		IdempotencyKey:       pending.IdempotencyKey,
		ExpectedRevision:     pending.Request.ExpectedRevision,
		MessageDigest:        digest,
		Mode:                 pending.Request.Mode,
		TargetNodeID:         pending.Request.TargetNodeID,
		MinimumSecurityClass: pending.Request.MinimumSecurityClass,
		CostCredits:          pending.Request.CostCredits,
	})
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".chat-pending-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func LoadPendingTurn(conversationID string) (*PendingTurn, error) {
	path, err := pendingTurnPath(conversationID, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var record pendingTurnRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("invalid pending conversation turn: %w", err)
	}
	if record.Version != pendingTurnRecordVersion {
		// Migrate the pre-metadata sidecar once, then immediately replace it
		// with the metadata-only representation.
		var legacy struct {
			IdempotencyKey string      `json:"idempotency_key"`
			Request        TurnRequest `json:"request"`
		}
		if err := json.Unmarshal(data, &legacy); err != nil || strings.TrimSpace(legacy.Request.Message) == "" {
			return nil, errors.New("invalid pending conversation turn")
		}
		pending := PendingTurn{IdempotencyKey: legacy.IdempotencyKey, Request: legacy.Request}
		if err := SavePendingTurn(conversationID, pending); err != nil {
			return nil, err
		}
		pending.Request.Message = legacy.Request.Message
		pending.MessageDigest = MessageDigest(legacy.Request.Message)
		return &pending, nil
	}
	if strings.TrimSpace(record.IdempotencyKey) == "" || !validMessageDigest(record.MessageDigest) || strings.TrimSpace(record.Mode) == "" {
		return nil, errors.New("invalid pending conversation turn")
	}
	pending := &PendingTurn{
		IdempotencyKey: record.IdempotencyKey,
		MessageDigest:  record.MessageDigest,
		Request: TurnRequest{
			ExpectedRevision:     record.ExpectedRevision,
			Mode:                 record.Mode,
			TargetNodeID:         record.TargetNodeID,
			MinimumSecurityClass: record.MinimumSecurityClass,
			CostCredits:          record.CostCredits,
		},
	}
	return pending, nil
}

func validMessageDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func DeletePendingTurn(conversationID string) error {
	path, err := pendingTurnPath(conversationID, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := os.Remove(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else {
		return err
	}
}

func pendingTurnPath(conversationID string, prepare bool) (string, error) {
	if strings.TrimSpace(conversationID) == "" {
		return "", errors.New("conversation ID is required")
	}
	dir := auth.ConfigDir()
	if prepare {
		if info, err := os.Lstat(dir); err == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return "", fmt.Errorf("config path is not a directory: %s", dir)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return "", err
		}
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("config path is not a directory: %s", dir)
	}
	digest := sha256.Sum256([]byte(conversationID))
	path := filepath.Join(dir, "chat-pending-"+hex.EncodeToString(digest[:])+".json")
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return "", fmt.Errorf("pending turn path is not a regular file: %s", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	return path, nil
}

func request(method, path string, body interface{}, headers map[string]string, output interface{}, expected ...int) error {
	var payload []byte
	var err error
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	resp, err := auth.DoAuthenticated(func() (*http.Request, error) {
		var reader *bytes.Reader
		if payload == nil {
			reader = bytes.NewReader(nil)
		} else {
			reader = bytes.NewReader(payload)
		}
		req, err := http.NewRequest(method, strings.TrimRight(config.ServerURL, "/")+path, reader)
		if err != nil {
			return nil, err
		}
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		return req, nil
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	statusExpected := false
	for _, candidate := range expected {
		if resp.StatusCode == candidate {
			statusExpected = true
			break
		}
	}
	if !statusExpected {
		var apiError struct {
			Error string `json:"error"`
		}
		if json.NewDecoder(resp.Body).Decode(&apiError) == nil && apiError.Error != "" {
			return &APIError{StatusCode: resp.StatusCode, Message: apiError.Error}
		}
		return &APIError{StatusCode: resp.StatusCode}
	}
	if output == nil || resp.StatusCode == http.StatusNoContent || resp.ContentLength == 0 {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(output)
}
