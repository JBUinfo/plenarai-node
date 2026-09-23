package securework

import (
	"errors"
	"strings"
)

var ErrInvalidConversationContext = errors.New("invalid conversation context")

type ContextMessage struct {
	ID             string `json:"id"`
	ConversationID string `json:"conversation_id"`
	MessageSeq     int64  `json:"message_seq"`
	Role           string `json:"role"`
	Content        string `json:"content"`
	Provenance     string `json:"provenance"`
}

type ContextExchange struct {
	User      ContextMessage `json:"user"`
	Assistant ContextMessage `json:"assistant"`
}

type ContextConstraint struct {
	ID              string `json:"id"`
	Text            string `json:"text"`
	SourceMessageID string `json:"source_message_id,omitempty"`
	Revision        int64  `json:"revision"`
	Provenance      string `json:"provenance"`
}

type ContextSummary struct {
	Version          int64    `json:"version"`
	Text             string   `json:"text"`
	SourceMessageIDs []string `json:"source_message_ids"`
}

type ContextFragment struct {
	ID              string `json:"id"`
	SourceMessageID string `json:"source_message_id"`
	Position        int    `json:"position"`
	Text            string `json:"text"`
}

type ContextBudgetMetadata struct {
	TokenBudget               int    `json:"token_budget"`
	ByteBudget                int    `json:"byte_budget"`
	MessageBudget             int    `json:"message_budget"`
	ReservedTokens            int    `json:"reserved_tokens"`
	ReservedBytes             int    `json:"reserved_bytes"`
	EstimatedTokens           int    `json:"estimated_tokens"`
	Bytes                     int    `json:"bytes"`
	Messages                  int    `json:"messages"`
	CandidateReserveTokens    int    `json:"candidate_reserve_tokens,omitempty"`
	CandidateReserveBytes     int    `json:"candidate_reserve_bytes,omitempty"`
	TokenEstimateKind         string `json:"token_estimate_kind"`
	OmittedHistory            bool   `json:"omitted_history"`
	IncludedExchangeCount     int    `json:"included_exchange_count"`
	OmittedExchangeCount      int    `json:"omitted_exchange_count"`
	OmittedExchangeCountExact bool   `json:"omitted_exchange_count_exact"`
	OutputReserveTokens       int    `json:"output_reserve_tokens,omitempty"`
}

type ContextBundle struct {
	SchemaVersion       int                   `json:"schema_version"`
	ContextID           string                `json:"context_id"`
	ConversationID      string                `json:"conversation_id"`
	TurnID              string                `json:"turn_id"`
	BaseRevision        int64                 `json:"base_revision"`
	PolicyVersion       string                `json:"policy_version"`
	PromptVersion       string                `json:"prompt_version"`
	SourceMessageIDs    []string              `json:"source_message_ids"`
	ExplicitConstraints []ContextConstraint   `json:"explicit_constraints"`
	Summary             *ContextSummary       `json:"summary,omitempty"`
	RecentMessages      []ContextMessage      `json:"recent_messages"`
	RetrievedFragments  []ContextFragment     `json:"retrieved_fragments,omitempty"`
	CurrentMessage      ContextMessage        `json:"current_message"`
	BudgetMetadata      ContextBudgetMetadata `json:"budget_metadata"`
}

func (b ContextBundle) Validate(expectedContextID string) error {
	if b.SchemaVersion != ContextSchemaVersionV1 || b.ContextID == "" || b.ContextID != expectedContextID ||
		b.ConversationID == "" || b.TurnID == "" || b.BaseRevision < 0 || b.PolicyVersion == "" || b.PromptVersion == "" ||
		!validContextMessage(b.CurrentMessage, b.ConversationID) ||
		b.CurrentMessage.Role != "user" || b.CurrentMessage.Provenance != "user" ||
		len(b.RecentMessages) > MaxConversationHistoryMessages ||
		len(b.ExplicitConstraints) > MaxConversationMessages || b.Summary != nil || len(b.RetrievedFragments) != 0 {
		return ErrInvalidConversationContext
	}
	messageCount := len(b.RecentMessages) + 2 // system + current
	if len(b.ExplicitConstraints) > 0 {
		messageCount++
	}
	// Older backends used the same context capability before these two
	// accounting fields were added. Zero means "not supplied" during the
	// rolling upgrade; any supplied value must still match the worker limits.
	if messageCount > MaxConversationMessages ||
		(b.BudgetMetadata.MessageBudget != 0 && b.BudgetMetadata.MessageBudget != MaxConversationMessages) ||
		(b.BudgetMetadata.Messages != 0 && b.BudgetMetadata.Messages != messageCount) {
		return ErrInvalidConversationContext
	}
	seenIDs := make(map[string]struct{}, len(b.RecentMessages)+1)
	lastSeq := int64(0)
	for _, message := range b.RecentMessages {
		if !validContextMessage(message, b.ConversationID) || message.MessageSeq <= lastSeq {
			return ErrInvalidConversationContext
		}
		if message.ID != "" {
			if _, exists := seenIDs[message.ID]; exists {
				return ErrInvalidConversationContext
			}
			seenIDs[message.ID] = struct{}{}
		}
		if message.MessageSeq > lastSeq {
			lastSeq = message.MessageSeq
		}
	}
	if b.CurrentMessage.MessageSeq <= lastSeq {
		return ErrInvalidConversationContext
	}
	if b.CurrentMessage.ID != "" {
		if _, exists := seenIDs[b.CurrentMessage.ID]; exists {
			return ErrInvalidConversationContext
		}
	}
	for _, constraint := range b.ExplicitConstraints {
		if constraint.ID == "" || strings.TrimSpace(constraint.Text) == "" ||
			(constraint.Provenance != "user" && constraint.Provenance != "model") {
			return ErrInvalidConversationContext
		}
	}
	if b.BudgetMetadata.TokenBudget < 0 || b.BudgetMetadata.ByteBudget < 0 ||
		b.BudgetMetadata.OutputReserveTokens < 0 ||
		b.BudgetMetadata.CandidateReserveTokens < 0 || b.BudgetMetadata.CandidateReserveBytes < 0 {
		return ErrInvalidConversationContext
	}
	return nil
}

func validContextMessage(message ContextMessage, conversationID string) bool {
	if message.Content == "" || message.ConversationID != conversationID || message.MessageSeq <= 0 {
		return false
	}
	if message.Role != "user" && message.Role != "assistant" {
		return false
	}
	return message.Provenance == "user" || message.Provenance == "model"
}
