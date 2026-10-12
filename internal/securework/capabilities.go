package securework

import (
	"errors"
	"fmt"
	"strings"
)

const (
	CapabilityProtocolVersion = 1

	CapabilityQuestionV1          = "question_v1"
	CapabilityConversationContext = "conversation_context_v1"

	WorkKindQuestion         = "question"
	WorkKindConversationTurn = "conversation_turn"

	ContextSchemaVersionV1 = 1

	MaxNodePayloadBytes        = 1 << 20
	MaxEncryptedContextBytes   = 768 << 10
	MaxConversationAnswerBytes = 4096
	// The worker adds system/current messages; constraint capacity is checked
	// separately because all constraints are combined into one message.
	MaxConversationMessages        = 128
	MaxConversationHistoryMessages = MaxConversationMessages - 2

	maxCapabilityCount       = 32
	maxCapabilityNameBytes   = 64
	maxCapabilityStringBytes = 256
	maxArtifactDigestBytes   = 128
	maxContextWindowTokens   = 1 << 20
)

var ErrInvalidCapabilities = errors.New("invalid node capabilities")
var ErrInvalidConversationWork = errors.New("invalid conversation work payload")

// CapabilityAnnouncement is an untrusted, connection-scoped description of a
// node's available work profiles. It is used for routing and sizing only; it
// is not an attestation or a security claim.
type CapabilityAnnouncement struct {
	ProtocolVersion     int      `json:"protocol_version"`
	Capabilities        []string `json:"capabilities"`
	ModelID             string   `json:"model_id,omitempty"`
	ModelVersion        string   `json:"model_version,omitempty"`
	ArtifactDigest      string   `json:"artifact_digest,omitempty"`
	Engine              string   `json:"engine,omitempty"`
	Template            string   `json:"template,omitempty"`
	ContextWindowTokens int      `json:"context_window_tokens,omitempty"`
	// PromptOverheadTokens is the node's measured system prompt and template framing.
	PromptOverheadTokens int    `json:"prompt_overhead_tokens,omitempty"`
	MaxPayloadBytes      int    `json:"max_payload_bytes,omitempty"`
	SupportsRoles        bool   `json:"supports_roles,omitempty"`
	OpaqueSigningKey     []byte `json:"opaque_signing_key,omitempty"`
}

func (c CapabilityAnnouncement) Validate() error {
	if c.ProtocolVersion != CapabilityProtocolVersion || len(c.Capabilities) > maxCapabilityCount {
		return ErrInvalidCapabilities
	}
	seen := make(map[string]struct{}, len(c.Capabilities))
	for _, capability := range c.Capabilities {
		if capability == "" || len(capability) > maxCapabilityNameBytes ||
			strings.IndexAny(capability, " \t\r\n") >= 0 {
			return ErrInvalidCapabilities
		}
		if _, ok := seen[capability]; ok {
			return ErrInvalidCapabilities
		}
		seen[capability] = struct{}{}
	}
	if _, ok := seen["opaque_conversation_v2"]; ok && len(c.OpaqueSigningKey) != 32 {
		return ErrInvalidCapabilities
	}
	for _, value := range []struct {
		name  string
		value string
		limit int
	}{{"model_id", c.ModelID, maxCapabilityStringBytes}, {"model_version", c.ModelVersion, maxCapabilityStringBytes}, {"engine", c.Engine, maxCapabilityStringBytes}, {"template", c.Template, maxCapabilityStringBytes}, {"artifact_digest", c.ArtifactDigest, maxArtifactDigestBytes}} {
		if len(value.value) > value.limit {
			return fmt.Errorf("%w: %s is too long", ErrInvalidCapabilities, value.name)
		}
	}
	if c.PromptOverheadTokens < 0 || c.PromptOverheadTokens > 0 && c.PromptOverheadTokens >= c.ContextWindowTokens {
		return ErrInvalidCapabilities
	}
	if c.ContextWindowTokens < 0 || c.ContextWindowTokens > maxContextWindowTokens ||
		c.MaxPayloadBytes < 0 || c.MaxPayloadBytes > MaxNodePayloadBytes {
		return ErrInvalidCapabilities
	}
	return nil
}

func (c CapabilityAnnouncement) SupportsWorkKind(workKind string, schemaVersion int) bool {
	if workKind == "" {
		workKind = WorkKindQuestion
	}
	supported := func(name string) bool {
		for _, capability := range c.Capabilities {
			if capability == name {
				return true
			}
		}
		return false
	}
	switch workKind {
	case WorkKindQuestion:
		return supported(CapabilityQuestionV1)
	case WorkKindConversationTurn:
		return schemaVersion == ContextSchemaVersionV1 &&
			supported(CapabilityConversationContext) && c.SupportsRoles &&
			c.ContextWindowTokens > 0 && c.MaxPayloadBytes > 0
	case "opaque_conversation_turn":
		return schemaVersion == 2 && supported("opaque_conversation_v2") && c.SupportsRoles &&
			c.ContextWindowTokens > 0 && c.MaxPayloadBytes > 0 && len(c.OpaqueSigningKey) == 32
	default:
		return false
	}
}

func ValidateConversationWork(workKind, contextID string, schemaVersion int, encryptedContext []byte) error {
	if workKind != WorkKindConversationTurn || strings.TrimSpace(contextID) == "" ||
		len(contextID) > maxCapabilityStringBytes || schemaVersion != ContextSchemaVersionV1 ||
		len(encryptedContext) == 0 || len(encryptedContext) > MaxEncryptedContextBytes {
		return ErrInvalidConversationWork
	}
	return nil
}

// ConversationResultContent is the encrypted result body for a conversation
// turn. Keeping the linkage inside the encrypted body lets the existing
// envelope authenticate it without changing its cryptographic transcript.
type ConversationResultContent struct {
	WorkKind             string   `json:"work_kind"`
	ContextID            string   `json:"context_id"`
	ContextSchemaVersion int      `json:"context_schema_version"`
	ContextDigest        string   `json:"context_digest"`
	AssignmentDigest     string   `json:"assignment_digest"`
	ResponseText         string   `json:"response_text"`
	FailureCode          string   `json:"failure_code,omitempty"`
	Notes                []string `json:"notes,omitempty"`
}
