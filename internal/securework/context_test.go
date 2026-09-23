package securework

import "testing"

func TestContextBundleValidateAcceptsLegacyMessageMetadata(t *testing.T) {
	bundle := ContextBundle{
		SchemaVersion:  ContextSchemaVersionV1,
		ContextID:      "context-1",
		ConversationID: "conversation-1",
		TurnID:         "turn-1",
		PolicyVersion:  "policy-1",
		PromptVersion:  "prompt-1",
		RecentMessages: []ContextMessage{{
			ID:             "message-1",
			ConversationID: "conversation-1",
			MessageSeq:     1,
			Role:           "assistant",
			Content:        "previous answer",
			Provenance:     "model",
		}},
		CurrentMessage: ContextMessage{
			ID:             "message-2",
			ConversationID: "conversation-1",
			MessageSeq:     2,
			Role:           "user",
			Content:        "current question",
			Provenance:     "user",
		},
	}

	if err := bundle.Validate("context-1"); err != nil {
		t.Fatalf("legacy context rejected: %v", err)
	}
}

func TestContextBundleValidateRejectsIncorrectMessageMetadata(t *testing.T) {
	bundle := ContextBundle{
		SchemaVersion:  ContextSchemaVersionV1,
		ContextID:      "context-1",
		ConversationID: "conversation-1",
		TurnID:         "turn-1",
		PolicyVersion:  "policy-1",
		PromptVersion:  "prompt-1",
		CurrentMessage: ContextMessage{
			ID:             "message-1",
			ConversationID: "conversation-1",
			MessageSeq:     1,
			Role:           "user",
			Content:        "current question",
			Provenance:     "user",
		},
		BudgetMetadata: ContextBudgetMetadata{
			MessageBudget: MaxConversationMessages,
			Messages:      99,
		},
	}

	if err := bundle.Validate("context-1"); err != ErrInvalidConversationContext {
		t.Fatalf("incorrect message metadata error = %v, want %v", err, ErrInvalidConversationContext)
	}
}
