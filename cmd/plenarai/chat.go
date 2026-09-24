package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/plenarai/cli/internal/conversationer"
)

var (
	chatConversationID string
	chatNodeID         string
	chatMode           string
)

var chatCmd = &cobra.Command{
	Use:   "chat",
	Short: "Start or resume a conversation",
	Args:  cobra.NoArgs,
	RunE:  runChat,
}

func init() {
	rootCmd.AddCommand(chatCmd)
	chatCmd.Flags().StringVar(&chatConversationID, "conversation", "", "resume this conversation UUID")
	chatCmd.Flags().StringVar(&chatNodeID, "node-id", "", "direct every turn to this node UUID")
	chatCmd.Flags().StringVar(&chatMode, "mode", "directed", "conversation mode: directed or evaluated")
}

func runChat(cmd *cobra.Command, args []string) error {
	chatMode = strings.ToLower(strings.TrimSpace(chatMode))
	if chatMode != "directed" && chatMode != "evaluated" {
		return fmt.Errorf("--mode must be directed or evaluated")
	}
	if chatMode == "directed" && strings.TrimSpace(chatNodeID) == "" {
		return fmt.Errorf("--node-id is required for directed chat")
	}
	if chatMode == "evaluated" && strings.TrimSpace(chatNodeID) != "" {
		return fmt.Errorf("--node-id cannot be used with evaluated chat")
	}
	conversation, err := loadOrCreateConversation()
	if err != nil {
		return err
	}
	fmt.Printf("Conversation %s (revision %d). Type /exit to leave.\n", conversation.ID, conversation.Revision)
	if err := resumePendingTurn(&conversation); err != nil {
		fmt.Printf("pending turn resume failed: %v\n", err)
	}
	if err := resumeActiveTurn(&conversation); err != nil {
		fmt.Printf("active turn resume failed: %v\n", err)
	}

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024), 16*1024)
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			return scanner.Err()
		}
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "/exit" || trimmed == "/quit":
			return nil
		case trimmed == "/new":
			created, err := conversationer.Create("")
			if err != nil {
				fmt.Printf("new conversation failed: %v\n", err)
				continue
			}
			conversation = created
			fmt.Printf("Conversation %s (revision %d).\n", conversation.ID, conversation.Revision)
		case trimmed == "/history":
			if err := printHistory(conversation.ID); err != nil {
				fmt.Printf("history failed: %v\n", err)
			}
		case trimmed == "/retry":
			if err := resumePendingTurn(&conversation); err != nil {
				fmt.Printf("pending turn retry failed: %v\n", err)
			} else if err := resumeActiveTurn(&conversation); err != nil {
				fmt.Printf("active turn retry failed: %v\n", err)
			}
		case trimmed == "/discard":
			if err := discardPendingTurn(conversation.ID); err != nil {
				fmt.Printf("pending turn discard failed: %v\n", err)
			} else {
				fmt.Println("Local pending record discarded; an accepted server turn is not cancelled.")
			}
		case trimmed == "/context":
			fmt.Println("Usage: /context <message> — inspect the context that would be shared")
		case trimmed == "/pin":
			fmt.Println("Usage: /pin <constraint>")
		case strings.HasPrefix(trimmed, "/context "):
			if err := printContextPreview(conversation.ID, strings.TrimSpace(trimmed[len("/context "):])); err != nil {
				fmt.Printf("context preview failed: %v\n", err)
			}
		case strings.HasPrefix(trimmed, "/pin "):
			if err := pinConstraint(&conversation, strings.TrimSpace(trimmed[len("/pin "):])); err != nil {
				fmt.Printf("pin failed: %v\n", err)
			}
		case strings.HasPrefix(trimmed, "/unpin "):
			if err := unpinConstraint(&conversation, strings.TrimSpace(trimmed[len("/unpin "):])); err != nil {
				fmt.Printf("unpin failed: %v\n", err)
			}
		case trimmed == "/unpin":
			fmt.Println("Usage: /unpin <constraint-id>")
		case trimmed == "/delete":
			deleted, err := confirmDeleteConversation(&conversation, scanner)
			if err != nil {
				fmt.Printf("conversation deletion failed: %v\n", err)
				if deleted {
					return nil
				}
			} else if deleted {
				return nil
			}
		case trimmed == "":
			continue
		default:
			if err := sendChatTurn(&conversation, line); err != nil {
				fmt.Printf("turn failed: %v\n", err)
			}
		}
	}
}

func loadOrCreateConversation() (*conversationer.Conversation, error) {
	if strings.TrimSpace(chatConversationID) != "" {
		return conversationer.Get(chatConversationID)
	}
	return conversationer.Create("")
}

func sendChatTurn(conversation **conversationer.Conversation, message string) error {
	if len(message) > conversationer.MaxTurnMessageBytes {
		return fmt.Errorf("message exceeds %d bytes", conversationer.MaxTurnMessageBytes)
	}
	if (*conversation).ActiveTurnID != nil && *(*conversation).ActiveTurnID != "" {
		return fmt.Errorf("a turn is still active; use /retry before sending another message")
	}
	pending, err := conversationer.LoadPendingTurn((*conversation).ID)
	if err != nil {
		return err
	}
	if pending != nil {
		if pending.Request.Message != "" && pending.Request.Message != message {
			return fmt.Errorf("an earlier turn is still pending; use /retry or /discard before sending another message")
		}
		if pending.MessageDigest != conversationer.MessageDigest(message) {
			return fmt.Errorf("an earlier turn is still pending with different content; re-enter the original message or use /discard")
		}
		pending.Request.Message = message
	} else {
		idempotencyKey, err := conversationer.NewIdempotencyKey()
		if err != nil {
			return err
		}
		targetNodeID := ""
		if chatMode == "directed" {
			targetNodeID = chatNodeID
		}
		pending = &conversationer.PendingTurn{
			IdempotencyKey: idempotencyKey,
			Request: conversationer.TurnRequest{
				ExpectedRevision:     (*conversation).Revision,
				Message:              message,
				Mode:                 chatMode,
				TargetNodeID:         targetNodeID,
				MinimumSecurityClass: "standard",
				CostCredits:          1,
			},
		}
		if err := conversationer.SavePendingTurn((*conversation).ID, *pending); err != nil {
			return err
		}
	}
	return submitPendingTurn(conversation, pending)
}

func resumePendingTurn(conversation **conversationer.Conversation) error {
	pending, err := conversationer.LoadPendingTurn((*conversation).ID)
	if err != nil || pending == nil {
		return err
	}
	if pending.Request.Message == "" {
		receipt, found, err := conversationer.ReconcileTurn((*conversation).ID, pending.IdempotencyKey)
		if err != nil {
			return fmt.Errorf("pending turn reconciliation failed: %w", err)
		}
		if !found {
			return fmt.Errorf("pending turn was not accepted; re-enter the original message or use /discard")
		}
		return acceptTurnReceipt(conversation, receipt)
	}
	fmt.Printf("Resuming pending turn with idempotency key %s.\n", pending.IdempotencyKey)
	return submitPendingTurn(conversation, pending)
}

func submitPendingTurn(conversation **conversationer.Conversation, pending *conversationer.PendingTurn) error {
	receipt, err := conversationer.CreateTurn((*conversation).ID, pending.IdempotencyKey, pending.Request)
	if err != nil {
		if conversationer.IsDefinitiveAPIError(err) {
			if discardErr := conversationer.DeletePendingTurn((*conversation).ID); discardErr != nil {
				return fmt.Errorf("turn rejected and pending record could not be discarded: %w (discard: %v)", err, discardErr)
			}
			if current, refreshErr := conversationer.Get((*conversation).ID); refreshErr == nil {
				*conversation = current
			}
			return fmt.Errorf("turn rejected; pending record discarded: %w", err)
		}
		return err
	}
	return acceptTurnReceipt(conversation, receipt)
}

func acceptTurnReceipt(conversation **conversationer.Conversation, receipt *conversationer.TurnReceipt) error {
	(*conversation).Revision = receipt.Revision
	(*conversation).ActiveTurnID = &receipt.TurnID
	if err := conversationer.DeletePendingTurn((*conversation).ID); err != nil {
		return fmt.Errorf("turn accepted but pending record could not be removed: %w", err)
	}
	fmt.Printf("Turn %s submitted.\n", receipt.TurnID)
	return waitForTurn(conversation, receipt.TurnID)
}

func discardPendingTurn(conversationID string) error {
	// Recovery must also work when the local metadata file is malformed.
	return conversationer.DeletePendingTurn(conversationID)
}

func resumeActiveTurn(conversation **conversationer.Conversation) error {
	if (*conversation).ActiveTurnID == nil || *(*conversation).ActiveTurnID == "" {
		return nil
	}
	turnID := *(*conversation).ActiveTurnID
	fmt.Printf("Resuming active turn %s.\n", turnID)
	return waitForTurn(conversation, turnID)
}

func waitForTurn(conversation **conversationer.Conversation, turnID string) error {
	for attempt := 0; attempt < 60; attempt++ {
		time.Sleep(time.Second)
		view, pollErr := conversationer.GetTurn((*conversation).ID, turnID)
		if pollErr != nil {
			if attempt == 59 {
				return pollErr
			}
			continue
		}
		if view.Conversation.ID != "" {
			// Terminal turns increment the conversation revision as well. Keep
			// the complete server view so the next message uses that revision.
			*conversation = &view.Conversation
		}
		switch view.Turn.State {
		case "completed":
			if view.Assistant == nil {
				return fmt.Errorf("turn completed without an assistant message")
			}
			fmt.Printf("\n%s\n", view.Assistant.Content)
			return nil
		case "failed", "cancelled":
			if view.Turn.FailureCode != nil {
				return fmt.Errorf("turn %s: %s", view.Turn.State, *view.Turn.FailureCode)
			}
			return fmt.Errorf("turn %s", view.Turn.State)
		}
		if attempt%5 == 4 {
			fmt.Print(".")
		}
	}
	return fmt.Errorf("timed out waiting for turn %s; resume with --conversation %s", turnID, (*conversation).ID)
}

func printHistory(conversationID string) error {
	messages, err := conversationer.History(conversationID, 100)
	if err != nil {
		return err
	}
	for _, message := range messages {
		fmt.Printf("[%s] %s\n", message.Role, message.Content)
	}
	return nil
}

func pinConstraint(conversation **conversationer.Conversation, text string) error {
	if strings.TrimSpace(text) == "" {
		return fmt.Errorf("constraint text is required")
	}
	constraints, err := conversationer.Constraints((*conversation).ID)
	if err != nil {
		return err
	}
	inputs := make([]conversationer.ConstraintInput, 0, len(constraints)+1)
	for _, constraint := range constraints {
		inputs = append(inputs, conversationer.ConstraintInput{
			Text:            constraint.Text,
			SourceMessageID: constraintSourceID(constraint),
		})
	}
	inputs = append(inputs, conversationer.ConstraintInput{Text: text})
	updated, constraints, err := conversationer.ReplaceConstraints((*conversation).ID, (*conversation).Revision, inputs)
	if err != nil {
		if current, refreshErr := conversationer.Get((*conversation).ID); refreshErr == nil {
			*conversation = current
		}
		return err
	}
	*conversation = updated
	if len(constraints) == 0 {
		return fmt.Errorf("server returned no pinned constraint")
	}
	fmt.Printf("Pinned constraint %s (revision %d).\n", constraints[len(constraints)-1].ID, updated.Revision)
	return nil
}

func unpinConstraint(conversation **conversationer.Conversation, id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("constraint ID is required")
	}
	constraints, err := conversationer.Constraints((*conversation).ID)
	if err != nil {
		return err
	}
	inputs := make([]conversationer.ConstraintInput, 0, len(constraints))
	found := false
	for _, constraint := range constraints {
		if constraint.ID == id {
			found = true
			continue
		}
		inputs = append(inputs, conversationer.ConstraintInput{
			Text:            constraint.Text,
			SourceMessageID: constraintSourceID(constraint),
		})
	}
	if !found {
		return fmt.Errorf("constraint %s not found", id)
	}
	updated, _, err := conversationer.ReplaceConstraints((*conversation).ID, (*conversation).Revision, inputs)
	if err != nil {
		if current, refreshErr := conversationer.Get((*conversation).ID); refreshErr == nil {
			*conversation = current
		}
		return err
	}
	*conversation = updated
	fmt.Printf("Unpinned constraint %s (revision %d).\n", id, updated.Revision)
	return nil
}

func constraintSourceID(constraint conversationer.Constraint) string {
	if constraint.SourceMessageID == nil {
		return ""
	}
	return *constraint.SourceMessageID
}

func printContextPreview(conversationID, message string) error {
	if strings.TrimSpace(message) == "" {
		return fmt.Errorf("message is required")
	}
	preview, err := conversationer.PreviewContextFor(conversationID, message, chatMode, chatNodeID, "standard", 1)
	if err != nil {
		return err
	}
	fmt.Printf("Context preview: policy %s, prompt %s, revision %d\n", preview.PolicyVersion, preview.PromptVersion, preview.BaseRevision)
	fmt.Printf("Budget: %d/%d estimated tokens, %d/%d bytes, %d/%d messages; omitted history=%t\n",
		preview.BudgetMetadata.EstimatedTokens,
		preview.BudgetMetadata.TokenBudget,
		preview.BudgetMetadata.Bytes,
		preview.BudgetMetadata.ByteBudget,
		preview.BudgetMetadata.Messages,
		preview.BudgetMetadata.MessageBudget,
		preview.BudgetMetadata.OmittedHistory,
	)
	for _, constraint := range preview.ExplicitConstraints {
		fmt.Printf("[constraint %s] %s\n", constraint.ID, constraint.Text)
	}
	for _, message := range preview.RecentMessages {
		fmt.Printf("[%s] %s\n", message.Role, message.Content)
	}
	fmt.Printf("[current] %s\n", preview.CurrentMessage.Content)
	return nil
}

func confirmDeleteConversation(conversation **conversationer.Conversation, scanner *bufio.Scanner) (bool, error) {
	fmt.Print("This permanently deletes the conversation content. Type DELETE to confirm: ")
	if !scanner.Scan() {
		return false, scanner.Err()
	}
	if strings.TrimSpace(scanner.Text()) != "DELETE" {
		fmt.Println("Conversation deletion cancelled.")
		return false, nil
	}
	if err := conversationer.DeleteConversation((*conversation).ID); err != nil {
		return false, err
	}
	if err := conversationer.DeletePendingTurn((*conversation).ID); err != nil {
		return true, fmt.Errorf("conversation deleted but pending metadata could not be removed: %w", err)
	}
	fmt.Println("Conversation deleted.")
	return true, nil
}
