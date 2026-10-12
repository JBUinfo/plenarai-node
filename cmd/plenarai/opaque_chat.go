package main

import (
	"bufio"
	"fmt"
	"github.com/plenarai/cli/internal/auth"
	"github.com/plenarai/cli/internal/conversationer"
	"github.com/plenarai/cli/internal/inference"
	"github.com/plenarai/cli/internal/opaque"
	"github.com/plenarai/cli/internal/opaquechat"
	"github.com/spf13/cobra"
	"golang.org/x/term"
	"io"
	"os"
	"strings"
	"time"
)

var chatPrivacy string
var chatFingerprint string
var chatCost float64

func init() {
	chatCmd.Flags().StringVar(&chatPrivacy, "privacy", opaque.PrivacyMode, "privacy: client_encrypted_v2 or explicit server_readable")
	chatCmd.Flags().StringVar(&chatFingerprint, "provider-fingerprint", "", "independently verified provider public-key fingerprint")
	chatCmd.Flags().Float64Var(&chatCost, "cost", 1, "credits per encrypted turn")
	keys := &cobra.Command{Use: "keys", Short: "Export or import password-encrypted conversation keys"}
	export := &cobra.Command{Use: "export FILE", Args: cobra.ExactArgs(1), Short: "Back up conversation keys (does not export the remote ciphertext history)", RunE: func(cmd *cobra.Command, args []string) error {
		v, err := opaquechat.OpenVault()
		if err != nil {
			return err
		}
		defer v.Close()
		password, err := readBackupPassword(true)
		if err != nil {
			return err
		}
		defer opaque.Zero(password)
		data, err := v.Export(password)
		if err != nil {
			return err
		}
		defer opaque.Zero(data)
		if err = opaquechat.WriteExport(args[0], data); err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Encrypted key backup saved. Keep it and its password separately.")
		return nil
	}}
	imp := &cobra.Command{Use: "import FILE", Args: cobra.ExactArgs(1), Short: "Restore conversation keys without replacing different existing keys", RunE: func(cmd *cobra.Command, args []string) error {
		data, err := opaquechat.ReadExport(args[0])
		if err != nil {
			return err
		}
		defer opaque.Zero(data)
		password, err := readBackupPassword(false)
		if err != nil {
			return err
		}
		defer opaque.Zero(password)
		v, err := opaquechat.OpenVault()
		if err != nil {
			return err
		}
		defer v.Close()
		if err = v.Import(data, password); err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Conversation keys imported.")
		return nil
	}}
	keys.AddCommand(export, imp)
	chatCmd.AddCommand(keys)
	var source, node, pin string
	var assumeYes bool
	transfer := &cobra.Command{Use: "transfer", Args: cobra.NoArgs, Short: "Copy recent decrypted context into a new conversation with a verified provider", RunE: func(cmd *cobra.Command, args []string) error {
		auth.LoadConfig()
		owner, err := opaquechat.Owner()
		if err != nil {
			return err
		}
		p, err := opaquechat.GetProvider(node, pin)
		if err != nil {
			return err
		}
		v, err := opaquechat.OpenVault()
		if err != nil {
			return err
		}
		defer v.Close()
		s, err := opaquechat.Resume(v, owner, source)
		if err != nil {
			return err
		}
		preview, err := s.PreviewTransfer("Transferred encrypted conversation")
		if err != nil {
			return err
		}
		summary := "no summary"
		if preview.HasSummary {
			summary = fmt.Sprintf("a summary of %d bytes", preview.SummaryBytes)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Provider %s would receive %d verbatim exchanges, %s and %d requirements on its first turn.\n", p.ID, preview.Exchanges, summary, preview.Requirements)
		if !assumeYes {
			if !term.IsTerminal(int(os.Stdin.Fd())) {
				return fmt.Errorf("confirmation required: rerun with --yes to share this context")
			}
			fmt.Fprint(cmd.OutOrStdout(), "Share this context with the new provider? [y/N] ")
			var answer string
			fmt.Fscanln(cmd.InOrStdin(), &answer)
			if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" && a != "s" && a != "si" && a != "sí" {
				return fmt.Errorf("transfer cancelled; nothing was created")
			}
		}
		next, err := s.Transfer(p, "Transferred encrypted conversation")
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "New encrypted conversation: %s\nCopied recent context: %d messages. Original history retained. The new node receives context when you send its first turn.\n", next.Entry.Create.ConversationID, len(next.Messages))
		return nil
	}}
	transfer.Flags().StringVar(&source, "conversation", "", "source encrypted conversation UUID")
	transfer.Flags().StringVar(&node, "node-id", "", "new provider UUID")
	transfer.Flags().StringVar(&pin, "provider-fingerprint", "", "independently verified new provider fingerprint")
	transfer.Flags().BoolVar(&assumeYes, "yes", false, "share the previewed context without an interactive confirmation")
	chatCmd.AddCommand(transfer)
	var legacySource, legacyNode, legacyPin string
	migrate := &cobra.Command{Use: "migrate", Args: cobra.NoArgs, Short: "Explicitly copy recent legacy context into a new encrypted conversation; keeps the original", RunE: func(cmd *cobra.Command, args []string) error {
		if !opaque.ValidID(legacySource) {
			return fmt.Errorf("--conversation must be a UUID")
		}
		auth.LoadConfig()
		owner, err := opaquechat.Owner()
		if err != nil {
			return err
		}
		p, err := opaquechat.GetProvider(legacyNode, legacyPin)
		if err != nil {
			return err
		}
		original, err := conversationer.Get(legacySource)
		if err != nil {
			return err
		}
		if original.ActiveTurnID != nil {
			return fmt.Errorf("finish the legacy active turn before migration")
		}
		history := []conversationer.Message{}
		for offset := 0; ; offset += 100 {
			var page []conversationer.Message
			if err = conversationer.Request("GET", fmt.Sprintf("/v0/conversations/%s/messages?limit=100&offset=%d", legacySource, offset), nil, nil, &page, 200); err != nil {
				return err
			}
			history = append(history, page...)
			if len(history) > 126 {
				history = history[len(history)-126:]
			}
			if len(page) < 100 {
				break
			}
			if offset >= 1000000 {
				return fmt.Errorf("legacy history is too large for this migration")
			}
		}
		requirements, err := conversationer.Constraints(legacySource)
		if err != nil {
			return err
		}
		current, err := conversationer.Get(legacySource)
		if err != nil {
			return err
		}
		if current.Revision != original.Revision || current.ActiveTurnID != nil {
			return fmt.Errorf("legacy conversation changed during migration")
		}
		archive := opaquechat.Archive{Title: original.Title, SourceConversationID: legacySource}
		var user *conversationer.Message
		for _, m := range history {
			copy := m
			if m.Role == "user" {
				user = &copy
			} else if m.Role == "assistant" && user != nil {
				archive.Messages = append(archive.Messages, inference.Message{Role: "user", Content: user.Content}, inference.Message{Role: "assistant", Content: m.Content})
				user = nil
			}
		}
		for _, c := range requirements {
			archive.Constraints = append(archive.Constraints, c.Text)
		}
		v, err := opaquechat.OpenVault()
		if err != nil {
			return err
		}
		defer v.Close()
		s, err := opaquechat.Create(v, owner, p, archive)
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "New encrypted conversation: %s\nCopied recent context: %d messages. The original and earlier server backups remain readable by the server.\n", s.Entry.Create.ConversationID, len(s.Messages))
		return nil
	}}
	migrate.Flags().StringVar(&legacySource, "conversation", "", "source server-readable conversation UUID")
	migrate.Flags().StringVar(&legacyNode, "node-id", "", "verified destination provider UUID")
	migrate.Flags().StringVar(&legacyPin, "provider-fingerprint", "", "independently verified provider fingerprint")
	chatCmd.AddCommand(migrate)
}
func readBackupPassword(confirm bool) ([]byte, error) {
	fmt.Fprint(os.Stderr, "Key export password: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if confirm {
		fmt.Fprint(os.Stderr, "Repeat password: ")
		again, e := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		defer opaque.Zero(again)
		if e != nil || string(password) != string(again) {
			opaque.Zero(password)
			return nil, fmt.Errorf("passwords do not match")
		}
	}
	return password, nil
}
func runOpaqueChat(cmd *cobra.Command, args []string) error {
	if chatMode != "directed" {
		return fmt.Errorf("encrypted chat currently requires directed mode")
	}
	auth.LoadConfig()
	owner, err := opaquechat.Owner()
	if err != nil {
		return err
	}
	v, err := opaquechat.OpenVault()
	if err != nil {
		return err
	}
	defer v.Close()
	var s *opaquechat.Session
	if chatConversationID != "" {
		s, err = opaquechat.Resume(v, owner, chatConversationID)
		if err == nil && chatNodeID != "" && s.Entry.Create.ProviderID != chatNodeID {
			return fmt.Errorf("use chat transfer to explicitly change the provider")
		}
		if err == nil && chatFingerprint != "" && chatFingerprint != opaque.Fingerprint(s.Entry.Create.ProviderEncryptionKey, s.Entry.Create.ProviderSigningKey) {
			return fmt.Errorf("fingerprint does not match the pinned provider")
		}
	} else {
		p, e := opaquechat.GetProvider(chatNodeID, chatFingerprint)
		if e != nil {
			return e
		}
		s, err = opaquechat.Create(v, owner, p, opaquechat.Archive{Title: "Encrypted conversation"})
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Encrypted conversation: %s\nProvider: %s\nLocal keys are required to resume. Use chat keys export for a password-encrypted backup.\nCommands: %s\n", s.Entry.Create.ConversationID, s.Entry.Create.ProviderID, opaqueCommands)
	if s.Entry.Pending != nil {
		answer, e := s.ReconcilePending()
		if e != nil {
			return e
		}
		if answer != "" {
			fmt.Fprintln(cmd.OutOrStdout(), answer)
		}
	}
	// A crash after acceptance but before displaying the answer can leave the
	// remote turn active after Sync cleared the upload retry.
	if s.Conversation.ActiveTurnID != nil {
		return fmt.Errorf("this conversation has an active turn; resume after its signed deadline")
	}
	scanner := bufio.NewScanner(cmd.InOrStdin())
	scanner.Buffer(make([]byte, 4096), 128<<10)
	s.Notify = func(message string) { fmt.Fprintln(cmd.OutOrStdout(), message) }
	if term.IsTerminal(int(os.Stdin.Fd())) {
		s.Confirm = func(question string) string {
			fmt.Fprint(cmd.OutOrStdout(), question+" ")
			if !scanner.Scan() {
				return ""
			}
			return scanner.Text()
		}
	}
	for {
		fmt.Fprint(cmd.OutOrStdout(), "> ")
		if !scanner.Scan() {
			return scanner.Err()
		}
		text := strings.TrimSpace(scanner.Text())
		if text == "" {
			continue
		}
		switch text {
		case "/exit":
			return nil
		case "/history":
			for _, item := range s.History() {
				if item.Exchange != nil {
					fmt.Fprintf(cmd.OutOrStdout(), "user: %s\nassistant: %s\n", item.Exchange.User, item.Exchange.Assistant)
				} else if item.Summary.LastStatus == "valid" {
					fmt.Fprintf(cmd.OutOrStdout(), "[summary %s: valid]\n", item.Summary.Text)
				} else {
					fmt.Fprintf(cmd.OutOrStdout(), "[summary %s: %s (%s)]\n", item.Summary.Text, item.Summary.LastStatus, item.Summary.LastError)
				}
			}
			continue
		case "/summary":
			printSummary(cmd.OutOrStdout(), s)
			continue
		case "/summary rebuild":
			e := s.RebuildSummary(chatCost, func(turns int) bool {
				if s.Confirm == nil {
					return false
				}
				answer := strings.ToLower(strings.TrimSpace(s.Confirm(fmt.Sprintf("Rebuilding from the original exchanges takes %d summary turns (%g credits). Continue? [y/N]", turns, float64(turns)*chatCost))))
				return answer == "y" || answer == "yes" || answer == "s" || answer == "si" || answer == "sí"
			})
			if e != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "%v\n", e)
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "Summary rebuilt from the original exchanges.")
			}
			continue
		case "/summary auto", "/summary ask", "/summary off":
			mode := map[string]string{"/summary auto": "auto", "/summary ask": "", "/summary off": "off"}[text]
			if e := s.SetSummaryMode(mode); e != nil {
				return e
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Summary preference saved.")
			continue
		case "/context":
			r, e := s.ContextReport()
			if e != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "Context report unavailable: %v\n", e)
				continue
			}
			printContextReport(cmd.OutOrStdout(), r)
			continue
		case "/constraints":
			for _, c := range s.Constraints {
				fmt.Fprintln(cmd.OutOrStdout(), c)
			}
			continue
		case "/constraint clear":
			if e := s.SetConstraints([]string{}); e != nil {
				return e
			}
			continue
		}
		if strings.HasPrefix(text, "/constraint ") {
			values := append(append([]string{}, s.Constraints...), strings.TrimSpace(strings.TrimPrefix(text, "/constraint ")))
			if e := s.SetConstraints(values); e != nil {
				return e
			}
			continue
		}
		if strings.HasPrefix(text, "/") {
			fmt.Fprintf(cmd.OutOrStdout(), "Unknown command. Use %s.\n", opaqueCommands)
			continue
		}
		answer, e := s.Send(text, chatCost)
		if e != nil {
			return e
		}
		fmt.Fprintln(cmd.OutOrStdout(), answer)
		if s.LastFinishReason() == "length" {
			fmt.Fprintln(cmd.OutOrStdout(), "(The answer was cut off because the model's context window filled up.)")
		}
		// Compacting now keeps the next send from waiting on it.
		if e = s.AfterTurn(chatCost); e != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "Context maintenance postponed: %v\n", e)
		}
	}
}

const opaqueCommands = "/history, /context, /constraint TEXT, /constraints, /constraint clear, /summary, /summary auto|ask|off, /summary rebuild, /exit"

func printSummary(w io.Writer, s *opaquechat.Session) {
	v := s.Summary()
	switch {
	case !v.Has:
		fmt.Fprintln(w, "No summary yet: the whole conversation still fits.")
	case v.Transferred:
		fmt.Fprintf(w, "Summary transferred from a previous conversation (covers what happened before #1):\n%s\n", v.Text)
	default:
		fmt.Fprintf(w, "Summary of #1-#%d by provider %s (model revision %s, turn revision %d, %s):\n%s\n", v.K, s.Entry.Create.ProviderID, s.Entry.Create.ModelRevision, v.Revision, time.Unix(v.CreatedAt, 0).Format("2006-01-02 15:04"), v.Text)
	}
	if v.LastStatus == "rejected" || v.LastStatus == "failed" {
		fmt.Fprintf(w, "Last summary attempt: %s (%s).\n", v.LastStatus, v.LastError)
	}
}

// printContextReport shows budget and coverage only, never message content.
func printContextReport(w io.Writer, r opaquechat.ContextReport) {
	overhead, ratio := "announced by provider", "measured"
	if r.DefaultOverhead {
		overhead = "default"
	}
	if !r.Measured {
		ratio = "default"
	}
	fmt.Fprintf(w, "Provider window: %d tokens. Prompt overhead: %d (%s). Output reserve: %d. Margin: %d. Context budget: %d.\n", r.W, r.S, overhead, r.OutputReserve, r.Margin, r.P)
	fmt.Fprintf(w, "Estimated context now: %d tokens (%d%% of budget). Bytes per token: %.2f (%s).\n", r.Used, r.Percent, r.R, ratio)
	switch {
	case r.HasSummary && r.SummaryTransferred:
		fmt.Fprintln(w, "Summary: transferred from a previous conversation (covers what happened before #1).")
	case r.HasSummary:
		fmt.Fprintf(w, "Summary: covers #1-#%d (turn revision %d, %s).\n", r.SummaryK, r.SummaryRevision, time.Unix(r.SummaryCreated, 0).Format("2006-01-02 15:04"))
	default:
		fmt.Fprintln(w, "Summary: none.")
	}
	span := func(a, b int) string {
		if a == 0 {
			return "none"
		}
		return fmt.Sprintf("#%d-#%d", a, b)
	}
	fmt.Fprintf(w, "Verbatim exchanges: %s. Omitted exchanges: %s.\n", span(r.LiteralFrom, r.LiteralTo), span(r.OmittedFrom, r.OmittedTo))
	if r.LastUsage.PromptTokens > 0 {
		fmt.Fprintf(w, "Last measured usage: prompt_tokens=%d cached_tokens=%d finish_reason=%s.\n", r.LastUsage.PromptTokens, r.LastUsage.CachedTokens, r.LastUsage.FinishReason)
	} else {
		fmt.Fprintln(w, "Last measured usage: not reported yet.")
	}
	mode := map[string]string{"": "ask", "auto": "automatic", "off": "off"}[r.SummaryMode]
	fmt.Fprintf(w, "Summary mode: %s.\n", mode)
	if r.LastSummary == "rejected" || r.LastSummary == "failed" {
		fmt.Fprintf(w, "Last summary attempt: %s (%s).\n", r.LastSummary, r.LastReason)
	}
}
