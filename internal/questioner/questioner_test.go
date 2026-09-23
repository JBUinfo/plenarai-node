package questioner

import (
	"testing"

	"github.com/plenarai/cli/internal/config"
)

func TestFormatQuestionErrorIncludesWalletURL(t *testing.T) {
	originalServerURL := config.ServerURL
	config.ServerURL = "https://plenarai.com/"
	t.Cleanup(func() {
		config.ServerURL = originalServerURL
	})

	got := formatQuestionError(" insufficient credits ")
	want := "insufficient credits. Buy more credits at https://plenarai.com/wallet"
	if got != want {
		t.Fatalf("formatQuestionError() = %q, want %q", got, want)
	}
}

func TestFormatQuestionErrorLeavesOtherErrorsUnchanged(t *testing.T) {
	const want = "server unavailable"
	if got := formatQuestionError(want); got != want {
		t.Fatalf("formatQuestionError() = %q, want %q", got, want)
	}
}
