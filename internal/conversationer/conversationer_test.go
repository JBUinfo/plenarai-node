package conversationer

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestPendingTurnRoundTrip(t *testing.T) {
	t.Setenv("PLENARAI_CONFIG_DIR", t.TempDir())
	want := PendingTurn{
		IdempotencyKey: "idempotency-1",
		Request: TurnRequest{
			ExpectedRevision: 4,
			Message:          "keep this request stable",
			Mode:             "directed",
			TargetNodeID:     "node-1",
			CostCredits:      1,
		},
	}
	if err := SavePendingTurn("conversation-1", want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadPendingTurn("conversation-1")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.IdempotencyKey != want.IdempotencyKey || got.Request.ExpectedRevision != want.Request.ExpectedRevision ||
		got.Request.Mode != want.Request.Mode || got.Request.TargetNodeID != want.Request.TargetNodeID ||
		got.Request.MinimumSecurityClass != want.Request.MinimumSecurityClass || got.Request.CostCredits != want.Request.CostCredits ||
		got.Request.Message != "" || got.MessageDigest != MessageDigest(want.Request.Message) {
		t.Fatalf("pending turn = %#v, want %#v", got, want)
	}
	entries, err := os.ReadDir(os.Getenv("PLENARAI_CONFIG_DIR"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(os.Getenv("PLENARAI_CONFIG_DIR"), entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte(want.Request.Message)) {
			t.Fatalf("pending file %s contains the plaintext message", entry.Name())
		}
	}
	if err := DeletePendingTurn("conversation-1"); err != nil {
		t.Fatal(err)
	}
	got, err = LoadPendingTurn("conversation-1")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("pending turn remains after deletion: %#v", got)
	}
}

func TestAPIErrorDefinitiveClassification(t *testing.T) {
	if !(&APIError{StatusCode: 400}).Definitive() {
		t.Fatal("400 response should be definitive")
	}
	if (&APIError{StatusCode: 503}).Definitive() {
		t.Fatal("503 response should remain retryable")
	}
	if (&APIError{StatusCode: 429}).Definitive() {
		t.Fatal("429 response should remain retryable")
	}
}
