package secureworker

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/plenarai/cli/internal/crypto"
	"github.com/plenarai/cli/internal/inference"
	"github.com/plenarai/cli/internal/securework"
)

func TestScoreJobRejectsExcessiveCandidatesBeforeInference(t *testing.T) {
	candidates := map[string]string{}
	for i := 0; i < maxScoreCandidates+1; i++ {
		candidates[fmt.Sprint(i)] = "answer"
	}
	key, raw := encryptedRequest(t, securework.Version, "question", candidates)
	called := false
	_, _, err := processScore(key, raw, func(string, string) string { called = true; return "" })
	if !errors.Is(err, ErrInvalidRequest) || called {
		t.Fatalf("oversized job reached inference: called=%v err=%v", called, err)
	}
}

func TestEvaluateInvalidOutputAbstains(t *testing.T) {
	score := evaluate(func(string, string) string { return "not-json" }, "question", "answer")
	if !score.Abstained || score.Reason != "invalid_judge_output" {
		t.Fatalf("invalid judge output = %#v, want explicit abstention", score)
	}
	if score.Correctness != 0 || score.Completeness != 0 || score.Clarity != 0 {
		t.Fatalf("abstention carried fabricated numeric scores: %#v", score)
	}
}

func TestEvaluateOutOfRangeAbstains(t *testing.T) {
	score := evaluate(func(string, string) string {
		return `{"correctness":1.1,"completeness":0.8,"clarity":0.7}`
	}, "question", "answer")
	if !score.Abstained || score.Reason != "score_out_of_range" {
		t.Fatalf("out-of-range judge output = %#v, want explicit abstention", score)
	}
}

func TestEvaluateValidOutputKeepsScores(t *testing.T) {
	score := evaluate(func(string, string) string {
		return `{"correctness":0.9,"completeness":0.8,"clarity":0.7}`
	}, "question", "answer")
	if score.Abstained || score.Correctness != 0.9 || score.Completeness != 0.8 || score.Clarity != 0.7 {
		t.Fatalf("valid judge output = %#v", score)
	}
}

func TestEvaluateConversationUsesRoleAwareContext(t *testing.T) {
	bundle := securework.ContextBundle{
		RecentMessages: []securework.ContextMessage{
			{Role: "user", Content: "earlier request"},
			{Role: "assistant", Content: "earlier answer"},
		},
		CurrentMessage: securework.ContextMessage{Role: "user", Content: "latest request"},
	}
	var got []inference.Message
	score := evaluateConversation(context.Background(), func(_ context.Context, messages []inference.Message, _ inference.GenerationOptions) (string, error) {
		got = append([]inference.Message(nil), messages...)
		return `{"correctness":0.9,"completeness":0.8,"clarity":0.7}`, nil
	}, bundle, "candidate answer")
	if score.Abstained {
		t.Fatalf("conversation judge abstained: %#v", score)
	}
	want := []inference.Message{
		{Role: "system", Content: judgeSystemPrompt},
		{Role: "user", Content: "earlier request"},
		{Role: "assistant", Content: "earlier answer"},
		{Role: "user", Content: "latest request"},
	}
	if len(got) != len(want)+1 {
		t.Fatalf("conversation judge message count = %d, want %d", len(got), len(want)+1)
	}
	for i, message := range want {
		if got[i] != message {
			t.Fatalf("message %d = %#v, want %#v", i, got[i], message)
		}
	}
	if got[len(got)-1].Role != "user" || !strings.Contains(got[len(got)-1].Content, "candidate answer") {
		t.Fatalf("candidate was not appended as data: %#v", got[len(got)-1])
	}
}

type testTB interface {
	Helper()
	Fatal(args ...any)
}

func encryptedRequest(t testTB, version int, question string, candidates map[string]string) (*ecdh.PrivateKey, json.RawMessage) {
	t.Helper()
	node, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := server.ECDH(node.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	jobKey := make([]byte, 32)
	if _, err := rand.Read(jobKey); err != nil {
		t.Fatal(err)
	}
	wrappingKey, err := hkdf.Key(sha256.New, shared, nil, "plenarai-secure-work:key-wrap:v1", 32)
	crypto.ZeroBytes(shared)
	if err != nil {
		t.Fatal(err)
	}
	encryptedKey, err := crypto.EncryptAESGCMAAD(wrappingKey, jobKey, nil)
	crypto.ZeroBytes(wrappingKey)
	if err != nil {
		t.Fatal(err)
	}
	encryptedQuestion, err := crypto.EncryptAESGCMAAD(jobKey, []byte(question), nil)
	if err != nil {
		t.Fatal(err)
	}
	type candidate struct {
		ResponseID      string `json:"response_id"`
		EncryptedAnswer []byte `json:"encrypted_answer"`
	}
	list := make([]candidate, 0, len(candidates))
	for id, answer := range candidates {
		ciphertext, err := crypto.EncryptAESGCMAAD(jobKey, []byte(answer), nil)
		if err != nil {
			t.Fatal(err)
		}
		list = append(list, candidate{ResponseID: id, EncryptedAnswer: ciphertext})
	}
	crypto.ZeroBytes(jobKey)
	raw, err := json.Marshal(map[string]any{
		"protocol_version":    version,
		"question_id":         "job-test",
		"encrypted_question":  encryptedQuestion,
		"encrypted_responses": list,
		"encrypted_key":       encryptedKey,
		"server_public_key":   server.PublicKey().Bytes(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return node, raw
}

func TestProcessQuestionKeepsPlaintextInsideWorker(t *testing.T) {
	const question = "confidential question sentinel"
	const answer = "confidential answer sentinel"
	node, raw := encryptedRequest(t, securework.Version, question, nil)
	called := false
	jobID, envelope, err := ProcessQuestion(node, raw, "system", func(system, prompt string) string {
		called = true
		if system != "system" || prompt != question {
			t.Fatalf("unexpected inference input")
		}
		return answer
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(envelope)
	if !called || jobID != "job-test" || envelope.Kind != securework.KindResponse {
		t.Fatal("question did not complete through secure worker")
	}
	if bytes.Contains(encoded, []byte(question)) || bytes.Contains(encoded, []byte(answer)) {
		t.Fatal("plaintext crossed the secure-worker return boundary")
	}
}

func TestProcessQuestionWithErrorDoesNotSealEngineFailure(t *testing.T) {
	node, raw := encryptedRequest(t, securework.Version, "question", nil)
	_, envelope, err := ProcessQuestionWithError(node, raw, "system", func(_, _ string) (string, error) {
		return "", errors.New("model offline")
	})
	if !errors.Is(err, ErrInference) || envelope.Kind != "" {
		t.Fatalf("engine failure was sealed as a response: kind=%q err=%v", envelope.Kind, err)
	}
}

func TestProcessScoreKeepsScoresEncrypted(t *testing.T) {
	node, raw := encryptedRequest(t, securework.Version, "private question", map[string]string{"response-1": "private answer"})
	jobID, envelope, err := ProcessScore(node, raw, func(_, _ string) string {
		return `{"correctness":0.9,"completeness":0.8,"clarity":0.7}`
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(envelope)
	if jobID != "job-test" || envelope.Kind != securework.KindScore || bytes.Contains(encoded, []byte("correctness")) {
		t.Fatal("score plaintext crossed the secure-worker return boundary")
	}
}

func TestProcessQuestionRejectsDowngradeWithoutInference(t *testing.T) {
	node, raw := encryptedRequest(t, securework.Version-1, "secret", nil)
	called := false
	_, _, err := ProcessQuestion(node, raw, "system", func(_, _ string) string { called = true; return "" })
	if !errors.Is(err, ErrProtocol) || called {
		t.Fatalf("downgrade was not rejected before inference: %v", err)
	}
}

func BenchmarkProcessQuestion(b *testing.B) {
	node, raw := encryptedRequest(b, securework.Version, "benchmark question", nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := ProcessQuestion(node, raw, "system", func(_, _ string) string { return "answer" }); err != nil {
			b.Fatal(err)
		}
	}
}
