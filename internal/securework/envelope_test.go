package securework

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestSigningKeyIsStableAndDomainSeparated(t *testing.T) {
	private := bytes.Repeat([]byte{0x42}, 32)
	a := SigningKey(private)
	b := SigningKey(private)
	if !bytes.Equal(a, b) {
		t.Fatal("worker signing key is not stable")
	}
	private[0] ^= 1
	if bytes.Equal(a, SigningKey(private)) {
		t.Fatal("different node keys derived the same signing key")
	}
}

func TestPublishedInteroperabilityVector(t *testing.T) {
	data, err := os.ReadFile("testdata/secure-work-v1-vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Envelope   Envelope `json:"envelope"`
		Transcript string   `json:"transcript_base64"`
	}
	if json.Unmarshal(data, &vector) != nil {
		t.Fatal("invalid vector JSON")
	}
	want, err := base64.StdEncoding.DecodeString(vector.Transcript)
	if err != nil {
		t.Fatal(err)
	}
	if got := CanonicalTranscript(vector.Envelope); !bytes.Equal(got, want) {
		t.Fatal("CLI transcript differs from published vector")
	}
	if !ed25519.Verify(ed25519.PublicKey(vector.Envelope.SigningKey), want, vector.Envelope.Signature) {
		t.Fatal("published vector signature is invalid")
	}
}

func TestSealContainsOnlyCiphertextAndSignedMetadata(t *testing.T) {
	jobKey := make([]byte, 32)
	if _, err := rand.Read(jobKey); err != nil {
		t.Fatal(err)
	}
	signer := SigningKey(bytes.Repeat([]byte{7}, 32))
	secret := []byte("plaintext-must-not-appear")
	env, err := Seal(KindResponse, "job-1", jobKey, secret, signer, time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(env.Ciphertext, secret) || len(env.Signature) == 0 || len(env.Nonce) != nonceSize {
		t.Fatal("invalid encrypted worker envelope")
	}
}
