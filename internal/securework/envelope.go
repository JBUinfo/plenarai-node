// Package securework creates encrypted and signed worker output envelopes.
package securework

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/plenarai/cli/internal/crypto"
)

const (
	Version         = 1
	KindResponse    = "response"
	KindScore       = "score"
	DefaultLifetime = 2 * time.Minute
	nonceSize       = 32
)

var ErrInvalidEnvelope = errors.New("invalid secure-work envelope")

type Envelope struct {
	Version    int    `json:"version"`
	Kind       string `json:"kind"`
	JobID      string `json:"job_id"`
	IssuedAt   int64  `json:"issued_at"`
	ExpiresAt  int64  `json:"expires_at"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
	SigningKey []byte `json:"signing_key"`
	Signature  []byte `json:"signature"`
}

// SigningKey derives a stable worker signing key from the node's protected
// X25519 private-key bytes. It does not expose those bytes in the envelope.
func SigningKey(nodePrivate []byte) ed25519.PrivateKey {
	seed := sha256.Sum256(append([]byte("plenarai-secure-worker-signing-v1:"), nodePrivate...))
	return ed25519.NewKeyFromSeed(seed[:])
}

func Seal(kind, jobID string, key, plaintext []byte, signer ed25519.PrivateKey, now time.Time) (Envelope, error) {
	if (kind != KindResponse && kind != KindScore) || jobID == "" || len(key) != 32 || len(signer) != ed25519.PrivateKeySize {
		return Envelope{}, ErrInvalidEnvelope
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return Envelope{}, fmt.Errorf("secure-work nonce: %w", err)
	}
	env := Envelope{
		Version: Version, Kind: kind, JobID: jobID,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(DefaultLifetime).Unix(), Nonce: nonce,
		SigningKey: append([]byte(nil), signer.Public().(ed25519.PublicKey)...),
	}
	ciphertext, err := crypto.EncryptAESGCMAAD(key, plaintext, metadata(env))
	if err != nil {
		return Envelope{}, err
	}
	env.Ciphertext = ciphertext
	env.Signature = ed25519.Sign(signer, transcript(env))
	return env, nil
}

func metadata(env Envelope) []byte {
	b := make([]byte, 0, 128)
	b = appendUint64(b, uint64(env.Version))
	b = appendField(b, []byte(env.Kind))
	b = appendField(b, []byte(env.JobID))
	b = appendUint64(b, uint64(env.IssuedAt))
	b = appendUint64(b, uint64(env.ExpiresAt))
	b = appendField(b, env.Nonce)
	b = appendField(b, env.SigningKey)
	return b
}

func transcript(env Envelope) []byte { return appendField(metadata(env), env.Ciphertext) }

// CanonicalTranscript exposes the deterministic bytes used by interoperability tests.
func CanonicalTranscript(env Envelope) []byte {
	return append([]byte(nil), transcript(env)...)
}

func appendField(dst, value []byte) []byte {
	dst = appendUint64(dst, uint64(len(value)))
	return append(dst, value...)
}

func appendUint64(dst []byte, value uint64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], value)
	return append(dst, buf[:]...)
}
