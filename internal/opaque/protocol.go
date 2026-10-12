// Package opaque implements client-encrypted directed conversation envelopes.
// This file is byte-identical in the backend and CLI; neither metadata validation
// nor signature verification requires a conversation or per-turn private key.
package opaque

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"time"
)

const (
	Version       = 2
	PrivacyMode   = "client_encrypted_v2"
	Capability    = "opaque_conversation_v2"
	WorkKind      = "opaque_conversation_turn"
	MaxCiphertext = 1 << 20
	MaxRecord     = 128 << 10
	MaxAnswer     = 65536
	Lifetime      = 180 * time.Second
	ClockSkew     = 30 * time.Second
)

var ErrEnvelope = errors.New("invalid opaque conversation envelope")
var uuidPattern = regexp.MustCompile("^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")

func ValidID(id string) bool { return uuidPattern.MatchString(id) }
func NewID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
func RandomKey() ([]byte, error) { k := make([]byte, 32); _, e := rand.Read(k); return k, e }
func Fingerprint(encryption, signing []byte) string {
	b := field([]byte("plenarai-opaque-provider-v2"), encryption)
	b = field(b, signing)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

type Header struct {
	Version               int    `json:"version"`
	ConversationID        string `json:"conversation_id"`
	TurnID                string `json:"turn_id"`
	OwnerID               string `json:"owner_id"`
	ProviderID            string `json:"provider_id"`
	ModelRevision         string `json:"model_revision"`
	BaseRevision          int64  `json:"base_revision"`
	Sequence              int64  `json:"sequence"`
	CostUnits             int64  `json:"cost_units"`
	ExpiresAt             int64  `json:"expires_at"`
	PreviousDigest        []byte `json:"previous_digest,omitempty"`
	ClientSigningKey      []byte `json:"client_signing_key"`
	EphemeralKey          []byte `json:"ephemeral_key"`
	ProviderEncryptionKey []byte `json:"provider_encryption_key"`
	ProviderSigningKey    []byte `json:"provider_signing_key"`
}
type Request struct {
	Header       Header `json:"header"`
	ClientRecord []byte `json:"client_record"`
	Ciphertext   []byte `json:"ciphertext"`
	Signature    []byte `json:"signature"`
}
type Response struct {
	Header        Header `json:"header"`
	RequestDigest []byte `json:"request_digest"`
	Status        string `json:"status"`
	FailureCode   string `json:"failure_code,omitempty"`
	Ciphertext    []byte `json:"ciphertext"`
	Signature     []byte `json:"signature"`
}
type Create struct {
	Version               int    `json:"version"`
	ConversationID        string `json:"conversation_id"`
	OwnerID               string `json:"owner_id"`
	ProviderID            string `json:"provider_id"`
	ModelRevision         string `json:"model_revision"`
	ClientSigningKey      []byte `json:"client_signing_key"`
	ProviderEncryptionKey []byte `json:"provider_encryption_key"`
	ProviderSigningKey    []byte `json:"provider_signing_key"`
	Ciphertext            []byte `json:"ciphertext"`
	Signature             []byte `json:"signature"`
}

func field(b, v []byte) []byte { b = number(b, int64(len(v))); return append(b, v...) }
func number(b []byte, v int64) []byte {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(v))
	return append(b, n[:]...)
}
func (h Header) Canonical() []byte {
	b := field(nil, []byte("plenarai-opaque-header-v2"))
	b = number(b, int64(h.Version))
	for _, v := range []string{h.ConversationID, h.TurnID, h.OwnerID, h.ProviderID, h.ModelRevision} {
		b = field(b, []byte(v))
	}
	for _, v := range []int64{h.BaseRevision, h.Sequence, h.CostUnits, h.ExpiresAt} {
		b = number(b, v)
	}
	for _, v := range [][]byte{h.PreviousDigest, h.ClientSigningKey, h.EphemeralKey, h.ProviderEncryptionKey, h.ProviderSigningKey} {
		b = field(b, v)
	}
	return b
}
func (h Header) Validate() error {
	if h.Version != Version || !ValidID(h.ConversationID) || !ValidID(h.TurnID) || !ValidID(h.OwnerID) || !ValidID(h.ProviderID) || !ValidID(h.ModelRevision) ||
		h.BaseRevision < 0 || h.BaseRevision > 1<<40 || h.Sequence < 1 || h.Sequence > 1<<40 || h.CostUnits < 100000000 || h.CostUnits > 1000000000000 ||
		h.ExpiresAt <= 0 || len(h.PreviousDigest) != 0 && len(h.PreviousDigest) != 32 ||
		len(h.ClientSigningKey) != 32 || len(h.EphemeralKey) != 32 || len(h.ProviderEncryptionKey) != 32 || len(h.ProviderSigningKey) != 32 {
		return ErrEnvelope
	}
	return nil
}
func (h Header) Live(now time.Time) error {
	if e := h.Validate(); e != nil {
		return e
	}
	deadline := time.Unix(h.ExpiresAt, 0)
	if now.After(deadline.Add(ClockSkew)) || deadline.After(now.Add(Lifetime+ClockSkew)) {
		return ErrEnvelope
	}
	return nil
}
func (r Request) Canonical() []byte {
	b := field(nil, []byte("plenarai-opaque-request-v2"))
	b = field(b, r.Header.Canonical())
	b = field(b, r.ClientRecord)
	return field(b, r.Ciphertext)
}
func (r Request) Digest() []byte {
	b := field(r.Canonical(), r.Signature)
	h := sha256.Sum256(b)
	return append([]byte(nil), h[:]...)
}
func (r Request) Verify() error {
	if r.Header.Validate() != nil || len(r.ClientRecord) < 28 || len(r.ClientRecord) > MaxRecord || len(r.Ciphertext) < 28 || len(r.Ciphertext) > MaxCiphertext ||
		len(r.Signature) != 64 || !ed25519.Verify(r.Header.ClientSigningKey, r.Canonical(), r.Signature) {
		return ErrEnvelope
	}
	return nil
}
func requestAAD(r Request) []byte {
	b := field(nil, []byte("plenarai-opaque-work-request-v2"))
	b = field(b, r.Header.Canonical())
	sum := sha256.Sum256(r.ClientRecord)
	return field(b, sum[:])
}
func (r Response) Canonical() []byte {
	b := field(nil, []byte("plenarai-opaque-response-v2"))
	b = field(b, r.Header.Canonical())
	b = field(b, r.RequestDigest)
	b = field(b, []byte(r.Status))
	b = field(b, []byte(r.FailureCode))
	return field(b, r.Ciphertext)
}
func responseAAD(r Response) []byte {
	b := field(nil, []byte("plenarai-opaque-work-response-v2"))
	b = field(b, r.Header.Canonical())
	b = field(b, r.RequestDigest)
	b = field(b, []byte(r.Status))
	return field(b, []byte(r.FailureCode))
}
func (r Response) Digest() []byte {
	h := sha256.Sum256(field(r.Canonical(), r.Signature))
	return append([]byte(nil), h[:]...)
}
func (r Response) Verify(request Request) error {
	if request.Verify() != nil || !bytes.Equal(r.Header.Canonical(), request.Header.Canonical()) || !bytes.Equal(r.RequestDigest, request.Digest()) ||
		len(r.Ciphertext) < 28 || len(r.Ciphertext) > MaxRecord || len(r.Signature) != 64 {
		return ErrEnvelope
	}
	if r.Status == "completed" {
		if r.FailureCode != "" {
			return ErrEnvelope
		}
	} else if r.Status == "failed" {
		if r.FailureCode != "inference_failed" && r.FailureCode != "output_too_large" && r.FailureCode != "invalid_context" {
			return ErrEnvelope
		}
	} else {
		return ErrEnvelope
	}
	if !ed25519.Verify(request.Header.ProviderSigningKey, r.Canonical(), r.Signature) {
		return ErrEnvelope
	}
	return nil
}
func derive(shared []byte, h Header, purpose string) ([]byte, error) {
	salt := sha256.Sum256(h.Canonical())
	return hkdf.Key(sha256.New, shared, salt[:], "plenarai-opaque-v2:"+purpose, 32)
}
func aesSeal(k, p, aad []byte) ([]byte, error) {
	b, e := aes.NewCipher(k)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	n := make([]byte, g.NonceSize())
	if _, e = rand.Read(n); e != nil {
		return nil, e
	}
	return g.Seal(n, n, p, aad), nil
}
func aesOpen(k, c, aad []byte) ([]byte, error) {
	b, e := aes.NewCipher(k)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	if len(c) < g.NonceSize()+g.Overhead() {
		return nil, ErrEnvelope
	}
	p, e := g.Open(nil, c[:g.NonceSize()], c[g.NonceSize():], aad)
	if e != nil {
		return nil, ErrEnvelope
	}
	return p, nil
}

// SealRecord/OpenRecord derive a distinct key for each local record purpose.
// The backend and provider never receive the master secret.
func SealRecord(master []byte, purpose string, aad, plaintext []byte) ([]byte, error) {
	if len(master) != 32 {
		return nil, ErrEnvelope
	}
	k, e := hkdf.Key(sha256.New, master, nil, "plenarai-opaque-v2:record:"+purpose, 32)
	if e != nil {
		return nil, e
	}
	defer Zero(k)
	return aesSeal(k, plaintext, aad)
}
func OpenRecord(master []byte, purpose string, aad, ciphertext []byte) ([]byte, error) {
	if len(master) != 32 {
		return nil, ErrEnvelope
	}
	k, e := hkdf.Key(sha256.New, master, nil, "plenarai-opaque-v2:record:"+purpose, 32)
	if e != nil {
		return nil, e
	}
	defer Zero(k)
	return aesOpen(k, ciphertext, aad)
}
func SealRequest(h Header, recordCiphertext, context []byte, ephemeral *ecdh.PrivateKey, signer ed25519.PrivateKey) (Request, error) {
	if ephemeral == nil || len(signer) != 64 || !bytes.Equal(h.EphemeralKey, ephemeral.PublicKey().Bytes()) || !bytes.Equal(h.ClientSigningKey, signer.Public().(ed25519.PublicKey)) {
		return Request{}, ErrEnvelope
	}
	peer, e := ecdh.X25519().NewPublicKey(h.ProviderEncryptionKey)
	if e != nil {
		return Request{}, ErrEnvelope
	}
	shared, e := ephemeral.ECDH(peer)
	if e != nil {
		return Request{}, ErrEnvelope
	}
	defer Zero(shared)
	k, e := derive(shared, h, "request")
	if e != nil {
		return Request{}, e
	}
	defer Zero(k)
	r := Request{Header: h, ClientRecord: recordCiphertext}
	r.Ciphertext, e = aesSeal(k, context, requestAAD(r))
	if e != nil {
		return Request{}, e
	}
	r.Signature = ed25519.Sign(signer, r.Canonical())
	return r, r.Verify()
}
func OpenRequest(r Request, provider *ecdh.PrivateKey) ([]byte, []byte, error) {
	if r.Verify() != nil || provider == nil || !bytes.Equal(r.Header.ProviderEncryptionKey, provider.PublicKey().Bytes()) {
		return nil, nil, ErrEnvelope
	}
	peer, e := ecdh.X25519().NewPublicKey(r.Header.EphemeralKey)
	if e != nil {
		return nil, nil, ErrEnvelope
	}
	shared, e := provider.ECDH(peer)
	if e != nil {
		return nil, nil, ErrEnvelope
	}
	k, e := derive(shared, r.Header, "request")
	if e != nil {
		Zero(shared)
		return nil, nil, e
	}
	defer Zero(k)
	p, e := aesOpen(k, r.Ciphertext, requestAAD(r))
	if e != nil {
		Zero(shared)
		return nil, nil, e
	}
	return p, shared, nil
}
func SealResponse(r Request, shared, content []byte, status, code string, signer ed25519.PrivateKey) (Response, error) {
	if len(signer) != 64 || !bytes.Equal(signer.Public().(ed25519.PublicKey), r.Header.ProviderSigningKey) {
		return Response{}, ErrEnvelope
	}
	k, e := derive(shared, r.Header, "response")
	if e != nil {
		return Response{}, e
	}
	defer Zero(k)
	result := Response{Header: r.Header, RequestDigest: r.Digest(), Status: status, FailureCode: code}
	result.Ciphertext, e = aesSeal(k, content, responseAAD(result))
	if e != nil {
		return Response{}, e
	}
	result.Signature = ed25519.Sign(signer, result.Canonical())
	return result, result.Verify(r)
}
func OpenResponse(r Response, request Request, ephemeral *ecdh.PrivateKey) ([]byte, error) {
	if r.Verify(request) != nil || ephemeral == nil || !bytes.Equal(ephemeral.PublicKey().Bytes(), r.Header.EphemeralKey) {
		return nil, ErrEnvelope
	}
	peer, e := ecdh.X25519().NewPublicKey(r.Header.ProviderEncryptionKey)
	if e != nil {
		return nil, ErrEnvelope
	}
	shared, e := ephemeral.ECDH(peer)
	if e != nil {
		return nil, ErrEnvelope
	}
	defer Zero(shared)
	k, e := derive(shared, r.Header, "response")
	if e != nil {
		return nil, e
	}
	defer Zero(k)
	return aesOpen(k, r.Ciphertext, responseAAD(r))
}
func (c Create) AAD() []byte {
	b := field(nil, []byte("plenarai-opaque-create-v2"))
	b = number(b, int64(c.Version))
	for _, v := range []string{c.ConversationID, c.OwnerID, c.ProviderID, c.ModelRevision} {
		b = field(b, []byte(v))
	}
	for _, v := range [][]byte{c.ClientSigningKey, c.ProviderEncryptionKey, c.ProviderSigningKey} {
		b = field(b, v)
	}
	return b
}
func (c Create) Canonical() []byte { return field(c.AAD(), c.Ciphertext) }
func (c Create) Verify() error {
	if c.Version != Version || !ValidID(c.ConversationID) || !ValidID(c.OwnerID) || !ValidID(c.ProviderID) || !ValidID(c.ModelRevision) ||
		len(c.ClientSigningKey) != 32 || len(c.ProviderEncryptionKey) != 32 || len(c.ProviderSigningKey) != 32 || len(c.Ciphertext) < 28 || len(c.Ciphertext) > MaxCiphertext ||
		len(c.Signature) != 64 || !ed25519.Verify(c.ClientSigningKey, c.Canonical(), c.Signature) {
		return ErrEnvelope
	}
	return nil
}
