package opaque

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func fixture(t *testing.T) (Header, *ecdh.PrivateKey, *ecdh.PrivateKey, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	node, _ := ecdh.X25519().GenerateKey(rand.Reader)
	ephemeral, _ := ecdh.X25519().GenerateKey(rand.Reader)
	clientPub, client, _ := ed25519.GenerateKey(rand.Reader)
	nodePub, signer, _ := ed25519.GenerateKey(rand.Reader)
	h := Header{Version: 2, ConversationID: "11111111-1111-4111-8111-111111111111", TurnID: "22222222-2222-4222-8222-222222222222", OwnerID: "33333333-3333-4333-8333-333333333333", ProviderID: "44444444-4444-4444-8444-444444444444", ModelRevision: "55555555-5555-4555-8555-555555555555",
		Sequence: 1, CostUnits: 1e8, ExpiresAt: time.Now().Add(Lifetime).Unix(), ClientSigningKey: clientPub, EphemeralKey: ephemeral.PublicKey().Bytes(), ProviderEncryptionKey: node.PublicKey().Bytes(), ProviderSigningKey: nodePub}
	return h, node, ephemeral, client, signer
}
func TestClientNodeOnlyAndTranscriptBinding(t *testing.T) {
	h, node, ephemeral, client, signer := fixture(t)
	master, _ := RandomKey()
	record, err := SealRecord(master, "message", h.Canonical(), []byte("CLIENT-RECORD-CANARY"))
	if err != nil {
		t.Fatal(err)
	}
	req, err := SealRequest(h, record, []byte("CONTEXT-CANARY"), ephemeral, client)
	if err != nil {
		t.Fatal(err)
	}
	body, shared, err := OpenRequest(req, node)
	if err != nil || string(body) != "CONTEXT-CANARY" {
		t.Fatalf("decrypt: %v", err)
	}
	if _, err = OpenRecord(shared, "message", h.Canonical(), record); err == nil {
		t.Fatal("node shared key opened client-only history")
	}
	wrong, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if _, _, err = OpenRequest(req, wrong); err == nil {
		t.Fatal("another node opened the request")
	}
	response, err := SealResponse(req, shared, []byte("ANSWER-CANARY"), "completed", "", signer)
	if err != nil {
		t.Fatal(err)
	}
	body, err = OpenResponse(response, req, ephemeral)
	if err != nil || string(body) != "ANSWER-CANARY" {
		t.Fatal("client failed to decrypt")
	}
	if _, err = OpenResponse(response, req, wrong); err == nil {
		t.Fatal("coordinator key opened the answer")
	}
	for _, mutate := range []func(*Request){
		func(r *Request) { r.Header.OwnerID = h.ProviderID },
		func(r *Request) { r.Header.CostUnits++ },
		func(r *Request) { r.Header.Sequence++ },
		func(r *Request) { r.Header.ExpiresAt++ },
		func(r *Request) { r.Header.ProviderEncryptionKey = wrong.PublicKey().Bytes() },
		func(r *Request) { r.ClientRecord = append([]byte{}, r.ClientRecord...); r.ClientRecord[0] ^= 1 },
		func(r *Request) { r.Ciphertext = append([]byte{}, r.Ciphertext...); r.Ciphertext[0] ^= 1 },
	} {
		changed := req
		mutate(&changed)
		if changed.Verify() == nil || response.Verify(changed) == nil {
			t.Fatal("tampered transcript accepted")
		}
	}
	replay := req
	replay.Header.TurnID = h.ConversationID
	replay.Signature = ed25519.Sign(client, replay.Canonical())
	if response.Verify(replay) == nil {
		t.Fatal("response replayed on a different turn")
	}
	modified := response
	modified.Status = "failed"
	modified.FailureCode = "inference_failed"
	if modified.Verify(req) == nil {
		t.Fatal("unsigned billing status change accepted")
	}
	if bytes.Contains(req.Ciphertext, []byte("CONTEXT-CANARY")) {
		t.Fatal("plaintext in ciphertext")
	}
}
