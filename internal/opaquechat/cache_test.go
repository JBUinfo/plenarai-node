package opaquechat

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/plenarai/cli/internal/auth"
	"github.com/plenarai/cli/internal/config"
	"github.com/plenarai/cli/internal/inference"
	"github.com/plenarai/cli/internal/opaque"
)

// fakeChain signs a real opaque history and serves it like the backend.
type fakeChain struct {
	t       *testing.T
	entry   *Entry
	owner   string
	node    *ecdh.PrivateKey
	signer  ed25519.PrivateKey
	turns   []Turn
	visible int
	afters  []int64
	// respond plays the provider for turns posted by the client under test.
	respond func(messages []inference.Message) (string, inference.Usage)
	window  int
}

func newFakeChain(t *testing.T) *fakeChain {
	t.Helper()
	master, _ := opaque.RandomKey()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	node, _ := ecdh.X25519().GenerateKey(rand.Reader)
	nodePub, nodePriv, _ := ed25519.GenerateKey(rand.Reader)
	f := &fakeChain{t: t, owner: "33333333-3333-4333-8333-333333333333", node: node, signer: nodePriv}
	c := opaque.Create{Version: 2, ConversationID: "11111111-1111-4111-8111-111111111111", OwnerID: f.owner, ProviderID: "44444444-4444-4444-8444-444444444444", ModelRevision: "55555555-5555-4555-8555-555555555555", ClientSigningKey: pub, ProviderEncryptionKey: node.PublicKey().Bytes(), ProviderSigningKey: nodePub}
	c.Ciphertext, _ = opaque.SealRecord(master, "archive", c.AAD(), []byte(`{"title":"t"}`))
	c.Signature = ed25519.Sign(priv, c.Canonical())
	f.entry = &Entry{Master: master, SigningSeed: priv.Seed(), Create: c, CreationConfirmed: true}
	return f
}
func (f *fakeChain) head(n int) []byte {
	if n == 0 {
		return nil
	}
	if r := f.turns[n-1].Response; r != nil {
		return r.Digest()
	}
	return f.turns[n-1].Request.Digest()
}
func (f *fakeChain) add(text, answer string) { f.addRecord(record{Text: text}, answer) }
func (f *fakeChain) addRecord(rec record, answer string) {
	f.t.Helper()
	c := f.entry.Create
	rev := int64(len(f.turns))
	eph, _ := ecdh.X25519().GenerateKey(rand.Reader)
	id, _ := opaque.NewID()
	h := opaque.Header{Version: 2, ConversationID: c.ConversationID, TurnID: id, OwnerID: f.owner, ProviderID: c.ProviderID, ModelRevision: c.ModelRevision, BaseRevision: rev, Sequence: rev*2 + 1, CostUnits: 100000000,
		ExpiresAt: time.Now().Add(opaque.Lifetime).Unix(), PreviousDigest: f.head(len(f.turns)), ClientSigningKey: c.ClientSigningKey, EphemeralKey: eph.PublicKey().Bytes(), ProviderEncryptionKey: c.ProviderEncryptionKey, ProviderSigningKey: c.ProviderSigningKey}
	rec.EphemeralPrivate = eph.Bytes()
	body, _ := json.Marshal(rec)
	rc, _ := opaque.SealRecord(f.entry.Master, "message", h.Canonical(), body)
	req, err := opaque.SealRequest(h, rc, []byte(`{"messages":[{"role":"user","content":"x"}]}`), eph, ed25519.NewKeyFromSeed(f.entry.SigningSeed))
	if err != nil {
		f.t.Fatal(err)
	}
	_, shared, err := opaque.OpenRequest(req, f.node)
	if err != nil {
		f.t.Fatal(err)
	}
	out, _ := json.Marshal(answerBody{Text: answer})
	resp, err := opaque.SealResponse(req, shared, out, "completed", "", f.signer)
	if err != nil {
		f.t.Fatal(err)
	}
	f.turns = append(f.turns, Turn{Request: req, Response: &resp, State: "completed"})
	f.visible = len(f.turns)
}
func (f *fakeChain) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	base := "/v0/opaque-conversations/" + f.entry.Create.ConversationID
	turns := f.turns[:f.visible]
	if r.Method == http.MethodPost && r.URL.Path == base+"/turns" {
		var req opaque.Request
		if json.NewDecoder(r.Body).Decode(&req) != nil || req.Verify() != nil || req.Header.BaseRevision != int64(len(f.turns)) {
			http.Error(w, "conflict", http.StatusConflict)
			return
		}
		body, shared, err := opaque.OpenRequest(req, f.node)
		if err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		var in struct{ Messages []inference.Message }
		json.Unmarshal(body, &in)
		text, usage := f.respond(in.Messages)
		out, _ := json.Marshal(answerBody{Text: text, Usage: &usage})
		resp, _ := opaque.SealResponse(req, shared, out, "completed", "", f.signer)
		f.turns = append(f.turns, Turn{Request: req, Response: &resp, State: "completed"})
		f.visible = len(f.turns)
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(f.turns[len(f.turns)-1])
		return
	}
	for _, t := range turns {
		if r.URL.Path == base+"/turns/"+t.Request.Header.TurnID {
			json.NewEncoder(w).Encode(t)
			return
		}
	}
	switch r.URL.Path {
	case "/v0/opaque-providers/" + f.entry.Create.ProviderID:
		c := f.entry.Create
		json.NewEncoder(w).Encode(Provider{ID: c.ProviderID, ModelRevision: c.ModelRevision, EncryptionKey: c.ProviderEncryptionKey, SigningKey: c.ProviderSigningKey, Fingerprint: opaque.Fingerprint(c.ProviderEncryptionKey, c.ProviderSigningKey), ContextWindowTokens: f.window, MinCost: 1})
	case base:
		json.NewEncoder(w).Encode(Conversation{Create: f.entry.Create, Revision: int64(len(turns)), NextSequence: int64(len(turns))*2 + 1, HeadDigest: f.head(len(turns))})
	case base + "/turns":
		after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
		f.afters = append(f.afters, after)
		page := []Turn{}
		for _, t := range turns {
			if t.Request.Header.Sequence > after && len(page) < 20 {
				page = append(page, t)
			}
		}
		json.NewEncoder(w).Encode(page)
	default:
		http.NotFound(w, r)
	}
}

// serveFakeChain points the client at f with a temporary credential store.
func serveFakeChain(t *testing.T, f *fakeChain) *Vault {
	t.Helper()
	t.Setenv("PLENARAI_CONFIG_DIR", filepath.Join(t.TempDir(), "secrets"))
	if err := auth.SaveTokens(&auth.TokenPair{AccessToken: "test", RefreshToken: "test"}); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(f)
	t.Cleanup(server.Close)
	old := config.ServerURL
	config.ServerURL = server.URL
	t.Cleanup(func() { config.ServerURL = old })
	v, err := OpenVault()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.Close)
	v.Entries[f.entry.Create.ConversationID] = f.entry
	return v
}
func TestSyncCacheIncrementalCorruptionAndRollback(t *testing.T) {
	f := newFakeChain(t)
	for i := 0; i < 30; i++ {
		f.add("question "+strconv.Itoa(i), "answer "+strconv.Itoa(i))
	}
	v := serveFakeChain(t, f)
	var err error
	sync := func() (*Session, error) {
		s := &Session{Vault: v, Entry: f.entry, Owner: f.owner}
		return s, s.Sync()
	}
	if s, err := sync(); err != nil || len(s.Exchanges) != 30 || len(f.afters) != 2 || f.afters[0] != 0 {
		t.Fatalf("full sync: %v exchanges=%d afters=%v", err, len(s.Exchanges), f.afters)
	}
	f.add("question 30", "answer 30")
	f.afters = nil
	s, err := sync()
	if err != nil || len(s.Exchanges) != 31 || len(f.afters) != 1 || f.afters[0] != 59 || s.Exchanges[30].N != 31 || s.Exchanges[30].User != "question 30" {
		t.Fatalf("cached sync must fetch only new turns: %v afters=%v", err, f.afters)
	}
	path, _ := auth.SecretPath(cacheName(f.entry.Create.ConversationID), false)
	if err = os.WriteFile(path, []byte("corrupted"), 0600); err != nil {
		t.Fatal(err)
	}
	f.afters = nil
	if s, err = sync(); err != nil || len(s.Exchanges) != 31 || f.afters[0] != 0 {
		t.Fatalf("corrupted cache must rebuild silently: %v afters=%v", err, f.afters)
	}
	// An older restored key anchor must not let a truncated server history
	// hide turns that this device already verified into its cache.
	f.entry.Revision, f.entry.Head = 20, f.head(20)
	f.visible = 25
	if _, err = sync(); err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("history shorter than the verified cache was accepted: %v", err)
	}
}
