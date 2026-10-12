package opaquechat

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/plenarai/cli/internal/conversationer"
	"github.com/plenarai/cli/internal/inference"
	"github.com/plenarai/cli/internal/opaque"
)

type Provider struct {
	ID                   string  `json:"id"`
	ModelRevision        string  `json:"model_revision"`
	EncryptionKey        []byte  `json:"encryption_key"`
	SigningKey           []byte  `json:"signing_key"`
	Fingerprint          string  `json:"fingerprint"`
	ContextWindowTokens  int     `json:"context_window_tokens"`
	PromptOverheadTokens int     `json:"prompt_overhead_tokens"`
	MinCost              float64 `json:"min_cost"`
}
type Conversation struct {
	Create       opaque.Create `json:"create"`
	Revision     int64         `json:"revision"`
	NextSequence int64         `json:"next_sequence"`
	HeadDigest   []byte        `json:"head_digest"`
	ActiveTurnID *string       `json:"active_turn_id,omitempty"`
}
type Turn struct {
	Request  opaque.Request   `json:"request"`
	Response *opaque.Response `json:"response,omitempty"`
	State    string           `json:"state"`
}
type Archive struct {
	Title                string              `json:"title"`
	Messages             []inference.Message `json:"messages,omitempty"`
	Constraints          []string            `json:"constraints,omitempty"`
	SourceConversationID string              `json:"source_conversation_id,omitempty"`
	Summary              *TransferredSummary `json:"summary,omitempty"`
}

// record is sealed with the conversation master key; only this client reads it.
type record struct {
	Text             string       `json:"text"`
	EphemeralPrivate []byte       `json:"ephemeral_private"`
	Kind             string       `json:"kind,omitempty"`
	Summary          *summaryMeta `json:"summary,omitempty"`
	OverheadTokens   int          `json:"overhead_tokens,omitempty"`
	PayloadBytes     int          `json:"payload_bytes,omitempty"`
	PayloadMessages  int          `json:"payload_messages,omitempty"`
}

// answerBody is the provider plaintext inside the signed response ciphertext.
type answerBody struct {
	Text                string           `json:"text"`
	Usage               *inference.Usage `json:"usage,omitempty"`
	Reason              string           `json:"reason,omitempty"`
	ContextWindowTokens int              `json:"context_window_tokens,omitempty"`
}
type Session struct {
	Vault        *Vault
	Entry        *Entry
	Owner        string
	Conversation Conversation
	Exchanges    []Exchange
	Messages     []inference.Message
	Constraints  []string
	// Confirm asks the user a question; nil means a non-interactive session.
	Confirm  func(question string) string
	Notify   func(message string)
	archive  Archive
	state    *cacheState
	provider *Provider
}

func Owner() (string, error) {
	var me struct {
		ID string `json:"id"`
	}
	err := conversationer.Request("GET", "/v0/users/me", nil, nil, &me, 200)
	if err == nil && !opaque.ValidID(me.ID) {
		err = fmt.Errorf("invalid account identity")
	}
	return me.ID, err
}
func GetProvider(id, pin string) (Provider, error) {
	var p Provider
	if !opaque.ValidID(id) || len(pin) != 64 {
		return p, fmt.Errorf("--node-id and --provider-fingerprint (obtained directly from the node operator) are required")
	}
	err := conversationer.Request("GET", "/v0/opaque-providers/"+id, nil, nil, &p, 200)
	if err != nil {
		return p, err
	}
	actual := opaque.Fingerprint(p.EncryptionKey, p.SigningKey)
	if p.ID != id || len(p.EncryptionKey) != 32 || len(p.SigningKey) != 32 || !opaque.ValidID(p.ModelRevision) || actual != pin || p.Fingerprint != actual || p.ContextWindowTokens < 1 {
		return p, fmt.Errorf("provider identity does not match the independently verified fingerprint")
	}
	return p, nil
}
func Create(v *Vault, owner string, p Provider, archive Archive) (*Session, error) {
	id, err := opaque.NewID()
	if err != nil {
		return nil, err
	}
	master, err := opaque.RandomKey()
	if err != nil {
		return nil, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		opaque.Zero(master)
		return nil, err
	}
	defer opaque.Zero(priv)
	c := opaque.Create{Version: 2, ConversationID: id, OwnerID: owner, ProviderID: p.ID, ModelRevision: p.ModelRevision, ClientSigningKey: pub, ProviderEncryptionKey: p.EncryptionKey, ProviderSigningKey: p.SigningKey}
	if len(archive.Messages)%2 != 0 {
		opaque.Zero(master)
		return nil, fmt.Errorf("transfer requires complete user/assistant pairs")
	}
	for i, m := range archive.Messages {
		role := "user"
		if i%2 == 1 {
			role = "assistant"
		}
		if m.Role != role {
			opaque.Zero(master)
			return nil, fmt.Errorf("invalid transferred roles")
		}
	}
	archive, plain, err := fitArchive(archive)
	if err != nil {
		return nil, err
	}
	defer opaque.Zero(plain)
	c.Ciphertext, err = opaque.SealRecord(master, "archive", c.AAD(), plain)
	if err != nil {
		opaque.Zero(master)
		return nil, err
	}
	c.Signature = ed25519.Sign(priv, c.Canonical())
	if err = c.Verify(); err != nil {
		opaque.Zero(master)
		return nil, err
	}
	e := &Entry{Master: master, SigningSeed: priv.Seed(), Create: c}
	v.Entries[id] = e
	// Persist keys before the first network mutation. A failed upload can be resumed.
	if err = v.Save(); err != nil {
		return nil, err
	}
	var out Conversation
	if err = conversationer.Request("POST", "/v0/opaque-conversations", c, nil, &out, 201); err != nil {
		return nil, fmt.Errorf("conversation %s has local keys; resume with --conversation to retry its exact creation: %w", id, err)
	}
	e.CreationConfirmed = true
	if err = v.Save(); err != nil {
		return nil, err
	}
	s := &Session{Vault: v, Entry: e, Owner: owner}
	if err = s.Sync(); err != nil {
		return nil, err
	}
	return s, nil
}
func Resume(v *Vault, owner, id string) (*Session, error) {
	e := v.Entries[id]
	if e == nil {
		return nil, fmt.Errorf("the local key for this conversation is missing; import its encrypted key backup")
	}
	if e.Create.OwnerID != owner {
		return nil, fmt.Errorf("this key belongs to another account")
	}
	s := &Session{Vault: v, Entry: e, Owner: owner}
	if err := s.Sync(); err != nil {
		var apiErr *conversationer.APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusNotFound || e.CreationConfirmed || e.Revision != 0 {
			return nil, err
		}
		var out Conversation
		if err = conversationer.Request("POST", "/v0/opaque-conversations", e.Create, nil, &out, 201); err != nil {
			return nil, err
		}
		e.CreationConfirmed = true
		if err = v.Save(); err != nil {
			return nil, err
		}
		if err = s.Sync(); err != nil {
			return nil, err
		}
	}
	return s, nil
}
func (s *Session) id() string   { return s.Entry.Create.ConversationID }
func (s *Session) path() string { return "/v0/opaque-conversations/" + s.id() }

// Sync verifies the signed chain and rebuilds the local transcript. A valid
// encrypted cache lets it verify only turns after the cached terminal turn;
// any cache disagreement is discarded and followed by one full verification.
func (s *Session) Sync() error {
	if cached := loadCache(s.Entry); cached != nil {
		err := s.sync(cached)
		if !errors.Is(err, errCacheMismatch) {
			return err
		}
		deleteCache(s.id())
	}
	return s.sync(nil)
}
func (s *Session) sync(cached *cacheState) error {
	var c Conversation
	if err := conversationer.Request("GET", s.path(), nil, nil, &c, 200); err != nil {
		return err
	}
	a, _ := json.Marshal(c.Create)
	b, _ := json.Marshal(s.Entry.Create)
	signer := ed25519.NewKeyFromSeed(s.Entry.SigningSeed)
	defer opaque.Zero(signer)
	if !bytes.Equal(a, b) || c.Create.Verify() != nil || !bytes.Equal(signer.Public().(ed25519.PublicKey), c.Create.ClientSigningKey) || c.Revision < s.Entry.Revision {
		return fmt.Errorf("conversation identity or history rollback detected")
	}
	plain, err := opaque.OpenRecord(s.Entry.Master, "archive", c.Create.AAD(), c.Create.Ciphertext)
	if err != nil {
		return fmt.Errorf("cannot decrypt conversation archive")
	}
	var archive Archive
	err = json.Unmarshal(plain, &archive)
	opaque.Zero(plain)
	if err != nil {
		return fmt.Errorf("invalid encrypted archive")
	}
	constraints := archive.Constraints
	if len(s.Entry.Settings) > 0 {
		body, e := opaque.OpenRecord(s.Entry.Master, "settings", []byte(s.id()), s.Entry.Settings)
		if e != nil {
			return fmt.Errorf("cannot decrypt local conversation settings")
		}
		e = json.Unmarshal(body, &constraints)
		opaque.Zero(body)
		if e != nil {
			return fmt.Errorf("invalid local conversation settings")
		}
	}
	base := archiveExchanges(archive)
	st := &cacheState{Version: cacheVersion}
	anchorFound := s.Entry.Revision == 0 && len(s.Entry.Head) == 0
	pendingFound := false
	if cached != nil {
		if c.Revision < cached.Revision {
			return fmt.Errorf("conversation identity or history rollback detected")
		}
		st = cached
		if r := s.Entry.Revision; !anchorFound && r >= 1 && r <= st.Revision {
			d := st.TurnDigests[r-1]
			if !bytes.Equal(s.Entry.Head, d.Request) && !bytes.Equal(s.Entry.Head, d.Terminal) {
				return errCacheMismatch
			}
			anchorFound = true
		}
		if p := s.Entry.Pending; p != nil && p.Header.BaseRevision < st.Revision {
			if !bytes.Equal(st.TurnDigests[p.Header.BaseRevision].Request, p.Digest()) {
				return errCacheMismatch
			}
			pendingFound = true
		}
	}
	chainErr := fmt.Errorf("invalid encrypted history chain")
	if cached != nil {
		chainErr = errCacheMismatch
	}
	rev, head, after := st.Revision, append([]byte{}, st.Head...), st.After
	checkpoint := struct {
		rev, after int64
		head       []byte
	}{rev, after, head}
	var last *Turn
	for {
		var page []Turn
		if err = conversationer.Request("GET", s.path()+"/turns?after="+strconv.FormatInt(after, 10), nil, nil, &page, 200); err != nil {
			return err
		}
		if len(page) == 0 {
			break
		}
		for _, t := range page {
			h := t.Request.Header
			if t.Request.Verify() != nil || h.ConversationID != s.id() || h.OwnerID != s.Owner || h.ProviderID != c.Create.ProviderID || h.ModelRevision != c.Create.ModelRevision ||
				!bytes.Equal(h.ClientSigningKey, c.Create.ClientSigningKey) || !bytes.Equal(h.ProviderEncryptionKey, c.Create.ProviderEncryptionKey) || !bytes.Equal(h.ProviderSigningKey, c.Create.ProviderSigningKey) {
				return fmt.Errorf("invalid encrypted history chain")
			}
			if h.Sequence != rev*2+1 || h.BaseRevision != rev || !bytes.Equal(h.PreviousDigest, head) {
				return chainErr
			}
			if last != nil && last.State == "pending" {
				return fmt.Errorf("invalid encrypted turn state")
			}
			rev++
			head = t.Request.Digest()
			request := head
			after = h.Sequence
			if rev == s.Entry.Revision && bytes.Equal(head, s.Entry.Head) {
				anchorFound = true
			}
			recBytes, e := opaque.OpenRecord(s.Entry.Master, "message", h.Canonical(), t.Request.ClientRecord)
			if e != nil {
				return fmt.Errorf("cannot decrypt own message record")
			}
			var rec record
			e = json.Unmarshal(recBytes, &rec)
			opaque.Zero(recBytes)
			if e != nil || len(rec.EphemeralPrivate) != 32 || rec.Kind != "" && rec.Kind != "summary" || (rec.Kind == "summary") != (rec.Summary != nil) {
				return fmt.Errorf("invalid local message record")
			}
			if t.Response != nil {
				if t.Response.Verify(t.Request) != nil {
					return fmt.Errorf("invalid provider response signature")
				}
				ephemeral, e := ecdh.X25519().NewPrivateKey(rec.EphemeralPrivate)
				opaque.Zero(rec.EphemeralPrivate)
				if e != nil {
					return e
				}
				raw, e := opaque.OpenResponse(*t.Response, t.Request, ephemeral)
				if e != nil {
					return fmt.Errorf("cannot decrypt provider response")
				}
				var answer answerBody
				e = json.Unmarshal(raw, &answer)
				opaque.Zero(raw)
				if e != nil || t.State != t.Response.Status || (t.State == "completed" && (answer.Text == "" || len(answer.Text) > opaque.MaxAnswer)) {
					return fmt.Errorf("invalid encrypted provider content")
				}
				head = t.Response.Digest()
				if t.State == "completed" && rec.Kind == "" {
					st.Exchanges = append(st.Exchanges, Exchange{N: len(base) + len(st.Exchanges) + 1, Revision: rev, User: rec.Text, Assistant: answer.Text})
				}
				observe(st, archive, rec, answer, t.State, rev, h.ExpiresAt, len(base)+len(st.Exchanges))
			} else {
				opaque.Zero(rec.EphemeralPrivate)
				if t.State != "pending" && t.State != "failed" {
					return fmt.Errorf("invalid encrypted turn state")
				}
			}
			st.TurnDigests = append(st.TurnDigests, turnDigest{Request: request, Terminal: head})
			if t.State != "pending" {
				checkpoint.rev, checkpoint.after, checkpoint.head = rev, after, head
			}
			if rev == s.Entry.Revision && bytes.Equal(head, s.Entry.Head) {
				anchorFound = true
			}
			if s.Entry.Pending != nil && h.TurnID == s.Entry.Pending.Header.TurnID {
				if !bytes.Equal(t.Request.Digest(), s.Entry.Pending.Digest()) {
					return fmt.Errorf("pending request was replaced")
				}
				pendingFound = t.State != "pending"
			}
			copy := t
			last = &copy
		}
		if len(page) < 20 {
			break
		}
	}
	if !anchorFound || rev != c.Revision || c.NextSequence != rev*2+1 || !bytes.Equal(head, c.HeadDigest) {
		if cached != nil {
			return errCacheMismatch
		}
		return fmt.Errorf("incomplete encrypted history or rollback")
	}
	if c.ActiveTurnID != nil && (last == nil || last.State != "pending" || last.Request.Header.TurnID != *c.ActiveTurnID) {
		return fmt.Errorf("invalid active turn")
	}
	if last != nil && last.State == "pending" && c.ActiveTurnID == nil {
		return fmt.Errorf("missing active turn")
	}
	// GET and history are separate snapshots: concurrent completion returns a safe
	// error and can be retried, never a guessed or silently truncated transcript.
	s.Entry.Revision = rev
	s.Entry.Head = append([]byte{}, head...)
	if pendingFound {
		s.Entry.Pending = nil
	}
	st.Revision, st.After, st.Head = checkpoint.rev, checkpoint.after, append([]byte{}, checkpoint.head...)
	st.TurnDigests = st.TurnDigests[:checkpoint.rev]
	s.Conversation = c
	s.archive = archive
	s.state = st
	s.Exchanges = append(base, st.Exchanges...)
	s.Messages = flatten(s.Exchanges)
	s.Constraints = constraints
	s.clampWindow()
	saveCache(s.Entry, st)
	return s.Vault.Save()
}

// clampWindow keeps window_start after the active summary and inside E.
func (s *Session) clampWindow() {
	if a := currentSummary(s.state, s.archive); a != nil && s.state.WindowStart < a.K+1 {
		s.state.WindowStart = a.K + 1
	}
	if s.state.WindowStart < 1 {
		s.state.WindowStart = 1
	}
	if s.state.WindowStart > len(s.Exchanges)+1 {
		s.state.WindowStart = len(s.Exchanges) + 1
	}
}
func archiveExchanges(a Archive) []Exchange {
	out := []Exchange{}
	for i := 0; i+1 < len(a.Messages); i += 2 {
		if a.Messages[i].Role == "user" && a.Messages[i+1].Role == "assistant" {
			out = append(out, Exchange{N: len(out) + 1, User: a.Messages[i].Content, Assistant: a.Messages[i+1].Content})
		}
	}
	return out
}
func flatten(exchanges []Exchange) []inference.Message {
	out := make([]inference.Message, 0, len(exchanges)*2)
	for _, e := range exchanges {
		out = append(out, inference.Message{Role: "user", Content: e.User}, inference.Message{Role: "assistant", Content: e.Assistant})
	}
	return out
}
func (s *Session) ReconcilePending() (string, error) {
	if s.Entry.Pending == nil {
		return "", nil
	}
	pending := *s.Entry.Pending
	var turn Turn
	err := conversationer.Request("POST", s.path()+"/turns", pending, nil, &turn, 202)
	if err != nil {
		// An expired request that the backend never accepted can be discarded only
		// after an authenticated exact-ID lookup confirms that it does not exist.
		var existing Turn
		lookup := conversationer.Request("GET", s.path()+"/turns/"+pending.Header.TurnID, nil, nil, &existing, 200)
		var apiErr *conversationer.APIError
		if errors.As(lookup, &apiErr) && apiErr.StatusCode == http.StatusNotFound && time.Now().Unix() > pending.Header.ExpiresAt {
			s.Entry.Pending = nil
			if saveErr := s.Vault.Save(); saveErr != nil {
				return "", saveErr
			}
			return "", fmt.Errorf("the previous encrypted message expired before acceptance; no automatic replacement was sent")
		}
		if lookup != nil {
			return "", err
		}
	}
	return s.Wait(pending)
}
func (s *Session) Wait(request opaque.Request) (string, error) {
	deadline := time.Unix(request.Header.ExpiresAt, 0).Add(10 * time.Second)
	for {
		var t Turn
		if err := conversationer.Request("GET", s.path()+"/turns/"+request.Header.TurnID, nil, nil, &t, 200); err != nil {
			return "", err
		}
		if !bytes.Equal(t.Request.Digest(), request.Digest()) || t.Request.Verify() != nil {
			return "", fmt.Errorf("turn identity mismatch")
		}
		if t.State != "pending" {
			var answer answerBody
			summary := false
			if t.Response != nil {
				if err := t.Response.Verify(request); err != nil {
					return "", err
				}
				body, err := opaque.OpenRecord(s.Entry.Master, "message", request.Header.Canonical(), request.ClientRecord)
				if err != nil {
					return "", err
				}
				var rec record
				err = json.Unmarshal(body, &rec)
				opaque.Zero(body)
				if err != nil {
					return "", err
				}
				summary = rec.Kind == "summary"
				ephemeral, err := ecdh.X25519().NewPrivateKey(rec.EphemeralPrivate)
				opaque.Zero(rec.EphemeralPrivate)
				if err != nil {
					return "", err
				}
				body, err = opaque.OpenResponse(*t.Response, request, ephemeral)
				if err != nil {
					return "", err
				}
				err = json.Unmarshal(body, &answer)
				opaque.Zero(body)
				if err != nil {
					return "", err
				}
				if t.Response.Status != t.State {
					return "", fmt.Errorf("turn state mismatch")
				}
			}
			if err := s.Sync(); err != nil {
				return "", err
			}
			if t.State != "completed" && answer.Reason == "context_window_exceeded" && answer.Usage != nil {
				return "", fmt.Errorf("the message did not fit the provider's context window (%d of %d tokens); credits are refunded, send it again", answer.Usage.PromptTokens, answer.ContextWindowTokens)
			}
			if t.State != "completed" {
				return "", fmt.Errorf("encrypted inference failed or expired; credits are refunded")
			}
			// Summary turns update the derived memory in Sync, never the transcript.
			if summary {
				return "", nil
			}
			return answer.Text, nil
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("turn remains pending; resume this conversation to reconcile it")
		}
		time.Sleep(time.Second)
	}
}

// prepare repeats the checks every paid turn needs and refreshes the pinned
// provider metadata used for budgeting.
func (s *Session) prepare(cost float64) (*Provider, error) {
	if s.Entry.Pending != nil {
		return nil, fmt.Errorf("reconcile the previous turn first")
	}
	if err := s.Sync(); err != nil {
		return nil, err
	}
	if s.Conversation.ActiveTurnID != nil {
		return nil, fmt.Errorf("conversation already has an active turn")
	}
	p, err := s.refreshProvider()
	if err != nil {
		return nil, err
	}
	if math.IsNaN(cost) || math.IsInf(cost, 0) || cost < 1 || cost > 10000 || cost < p.MinCost {
		return nil, fmt.Errorf("invalid price or price below provider minimum")
	}
	return p, nil
}
func (s *Session) refreshProvider() (*Provider, error) {
	c := s.Entry.Create
	p, err := GetProvider(c.ProviderID, opaque.Fingerprint(c.ProviderEncryptionKey, c.ProviderSigningKey))
	if err != nil {
		return nil, err
	}
	if p.ModelRevision != c.ModelRevision {
		return nil, fmt.Errorf("provider changed its model; explicitly transfer to a new conversation")
	}
	s.provider = &p
	return s.provider, nil
}
func (s *Session) budget() (Budget, error) {
	if s.provider == nil {
		if _, err := s.refreshProvider(); err != nil {
			return Budget{}, err
		}
	}
	return computeBudget(*s.provider, s.state.RatioObservations)
}
func (s *Session) projection() projection {
	return projection{Constraints: s.Constraints, Summary: currentSummary(s.state, s.archive), Exchanges: s.Exchanges, Start: s.state.WindowStart}
}

// ensureBudget keeps the next turn inside the provider window: first by a
// summary when allowed (§21.5), otherwise by moving window_start in one step.
func (s *Session) ensureBudget(ph phase, current string, cost float64) error {
	b, err := s.budget()
	if err != nil {
		return err
	}
	p := s.projection()
	if b.fits(p, b.limit(ph, current)) {
		return nil
	}
	if ok, err := s.compact(p, b, cost); err != nil {
		return err
	} else if ok {
		if b, err = s.budget(); err != nil {
			return err
		}
		if p = s.projection(); b.fits(p, b.limit(ph, current)) {
			return nil
		}
	}
	start, err := planWindow(p, b, ph, current)
	if start != s.state.WindowStart {
		s.state.WindowStart = start
		saveCache(s.Entry, s.state)
	}
	return err
}

// AfterTurn compacts right after a delivered answer so the next send rarely waits.
func (s *Session) AfterTurn(cost float64) error {
	return s.ensureBudget(afterTurn, "", cost)
}
func (s *Session) Send(text string, cost float64) (string, error) {
	if _, err := s.prepare(cost); err != nil {
		return "", err
	}
	if err := s.ensureBudget(beforeSend, text, cost); err != nil {
		return "", err
	}
	b, err := s.budget()
	if err != nil {
		return "", err
	}
	return s.sendRecord(record{Text: text}, buildProjection(s.projection(), text), b, cost)
}

// sendRecord seals one paid turn. The record keeps only what the user typed
// (or the summary metadata) plus sizes needed to calibrate token estimates.
func (s *Session) sendRecord(rec record, messages []inference.Message, b Budget, cost float64) (string, error) {
	c := s.Entry.Create
	rec.OverheadTokens, rec.PayloadMessages, rec.PayloadBytes = b.S, len(messages), 0
	for _, m := range messages {
		rec.PayloadBytes += len(m.Content)
	}
	payload, err := json.Marshal(struct {
		Messages []inference.Message `json:"messages"`
	}{messages})
	if err != nil {
		return "", err
	}
	defer opaque.Zero(payload)
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	id, err := opaque.NewID()
	if err != nil {
		return "", err
	}
	h := opaque.Header{Version: 2, ConversationID: s.id(), TurnID: id, OwnerID: s.Owner, ProviderID: c.ProviderID, ModelRevision: c.ModelRevision,
		BaseRevision: s.Conversation.Revision, Sequence: s.Conversation.NextSequence, CostUnits: int64(math.Round(cost * 1e8)), ExpiresAt: time.Now().Add(opaque.Lifetime).Unix(),
		PreviousDigest: s.Conversation.HeadDigest, ClientSigningKey: c.ClientSigningKey, EphemeralKey: ephemeral.PublicKey().Bytes(), ProviderEncryptionKey: c.ProviderEncryptionKey, ProviderSigningKey: c.ProviderSigningKey}
	rec.EphemeralPrivate = ephemeral.Bytes()
	body, _ := json.Marshal(rec)
	defer opaque.Zero(body)
	encryptedRecord, err := opaque.SealRecord(s.Entry.Master, "message", h.Canonical(), body)
	if err != nil {
		return "", err
	}
	signer := ed25519.NewKeyFromSeed(s.Entry.SigningSeed)
	defer opaque.Zero(signer)
	request, err := opaque.SealRequest(h, encryptedRecord, payload, ephemeral, signer)
	if err != nil {
		return "", err
	}
	s.Entry.Pending = &request
	if err = s.Vault.Save(); err != nil {
		return "", err
	}
	return s.ReconcilePending()
}

// fitArchive drops the oldest exchanges until the signed archive fits its record.
func fitArchive(a Archive) (Archive, []byte, error) {
	plain, err := json.Marshal(a)
	for err == nil && len(plain) > opaque.MaxRecord-28 && len(a.Messages) >= 2 {
		opaque.Zero(plain)
		a.Messages = a.Messages[2:]
		plain, err = json.Marshal(a)
	}
	return a, plain, err
}

// transferArchive copies the active summary (without references to this
// conversation's numbering) and the exchanges it does not cover.
func (s *Session) transferArchive(title string) Archive {
	a := Archive{Title: title, Constraints: s.Constraints, SourceConversationID: s.id()}
	k := 0
	if sum := currentSummary(s.state, s.archive); sum != nil {
		k = sum.K
		a.Summary = &TransferredSummary{Text: summaryRef.ReplaceAllString(sum.Text, ""), SourceConversationID: s.id(), SourceCoversThrough: sum.K,
			SourceProviderID: s.Entry.Create.ProviderID, SourceModelRevision: s.Entry.Create.ModelRevision, CreatedAt: sum.CreatedAt}
	}
	a.Messages = flatten(s.Exchanges[min(k, len(s.Exchanges)):])
	return a
}

// TransferPreview is what a new provider would receive, without content.
type TransferPreview struct {
	Exchanges, SummaryBytes, Requirements int
	HasSummary                            bool
}

func (s *Session) PreviewTransfer(title string) (TransferPreview, error) {
	if err := s.Sync(); err != nil {
		return TransferPreview{}, err
	}
	a, plain, err := fitArchive(s.transferArchive(title))
	opaque.Zero(plain)
	if err != nil {
		return TransferPreview{}, err
	}
	p := TransferPreview{Exchanges: len(a.Messages) / 2, Requirements: len(a.Constraints), HasSummary: a.Summary != nil}
	if a.Summary != nil {
		p.SummaryBytes = len(a.Summary.Text)
	}
	return p, nil
}
func (s *Session) Transfer(provider Provider, title string) (*Session, error) {
	if err := s.Sync(); err != nil {
		return nil, err
	}
	if s.Conversation.ActiveTurnID != nil || s.Entry.Pending != nil {
		return nil, fmt.Errorf("finish or reconcile the active turn before transferring")
	}
	// The new provider receives this context only on the next explicitly sent
	// turn. Its key never gains access to the previous encrypted archive.
	return Create(s.Vault, s.Owner, provider, s.transferArchive(title))
}

// SetConstraints stores encrypted local preferences and includes them only in
// the next selected node's encrypted context, never in a plaintext API field.
func (s *Session) SetConstraints(values []string) error {
	if s.Entry.Pending != nil || s.Conversation.ActiveTurnID != nil {
		return fmt.Errorf("finish the active turn before editing constraints")
	}
	if len(values) > 32 {
		return fmt.Errorf("at most 32 explicit requirements")
	}
	total := 0
	for _, v := range values {
		total += len(v)
		if v == "" || len(v) > 4096 {
			return fmt.Errorf("invalid explicit requirement")
		}
	}
	if total > 16384 {
		return fmt.Errorf("explicit requirements are too large")
	}
	raw, err := json.Marshal(values)
	if err != nil {
		return err
	}
	defer opaque.Zero(raw)
	encrypted, err := opaque.SealRecord(s.Entry.Master, "settings", []byte(s.id()), raw)
	if err != nil {
		return err
	}
	s.Entry.Settings = encrypted
	if err = s.Vault.Save(); err != nil {
		return err
	}
	s.Constraints = append([]string{}, values...)
	return nil
}
