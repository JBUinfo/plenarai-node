package opaquechat

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/plenarai/cli/internal/auth"
	"github.com/plenarai/cli/internal/inference"
	"github.com/plenarai/cli/internal/opaque"
)

// The cache is a disposable derivative of the verified chain, sealed with the
// conversation master key. Any doubt about it triggers a full verified sync.
const cacheVersion = 1
const maxCacheBytes = 256 << 20

var errCacheMismatch = errors.New("local encrypted history cache does not match the server chain")

type turnDigest struct {
	Request  []byte `json:"request"`
	Terminal []byte `json:"terminal"`
}

// Exchange is one completed chat turn. N is its stable 1-based position in E.
type Exchange struct {
	N         int    `json:"n"`
	Revision  int64  `json:"revision"`
	User      string `json:"user"`
	Assistant string `json:"assistant"`
}
type summaryState struct {
	Revision  int64       `json:"revision"`
	Meta      summaryMeta `json:"meta"`
	Text      string      `json:"text,omitempty"`
	Status    string      `json:"status"`
	Reason    string      `json:"reason,omitempty"`
	CreatedAt int64       `json:"created_at"`
}
type cacheState struct {
	Version           int             `json:"version"`
	Revision          int64           `json:"revision"`
	After             int64           `json:"after"`
	Head              []byte          `json:"head"`
	TurnDigests       []turnDigest    `json:"turn_digests"`
	Exchanges         []Exchange      `json:"exchanges"`
	Summaries         []summaryState  `json:"summaries"`
	WindowStart       int             `json:"window_start"`
	RatioObservations []float64       `json:"ratio_observations"`
	LastUsage         inference.Usage `json:"last_usage"`
}

func cacheName(id string) string { return "opaque-cache-" + id + ".bin" }
func cacheAAD(id string) []byte  { return []byte("plenarai-opaque-cache-v1|" + id) }

func (c *cacheState) valid() bool {
	if c.Version != cacheVersion || c.Revision < 0 || int64(len(c.TurnDigests)) != c.Revision || c.WindowStart < 0 {
		return false
	}
	if c.Revision == 0 {
		return len(c.Head) == 0 && c.After == 0 && len(c.Exchanges) == 0 && len(c.Summaries) == 0
	}
	if c.After != c.Revision*2-1 || !bytes.Equal(c.Head, c.TurnDigests[c.Revision-1].Terminal) {
		return false
	}
	last := int64(0)
	for _, e := range c.Exchanges {
		if e.Revision <= last || e.Revision > c.Revision {
			return false
		}
		last = e.Revision
	}
	for _, s := range c.Summaries {
		if s.Revision < 1 || s.Revision > c.Revision {
			return false
		}
	}
	return true
}
func loadCache(e *Entry) *cacheState {
	id := e.Create.ConversationID
	path, err := auth.SecretPath(cacheName(id), false)
	if err != nil {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxCacheBytes+1))
	f.Close()
	if err != nil || len(raw) > maxCacheBytes {
		deleteCache(id)
		return nil
	}
	plain, err := opaque.OpenRecord(e.Master, "cache", cacheAAD(id), raw)
	if err != nil {
		deleteCache(id)
		return nil
	}
	defer opaque.Zero(plain)
	var c cacheState
	if json.Unmarshal(plain, &c) != nil || !c.valid() {
		deleteCache(id)
		return nil
	}
	return &c
}

// saveCache is best effort: losing the cache only costs a full sync later.
func saveCache(e *Entry, c *cacheState) {
	id := e.Create.ConversationID
	plain, err := json.Marshal(c)
	if err != nil {
		return
	}
	defer opaque.Zero(plain)
	sealed, err := opaque.SealRecord(e.Master, "cache", cacheAAD(id), plain)
	if err != nil || len(sealed) > maxCacheBytes {
		return
	}
	path, err := auth.SecretPath(cacheName(id), true)
	if err != nil {
		return
	}
	if writeSecretFile(path, ".opaque-cache-*", sealed) != nil {
		deleteCache(id)
	}
}
func deleteCache(id string) {
	if path, err := auth.SecretPath(cacheName(id), false); err == nil {
		os.Remove(path)
	}
}

// writeSecretFile replaces path atomically with a restrictive temporary file.
func writeSecretFile(path, pattern string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), pattern)
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err = auth.SecureSecretFile(tmp.Name()); err != nil {
		tmp.Close()
		return err
	}
	if _, err = tmp.Write(data); err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
