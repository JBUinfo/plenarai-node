package opaquechat

import (
	"bytes"
	"crypto/ed25519"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/plenarai/cli/internal/auth"
	"github.com/plenarai/cli/internal/opaque"
)

const vaultName = "opaque-vault.json"

type Entry struct {
	Master            []byte          `json:"master"`
	SigningSeed       []byte          `json:"signing_seed"`
	Create            opaque.Create   `json:"create"`
	Revision          int64           `json:"revision"`
	Head              []byte          `json:"head"`
	Pending           *opaque.Request `json:"pending,omitempty"`
	Settings          []byte          `json:"settings,omitempty"`
	CreationConfirmed bool            `json:"creation_confirmed,omitempty"`
	// SummaryMode: "" asks before a paid summary turn, "auto" or "off".
	SummaryMode string `json:"summary_mode,omitempty"`
}
type Vault struct {
	Version int               `json:"version"`
	Entries map[string]*Entry `json:"entries"`
	path    string
	lock    *os.File
}

func OpenVault() (*Vault, error) {
	path, err := auth.SecretPath(vaultName, true)
	if err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(path+".lock", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, fmt.Errorf("another encrypted chat owns the vault lock; if a crashed process left it, remove %s after checking that no chat is running", path+".lock")
	}
	v := &Vault{Version: 2, Entries: map[string]*Entry{}, path: path, lock: lock}
	if err = auth.SecureSecretFile(path + ".lock"); err != nil {
		v.Close()
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return v, nil
	}
	if err != nil {
		v.Close()
		return nil, err
	}
	defer opaque.Zero(raw)
	if len(raw) > 32<<20 || json.Unmarshal(raw, v) != nil || v.Version != 2 || v.Entries == nil {
		v.Close()
		return nil, fmt.Errorf("invalid key vault; restore its encrypted backup")
	}
	if err = validateVault(v); err != nil {
		v.Close()
		return nil, err
	}
	return v, nil
}
func validateVault(v *Vault) error {
	for id, e := range v.Entries {
		if e == nil || !opaque.ValidID(id) || id != e.Create.ConversationID || len(e.Master) != 32 || len(e.SigningSeed) != 32 || e.Create.Verify() != nil || e.Revision < 0 || len(e.Head) != 0 && len(e.Head) != 32 {
			return fmt.Errorf("invalid conversation key backup")
		}
		private := ed25519.NewKeyFromSeed(e.SigningSeed)
		public := private.Public().(ed25519.PublicKey)
		opaque.Zero(private)
		if !bytes.Equal(public, e.Create.ClientSigningKey) || len(e.Settings) > 32768 || e.SummaryMode != "" && e.SummaryMode != "auto" && e.SummaryMode != "off" {
			return fmt.Errorf("invalid conversation identity in key backup")
		}
		if e.Pending != nil && (e.Pending.Verify() != nil || e.Pending.Header.ConversationID != id || !bytes.Equal(e.Pending.Header.ClientSigningKey, e.Create.ClientSigningKey)) {
			return fmt.Errorf("invalid pending encrypted turn")
		}
	}
	return nil
}
func (v *Vault) Close() {
	for _, e := range v.Entries {
		if e != nil {
			opaque.Zero(e.Master)
			opaque.Zero(e.SigningSeed)
		}
	}
	if v.lock != nil {
		v.lock.Close()
		os.Remove(v.path + ".lock")
		v.lock = nil
	}
}
func (v *Vault) Save() error {
	if err := validateVault(v); err != nil {
		return err
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	defer opaque.Zero(raw)
	if len(raw) > 32<<20 {
		return fmt.Errorf("local key vault exceeds its 32 MiB storage limit")
	}
	if _, err = auth.SecretPath(vaultName, true); err != nil {
		return err
	}
	return writeSecretFile(v.path, ".opaque-vault-*", raw)
}

type backup struct {
	Version    int    `json:"version"`
	Iterations int    `json:"iterations"`
	Salt       []byte `json:"salt"`
	Ciphertext []byte `json:"ciphertext"`
}

const backupIterations = 600000

func backupAAD(b backup) []byte {
	return []byte(fmt.Sprintf("plenarai-opaque-vault-export:%d:%d:%x", b.Version, b.Iterations, b.Salt))
}
func (v *Vault) Export(password []byte) ([]byte, error) {
	if len(password) < 12 {
		return nil, fmt.Errorf("use an export password of at least 12 characters")
	}
	if err := validateVault(v); err != nil {
		return nil, err
	}
	salt, err := opaque.RandomKey()
	if err != nil {
		return nil, err
	}
	b := backup{Version: 2, Iterations: backupIterations, Salt: salt[:16]}
	key, err := pbkdf2.Key(sha256.New, string(password), b.Salt, b.Iterations, 32)
	if err != nil {
		return nil, err
	}
	defer opaque.Zero(key)
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	defer opaque.Zero(raw)
	b.Ciphertext, err = opaque.SealRecord(key, "vault-export", backupAAD(b), raw)
	if err != nil {
		return nil, err
	}
	return json.Marshal(b)
}
func (v *Vault) Import(data, password []byte) error {
	if len(data) > 48<<20 {
		return fmt.Errorf("export is too large")
	}
	var b backup
	if json.Unmarshal(data, &b) != nil || b.Version != 2 || b.Iterations != backupIterations || len(b.Salt) != 16 {
		return fmt.Errorf("invalid encrypted key export")
	}
	key, err := pbkdf2.Key(sha256.New, string(password), b.Salt, b.Iterations, 32)
	if err != nil {
		return err
	}
	defer opaque.Zero(key)
	raw, err := opaque.OpenRecord(key, "vault-export", backupAAD(b), b.Ciphertext)
	if err != nil {
		return fmt.Errorf("wrong password or damaged key export")
	}
	defer opaque.Zero(raw)
	var incoming Vault
	if json.Unmarshal(raw, &incoming) != nil || incoming.Version != 2 || incoming.Entries == nil {
		return fmt.Errorf("invalid conversation backup")
	}
	defer func() {
		for _, e := range incoming.Entries {
			if e != nil {
				opaque.Zero(e.Master)
				opaque.Zero(e.SigningSeed)
			}
		}
	}()
	if err = validateVault(&incoming); err != nil {
		return err
	}
	for id, e := range incoming.Entries {
		old := v.Entries[id]
		if old != nil && (!bytes.Equal(old.Master, e.Master) || !bytes.Equal(old.SigningSeed, e.SigningSeed) || !bytes.Equal(old.Create.Signature, e.Create.Signature)) {
			return fmt.Errorf("backup conflicts with an existing conversation key")
		}
		if old != nil && old.Pending != nil {
			return fmt.Errorf("reconcile pending turns before importing")
		}
	}
	for id, e := range incoming.Entries {
		old := v.Entries[id]
		if old == nil || e.Revision > old.Revision {
			copy := *e
			copy.Master = append([]byte{}, e.Master...)
			copy.SigningSeed = append([]byte{}, e.SigningSeed...)
			v.Entries[id] = &copy
		}
	}
	return v.Save()
}
func WriteExport(path string, data []byte) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if err = auth.SecureSecretFile(path); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(path)
	}
	return err
}
func ReadExport(path string) ([]byte, error) {
	if err := auth.SecureSecretFile(path); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 48<<20+1))
	if len(data) > 48<<20 {
		return nil, fmt.Errorf("export too large")
	}
	return data, err
}
