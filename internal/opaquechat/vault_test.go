package opaquechat

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"github.com/plenarai/cli/internal/opaque"
	"os"
	"path/filepath"
	"testing"
)

func testEntry(t *testing.T) *Entry {
	t.Helper()
	master, _ := opaque.RandomKey()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	node, _ := ecdh.X25519().GenerateKey(rand.Reader)
	nodePub, _, _ := ed25519.GenerateKey(rand.Reader)
	c := opaque.Create{Version: 2, ConversationID: "11111111-1111-4111-8111-111111111111", OwnerID: "33333333-3333-4333-8333-333333333333", ProviderID: "44444444-4444-4444-8444-444444444444", ModelRevision: "55555555-5555-4555-8555-555555555555", ClientSigningKey: pub, ProviderEncryptionKey: node.PublicKey().Bytes(), ProviderSigningKey: nodePub}
	var err error
	c.Ciphertext, err = opaque.SealRecord(master, "archive", c.AAD(), []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	c.Signature = ed25519.Sign(priv, c.Canonical())
	return &Entry{Master: master, SigningSeed: priv.Seed(), Create: c}
}
func TestVaultBackupIntegrityAndMissingKeys(t *testing.T) {
	t.Setenv("PLENARAI_CONFIG_DIR", filepath.Join(t.TempDir(), "secrets"))
	v, err := OpenVault()
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	entry := testEntry(t)
	id := entry.Create.ConversationID
	v.Entries[id] = entry
	if err = v.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err = OpenVault(); err == nil {
		t.Fatal("concurrent vault writer accepted")
	}
	password := []byte("a long test-only password")
	data, err := v.Export(password)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, entry.Master) || bytes.Contains(data, entry.SigningSeed) {
		t.Fatal("raw keys in export")
	}
	restored := &Vault{Version: 2, Entries: map[string]*Entry{}, path: filepath.Join(t.TempDir(), vaultName)}
	// Use a separate guarded directory to test persisted import.
	t.Setenv("PLENARAI_CONFIG_DIR", filepath.Dir(restored.path))
	if err = restored.Import(data, []byte("wrong password")); err == nil {
		t.Fatal("wrong password accepted")
	}
	if err = restored.Import(data, password); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored.Entries[id].Master, entry.Master) {
		t.Fatal("key changed on restore")
	}
	restored.Entries[id].Master[0] ^= 1
	if err = restored.Import(data, password); err == nil {
		t.Fatal("conflicting existing key overwritten")
	}
	delete(restored.Entries, id)
	if _, err = Resume(restored, entry.Create.OwnerID, id); err == nil {
		t.Fatal("missing key silently regenerated")
	}
	damaged := append([]byte{}, data...)
	damaged[len(damaged)/2] ^= 1
	if err = restored.Import(damaged, password); err == nil {
		t.Fatal("damaged export accepted")
	}
}
func TestVaultRejectsSymlinksAndCorruption(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PLENARAI_CONFIG_DIR", dir)
	target := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(target, []byte("do not replace"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, vaultName)); err != nil {
		t.Skip(err)
	}
	if _, err := OpenVault(); err == nil {
		t.Fatal("symlink vault accepted")
	}
	if got, _ := os.ReadFile(target); string(got) != "do not replace" {
		t.Fatal("symlink target modified")
	}
}
