package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
)

// LoadOrGenerateKey loads the node's private key from disk, or generates a new one.
func LoadOrGenerateKey(configDir string) (*ecdh.PrivateKey, error) {
	keyPath := filepath.Join(configDir, "node.key")

	data, err := os.ReadFile(keyPath)
	if err == nil && len(data) > 0 {
		return ecdh.X25519().NewPrivateKey(data)
	}

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(configDir, 0700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, priv.Bytes(), 0600); err != nil {
		return nil, err
	}

	return priv, nil
}

// DecryptQuestion decrypts the AES key using ECDH, then decrypts the question.
// Returns plaintext. Caller MUST call ZeroBytes on the returned slice after use.
func DecryptQuestion(nodePrivate *ecdh.PrivateKey, serverPubBytes, encryptedKey, encryptedQuestion []byte) ([]byte, error) {
	serverPub, err := ecdh.X25519().NewPublicKey(serverPubBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid server public key: %w", err)
	}

	aesKey, err := decryptKeyFromServer(nodePrivate, serverPub, encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt AES key: %w", err)
	}
	defer ZeroBytes(aesKey)

	plaintext, err := DecryptAESGCM(aesKey, encryptedQuestion)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt question: %w", err)
	}

	return plaintext, nil
}

func decryptKeyFromServer(nodePrivate *ecdh.PrivateKey, serverPub *ecdh.PublicKey, encryptedKey []byte) ([]byte, error) {
	shared, err := nodePrivate.ECDH(serverPub)
	if err != nil {
		return nil, err
	}
	defer ZeroBytes(shared)
	return DecryptAESGCM(shared, encryptedKey)
}

// DecryptAESGCM decrypts AES-256-GCM ciphertext (nonce prepended).
func DecryptAESGCM(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ct, nil)
}

// ZeroBytes overwrites a byte slice with zeros for zero-trace security.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
