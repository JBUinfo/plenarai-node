package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
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
	plaintext, aesKey, err := DecryptQuestionAndKey(nodePrivate, serverPubBytes, encryptedKey, encryptedQuestion)
	if aesKey != nil {
		ZeroBytes(aesKey)
	}
	return plaintext, err
}

// DecryptQuestionAndKey returns both the plaintext and its per-job key. The
// caller MUST zero both returned slices after use.
func DecryptQuestionAndKey(nodePrivate *ecdh.PrivateKey, serverPubBytes, encryptedKey, encryptedQuestion []byte) ([]byte, []byte, error) {
	serverPub, err := ecdh.X25519().NewPublicKey(serverPubBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid server public key: %w", err)
	}

	aesKey, err := DecryptKeyFromServer(nodePrivate, serverPub, encryptedKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt AES key: %w", err)
	}

	plaintext, err := DecryptAESGCM(aesKey, encryptedQuestion)
	if err != nil {
		ZeroBytes(aesKey)
		return nil, nil, fmt.Errorf("failed to decrypt question: %w", err)
	}

	return plaintext, aesKey, nil
}

func DecryptKeyFromServer(nodePrivate *ecdh.PrivateKey, serverPub *ecdh.PublicKey, encryptedKey []byte) ([]byte, error) {
	shared, err := nodePrivate.ECDH(serverPub)
	if err != nil {
		return nil, err
	}
	defer ZeroBytes(shared)
	wrappingKey, err := hkdf.Key(sha256.New, shared, nil, "plenarai-secure-work:key-wrap:v1", 32)
	if err != nil {
		return nil, err
	}
	defer ZeroBytes(wrappingKey)
	return DecryptAESGCM(wrappingKey, encryptedKey)
}

// DecryptAESGCM decrypts AES-256-GCM ciphertext (nonce prepended).
func DecryptAESGCM(key, ciphertext []byte) ([]byte, error) {
	return DecryptAESGCMAAD(key, ciphertext, nil)
}

// EncryptAESGCMAAD encrypts plaintext with AES-256-GCM and authenticates aad.
func EncryptAESGCMAAD(key, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

// DecryptAESGCMAAD decrypts a nonce-prefixed AES-256-GCM ciphertext and
// authenticates aad.
func DecryptAESGCMAAD(key, ciphertext, aad []byte) ([]byte, error) {
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
	return gcm.Open(nil, nonce, ct, aad)
}

// ZeroBytes overwrites a byte slice with zeros for zero-trace security.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
