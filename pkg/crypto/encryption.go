package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"filippo.io/age"
)

type Encryptor struct {
	identity  *age.X25519Identity
	recipient age.Recipient
}

// NewEncryptor creates a new encryptor from an age identity string
// If no key is provided, generates a new one (for development)
func NewEncryptor(identityKey string) (*Encryptor, error) {
	var identity *age.X25519Identity
	var err error

	if identityKey == "" {
		// Generate new identity for development
		identity, err = age.GenerateX25519Identity()
		if err != nil {
			return nil, fmt.Errorf("generating identity: %w", err)
		}
	} else {
		identity, err = age.ParseX25519Identity(identityKey)
		if err != nil {
			return nil, fmt.Errorf("parsing identity: %w", err)
		}
	}

	return &Encryptor{
		identity:  identity,
		recipient: identity.Recipient(),
	}, nil
}

// GenerateKey generates a new age identity key pair
func GenerateKey() (identityKey string, publicKey string, err error) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return "", "", err
	}
	return identity.String(), identity.Recipient().String(), nil
}

// Encrypt encrypts plaintext using age
func (e *Encryptor) Encrypt(plaintext []byte) ([]byte, error) {
	var buf bytes.Buffer

	w, err := age.Encrypt(&buf, e.recipient)
	if err != nil {
		return nil, fmt.Errorf("creating encryptor: %w", err)
	}

	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("writing encrypted data: %w", err)
	}

	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("closing encryptor: %w", err)
	}

	return buf.Bytes(), nil
}

// Decrypt decrypts ciphertext using age
func (e *Encryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(ciphertext), e.identity)
	if err != nil {
		return nil, fmt.Errorf("creating decryptor: %w", err)
	}

	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading decrypted data: %w", err)
	}

	return plaintext, nil
}

// EncryptString encrypts a string and returns base64-encoded ciphertext
func (e *Encryptor) EncryptString(plaintext string) (string, error) {
	encrypted, err := e.Encrypt([]byte(plaintext))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// DecryptString decrypts base64-encoded ciphertext and returns plaintext string
func (e *Encryptor) DecryptString(ciphertext string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("decoding base64: %w", err)
	}

	decrypted, err := e.Decrypt(decoded)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}

// PublicKey returns the public key for this encryptor
func (e *Encryptor) PublicKey() string {
	return e.recipient.String()
}

// GenerateRandomBytes generates cryptographically secure random bytes
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

// GenerateToken generates a URL-safe random token
func GenerateToken(length int) (string, error) {
	b, err := GenerateRandomBytes(length)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
