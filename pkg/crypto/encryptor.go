package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"filippo.io/age"
)

// Encryptor handles encryption and decryption of sensitive data using age
type Encryptor struct {
	identity  *age.X25519Identity
	recipient *age.X25519Recipient
}

// NewEncryptor creates a new Encryptor from a base64-encoded private key
// If key is empty, a new key is generated
func NewEncryptor(key string) (*Encryptor, error) {
	var identity *age.X25519Identity
	var err error

	if key == "" {
		// Generate a new identity
		identity, err = age.GenerateX25519Identity()
		if err != nil {
			return nil, fmt.Errorf("generating identity: %w", err)
		}
	} else {
		// Parse the provided key
		identity, err = age.ParseX25519Identity(key)
		if err != nil {
			return nil, fmt.Errorf("parsing identity: %w", err)
		}
	}

	return &Encryptor{
		identity:  identity,
		recipient: identity.Recipient(),
	}, nil
}

// GenerateKey generates a new encryption key and returns it
func GenerateKey() (string, error) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return "", fmt.Errorf("generating identity: %w", err)
	}
	return identity.String(), nil
}

// Encrypt encrypts plaintext data and returns the ciphertext
func (e *Encryptor) Encrypt(plaintext []byte) ([]byte, error) {
	var buf bytes.Buffer

	w, err := age.Encrypt(&buf, e.recipient)
	if err != nil {
		return nil, fmt.Errorf("creating encryptor: %w", err)
	}

	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("writing plaintext: %w", err)
	}

	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("closing encryptor: %w", err)
	}

	return buf.Bytes(), nil
}

// Decrypt decrypts ciphertext and returns the plaintext
func (e *Encryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(ciphertext), e.identity)
	if err != nil {
		return nil, fmt.Errorf("creating decryptor: %w", err)
	}

	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading plaintext: %w", err)
	}

	return plaintext, nil
}

// EncryptString encrypts a string and returns base64-encoded ciphertext
func (e *Encryptor) EncryptString(plaintext string) (string, error) {
	ciphertext, err := e.Encrypt([]byte(plaintext))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptString decrypts base64-encoded ciphertext and returns the string
func (e *Encryptor) DecryptString(ciphertext string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("decoding base64: %w", err)
	}

	plaintext, err := e.Decrypt(decoded)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// PublicKey returns the public key (recipient) as a string
func (e *Encryptor) PublicKey() string {
	return e.recipient.String()
}

// GenerateRandomBytes generates cryptographically secure random bytes
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, fmt.Errorf("generating random bytes: %w", err)
	}
	return b, nil
}

// GenerateRandomString generates a cryptographically secure random string
func GenerateRandomString(n int) (string, error) {
	b, err := GenerateRandomBytes(n)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b)[:n], nil
}
