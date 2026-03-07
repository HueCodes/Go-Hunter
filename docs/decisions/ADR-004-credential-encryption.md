# ADR-004: age Encryption for Cloud Credential Storage

## Status

Accepted

## Context

Go-Hunter stores cloud provider credentials to perform automated asset discovery across:
- AWS (Access Key ID + Secret Access Key)
- GCP (Service Account JSON)
- Azure (Client ID + Client Secret + Tenant ID)
- DigitalOcean (API Token)
- Cloudflare (API Token or API Key + Email)

These credentials provide significant access to customer infrastructure and must be protected at rest. A breach of the database should not expose plaintext credentials.

### Security Requirements

1. **Encryption at Rest**: Credentials must be encrypted in the database
2. **Key Management**: Encryption key must be separate from the database
3. **Worker Access**: Background workers need to decrypt credentials for API calls
4. **Rotation Support**: Ability to rotate encryption keys without re-encrypting all data
5. **Audit Trail**: Decryption events should be loggable
6. **Go-Native**: Prefer pure Go implementation for deployment simplicity

### Alternatives Considered

1. **AES-256-GCM with crypto/aes**
   - Pros: Standard library, well-understood
   - Cons: Manual nonce management, key derivation boilerplate

2. **NaCl/Box (golang.org/x/crypto/nacl)**
   - Pros: High-level API, authenticated encryption
   - Cons: Key format not human-friendly, no streaming

3. **HashiCorp Vault**
   - Pros: Enterprise-grade, audit logging, dynamic secrets
   - Cons: Operational complexity, separate service to manage

4. **AWS KMS / GCP KMS / Azure Key Vault**
   - Pros: Managed service, HSM-backed
   - Cons: Cloud vendor lock-in, network dependency, cost

5. **age (filippo.io/age)**
   - Pros: Modern design, simple API, Go-native, passphrase or key-based
   - Cons: Newer (less battle-tested than GPG)

## Decision

We chose **age** (filippo.io/age) for credential encryption.

### Implementation Details

**Encryptor Package** (`pkg/crypto/encryptor.go`):
```go
package crypto

import (
    "bytes"
    "encoding/base64"
    "filippo.io/age"
)

// Encryptor handles encryption and decryption using age
type Encryptor struct {
    identity  *age.X25519Identity
    recipient *age.X25519Recipient
}

// NewEncryptor creates an encryptor from an age private key
// If key is empty, generates a new identity (development only)
func NewEncryptor(key string) (*Encryptor, error) {
    var identity *age.X25519Identity
    var err error

    if key == "" {
        identity, err = age.GenerateX25519Identity()
        if err != nil {
            return nil, fmt.Errorf("generating identity: %w", err)
        }
    } else {
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

// Encrypt encrypts plaintext using age
func (e *Encryptor) Encrypt(plaintext []byte) ([]byte, error) {
    var buf bytes.Buffer
    w, err := age.Encrypt(&buf, e.recipient)
    if err != nil {
        return nil, err
    }
    if _, err := w.Write(plaintext); err != nil {
        return nil, err
    }
    if err := w.Close(); err != nil {
        return nil, err
    }
    return buf.Bytes(), nil
}

// Decrypt decrypts ciphertext using age
func (e *Encryptor) Decrypt(ciphertext []byte) ([]byte, error) {
    r, err := age.Decrypt(bytes.NewReader(ciphertext), e.identity)
    if err != nil {
        return nil, err
    }
    return io.ReadAll(r)
}

// String convenience methods for API use
func (e *Encryptor) EncryptString(plaintext string) (string, error) {
    ciphertext, err := e.Encrypt([]byte(plaintext))
    if err != nil {
        return "", err
    }
    return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (e *Encryptor) DecryptString(ciphertext string) (string, error) {
    decoded, err := base64.StdEncoding.DecodeString(ciphertext)
    if err != nil {
        return "", err
    }
    plaintext, err := e.Decrypt(decoded)
    if err != nil {
        return "", err
    }
    return string(plaintext), nil
}
```

**Key Generation** (`pkg/crypto/encryptor.go`):
```go
// GenerateKey generates a new age private key
func GenerateKey() (string, error) {
    identity, err := age.GenerateX25519Identity()
    if err != nil {
        return "", err
    }
    return identity.String(), nil
}
```

**Database Storage** (`internal/database/models/cloud_credential.go`):
```go
type CloudCredential struct {
    Base
    OrganizationID uuid.UUID     `gorm:"type:uuid;index;not null"`
    Name           string        `gorm:"not null"`
    Provider       CloudProvider `gorm:"not null"`

    // Encrypted credentials stored as binary
    EncryptedData []byte `gorm:"type:bytea;not null" json:"-"`

    // Non-sensitive metadata
    Region   string `json:"region,omitempty"`
    IsActive bool   `gorm:"default:true"`
    LastUsed int64  `json:"last_used,omitempty"`
}
```

**Credential Creation** (`internal/assets/service.go`):
```go
func (s *Service) CreateCredential(ctx context.Context, orgID uuid.UUID,
    name string, provider models.CloudProvider, credData interface{}) (*models.CloudCredential, error) {

    // Serialize credential to JSON
    jsonData, err := json.Marshal(credData)
    if err != nil {
        return nil, fmt.Errorf("serializing credentials: %w", err)
    }

    // Encrypt with age
    encrypted, err := s.encryptor.Encrypt(jsonData)
    if err != nil {
        return nil, fmt.Errorf("encrypting credentials: %w", err)
    }

    cred := &models.CloudCredential{
        OrganizationID: orgID,
        Name:           name,
        Provider:       provider,
        EncryptedData:  encrypted,  // Raw bytes stored in PostgreSQL bytea
        IsActive:       true,
    }

    return cred, s.db.Create(cred).Error
}
```

**Credential Decryption in Worker** (`internal/assets/service.go`):
```go
func (s *Service) getProvider(cred *models.CloudCredential) (Provider, error) {
    // Decrypt credential
    decrypted, err := s.encryptor.Decrypt(cred.EncryptedData)
    if err != nil {
        return nil, fmt.Errorf("decrypting credentials: %w", err)
    }

    switch cred.Provider {
    case models.ProviderAWS:
        var awsCred AWSCredential
        if err := json.Unmarshal(decrypted, &awsCred); err != nil {
            return nil, err
        }
        return aws.New(awsCred, s.cfg, s.logger), nil
    // ... other providers
    }
}
```

**Configuration** (`.env.example`):
```bash
# age private key for credential encryption
# Generate with: go run -mod=mod filippo.io/age/cmd/age-keygen
# Example: AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ
ENCRYPTION_KEY=
```

**Server Initialization** (`cmd/server/main.go`):
```go
encryptor, err := crypto.NewEncryptor(cfg.Encryption.Key)
if err != nil {
    logger.Error("failed to create encryptor", "error", err)
    os.Exit(1)
}
if cfg.Encryption.Key == "" {
    logger.Warn("ENCRYPTION_KEY not set, using generated key - credentials will be lost on restart")
}
```

## Consequences

### Positive

1. **Modern Cryptography**: age uses X25519 for key exchange and ChaCha20-Poly1305 for symmetric encryption. These are modern, well-analyzed primitives.

2. **Simple Key Management**: A single environment variable holds the private key:
   ```bash
   export ENCRYPTION_KEY="AGE-SECRET-KEY-1..."
   ```

3. **Go-Native Implementation**: No CGO dependencies. The application compiles to a single static binary.

4. **Human-Readable Keys**: age keys are easy to copy, backup, and rotate:
   ```
   Public:  age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
   Private: AGE-SECRET-KEY-1QTMKL9FXLXHM8VQ6H7ZQXJ7DRQLWC2GJ6YLKHZ7ZXQVS4V4YMVQQ7VVQVQ
   ```

5. **Authenticated Encryption**: age provides AEAD, preventing both tampering and information leakage.

6. **Streaming Support**: Large credentials (like GCP service account JSON) can be encrypted without loading entirely into memory.

7. **Development Mode**: Auto-generated keys for local development with clear warnings:
   ```
   WARN: ENCRYPTION_KEY not set, using generated key - credentials will be lost on restart
   ```

### Negative

1. **Single Key for All Credentials**: All credentials use the same encryption key. A key compromise exposes everything.

   **Mitigation**:
   - Key rotation procedure documented
   - Consider per-organization keys for enterprise tier
   - Hardware security module integration for high-security deployments

2. **No Built-in Key Rotation**: Changing the key requires re-encrypting all credentials.

   **Mitigation**:
   - Build migration script for key rotation
   - Consider multiple-recipient encryption for zero-downtime rotation

3. **Newer Library**: age is younger than GPG/OpenSSL. Less security review history.

   **Mitigation**:
   - age is authored by Filippo Valsorda (Go security team lead)
   - Formal audit completed
   - Simple design limits attack surface

4. **No Hardware Security Module Support**: Keys are in application memory.

   **Mitigation**:
   - Use environment variable injection at runtime (not config files)
   - Consider Kubernetes secrets or HashiCorp Vault for key storage
   - Document deployment hardening

### Key Rotation Procedure

```bash
# 1. Generate new key
NEW_KEY=$(age-keygen 2>&1 | grep "AGE-SECRET-KEY")

# 2. Decrypt all credentials with old key, re-encrypt with new
# (Run migration script - not yet implemented)

# 3. Update ENCRYPTION_KEY environment variable
export ENCRYPTION_KEY="$NEW_KEY"

# 4. Restart server and workers
```

### Security Considerations

- **Never log credentials**: EncryptedData has `json:"-"` tag
- **Memory safety**: Clear plaintext from memory after use (Go limitation)
- **Key storage**: Use secret management (Vault, Kubernetes secrets, AWS Secrets Manager)
- **Access control**: Separate database access from encryption key access

## References

- [age Specification](https://age-encryption.org/v1)
- [age Go Implementation](https://github.com/FiloSottile/age)
- [age Security Audit](https://github.com/FiloSottile/age/blob/main/SECURITY.md)
- [Filippo Valsorda - age Design](https://words.filippo.io/dispatches/age-design/)
