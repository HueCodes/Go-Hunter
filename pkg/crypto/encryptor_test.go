package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEncryptor_GenerateNewKey(t *testing.T) {
	// Test creating encryptor with empty key (generates new)
	enc, err := NewEncryptor("")
	require.NoError(t, err)
	assert.NotNil(t, enc)
	assert.NotNil(t, enc.identity)
	assert.NotNil(t, enc.recipient)
}

func TestNewEncryptor_WithProvidedKey(t *testing.T) {
	// Generate a key first
	key, err := GenerateKey()
	require.NoError(t, err)

	// Create encryptor with that key
	enc, err := NewEncryptor(key)
	require.NoError(t, err)
	assert.NotNil(t, enc)
}

func TestNewEncryptor_InvalidKey(t *testing.T) {
	// Test with invalid key format
	_, err := NewEncryptor("invalid-key-format")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parsing identity")
}

func TestGenerateKey(t *testing.T) {
	key1, err := GenerateKey()
	require.NoError(t, err)
	assert.NotEmpty(t, key1)

	key2, err := GenerateKey()
	require.NoError(t, err)
	assert.NotEmpty(t, key2)

	// Keys should be unique
	assert.NotEqual(t, key1, key2)
}

func TestEncrypt_Decrypt(t *testing.T) {
	enc, err := NewEncryptor("")
	require.NoError(t, err)

	plaintext := []byte("sensitive data that needs encryption")

	// Encrypt
	ciphertext, err := enc.Encrypt(plaintext)
	require.NoError(t, err)
	assert.NotEmpty(t, ciphertext)

	// Ciphertext should be different from plaintext
	assert.NotEqual(t, plaintext, ciphertext)

	// Decrypt
	decrypted, err := enc.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestEncrypt_DifferentOutputEachTime(t *testing.T) {
	// Encryption should produce different ciphertext each time (nonce/IV)
	enc, err := NewEncryptor("")
	require.NoError(t, err)

	plaintext := []byte("same data")

	ciphertext1, err := enc.Encrypt(plaintext)
	require.NoError(t, err)

	ciphertext2, err := enc.Encrypt(plaintext)
	require.NoError(t, err)

	// Ciphertexts should be different due to randomness
	assert.NotEqual(t, ciphertext1, ciphertext2)

	// But both should decrypt to same plaintext
	decrypted1, err := enc.Decrypt(ciphertext1)
	require.NoError(t, err)

	decrypted2, err := enc.Decrypt(ciphertext2)
	require.NoError(t, err)

	assert.Equal(t, plaintext, decrypted1)
	assert.Equal(t, plaintext, decrypted2)
}

func TestDecrypt_InvalidCiphertext(t *testing.T) {
	enc, err := NewEncryptor("")
	require.NoError(t, err)

	// Try to decrypt garbage data
	_, err = enc.Decrypt([]byte("not valid ciphertext"))
	assert.Error(t, err)
}

func TestDecrypt_WrongKey(t *testing.T) {
	// Encrypt with one key
	enc1, err := NewEncryptor("")
	require.NoError(t, err)

	plaintext := []byte("secret message")
	ciphertext, err := enc1.Encrypt(plaintext)
	require.NoError(t, err)

	// Try to decrypt with different key
	enc2, err := NewEncryptor("")
	require.NoError(t, err)

	_, err = enc2.Decrypt(ciphertext)
	assert.Error(t, err, "Should not be able to decrypt with wrong key")
}

func TestEncryptString_DecryptString(t *testing.T) {
	enc, err := NewEncryptor("")
	require.NoError(t, err)

	plaintext := "AWS access key: AKIAIOSFODNN7EXAMPLE"

	// Encrypt string
	ciphertext, err := enc.EncryptString(plaintext)
	require.NoError(t, err)
	assert.NotEmpty(t, ciphertext)

	// Ciphertext should be base64-encoded (no special chars)
	assert.NotContains(t, ciphertext, " ")

	// Decrypt string
	decrypted, err := enc.DecryptString(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestDecryptString_InvalidBase64(t *testing.T) {
	enc, err := NewEncryptor("")
	require.NoError(t, err)

	// Invalid base64
	_, err = enc.DecryptString("not valid base64!!!")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decoding base64")
}

func TestDecryptString_ValidBase64ButInvalidCiphertext(t *testing.T) {
	enc, err := NewEncryptor("")
	require.NoError(t, err)

	// Valid base64 but not valid ciphertext
	_, err = enc.DecryptString("SGVsbG8gV29ybGQ=") // "Hello World" in base64
	assert.Error(t, err)
}

func TestPublicKey(t *testing.T) {
	enc, err := NewEncryptor("")
	require.NoError(t, err)

	pubKey := enc.PublicKey()
	assert.NotEmpty(t, pubKey)
	assert.Contains(t, pubKey, "age1") // age public keys start with "age1"
}

func TestEncrypt_EmptyData(t *testing.T) {
	enc, err := NewEncryptor("")
	require.NoError(t, err)

	// Encrypt empty data
	ciphertext, err := enc.Encrypt([]byte{})
	require.NoError(t, err)
	assert.NotEmpty(t, ciphertext) // Ciphertext has overhead even for empty data

	// Decrypt should return empty
	plaintext, err := enc.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Empty(t, plaintext)
}

func TestEncrypt_LargeData(t *testing.T) {
	enc, err := NewEncryptor("")
	require.NoError(t, err)

	// 1MB of data
	largeData := make([]byte, 1024*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	ciphertext, err := enc.Encrypt(largeData)
	require.NoError(t, err)

	decrypted, err := enc.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, largeData, decrypted)
}

func TestGenerateRandomBytes(t *testing.T) {
	// Test different sizes
	sizes := []int{16, 32, 64, 128}

	for _, size := range sizes {
		t.Run("size_"+string(rune(size)), func(t *testing.T) {
			bytes, err := GenerateRandomBytes(size)
			require.NoError(t, err)
			assert.Len(t, bytes, size)

			// Generate again and ensure different
			bytes2, err := GenerateRandomBytes(size)
			require.NoError(t, err)
			assert.NotEqual(t, bytes, bytes2, "Random bytes should be different")
		})
	}
}

func TestGenerateRandomBytes_Zero(t *testing.T) {
	bytes, err := GenerateRandomBytes(0)
	require.NoError(t, err)
	assert.Empty(t, bytes)
}

func TestGenerateRandomString(t *testing.T) {
	str1, err := GenerateRandomString(32)
	require.NoError(t, err)
	assert.Len(t, str1, 32)

	str2, err := GenerateRandomString(32)
	require.NoError(t, err)
	assert.Len(t, str2, 32)

	// Should be different
	assert.NotEqual(t, str1, str2)
}

func TestGenerateRandomString_DifferentSizes(t *testing.T) {
	sizes := []int{8, 16, 32, 64}

	for _, size := range sizes {
		str, err := GenerateRandomString(size)
		require.NoError(t, err)
		assert.Len(t, str, size)
	}
}

func TestEncryptor_KeyReuse(t *testing.T) {
	// Generate a key
	key, err := GenerateKey()
	require.NoError(t, err)

	// Create two encryptors with same key
	enc1, err := NewEncryptor(key)
	require.NoError(t, err)

	enc2, err := NewEncryptor(key)
	require.NoError(t, err)

	// Encrypt with first encryptor
	plaintext := []byte("reusable key test")
	ciphertext, err := enc1.Encrypt(plaintext)
	require.NoError(t, err)

	// Decrypt with second encryptor (same key)
	decrypted, err := enc2.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestEncryptor_RealWorldScenario(t *testing.T) {
	// Simulate encrypting AWS credentials
	enc, err := NewEncryptor("")
	require.NoError(t, err)

	credentials := map[string]string{
		"access_key": "AKIAIOSFODNN7EXAMPLE",
		"secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"region":     "us-east-1",
	}

	// Encrypt each credential
	encrypted := make(map[string]string)
	for key, value := range credentials {
		ciphertext, err := enc.EncryptString(value)
		require.NoError(t, err)
		encrypted[key] = ciphertext
	}

	// Decrypt and verify
	for key, expected := range credentials {
		decrypted, err := enc.DecryptString(encrypted[key])
		require.NoError(t, err)
		assert.Equal(t, expected, decrypted)
	}
}
