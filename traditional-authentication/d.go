package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"
)

// User credentials storage
var userDB = map[string]struct {
	oprfSecret []byte
	envelope   []byte
}{}

// Animate text with typewriter effect
func animate(msg string, speed time.Duration) {
	for _, c := range msg {
		fmt.Printf("%c", c)
		time.Sleep(speed * time.Millisecond)
	}
	fmt.Println()
}

// Visualize byte arrays with ellipsis
func peek(data []byte) string {
	if len(data) > 8 {
		return hex.EncodeToString(data[:4]) + "..." + hex.EncodeToString(data[len(data)-4:])
	}
	return hex.EncodeToString(data)
}

/* Cryptography Functions */
func generateOPRFSecret() []byte {
	secret := make([]byte, 32)
	rand.Read(secret)
	animate(fmt.Sprintf("🔐 Generated random OPRF secret: %s", peek(secret)), 20)
	return secret
}

func computeOPRF(password, secret []byte) []byte {
	animate("\n📝 Client computes OPRF:", 10)
	animate(fmt.Sprintf("   Password: '%s'", password), 5)
	animate(fmt.Sprintf("   Secret: %s", peek(secret)), 5)

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(password))
	result := mac.Sum(nil)

	animate(fmt.Sprintf("   HMAC-SHA256 output: %s", peek(result)), 15)
	return result
}

func deriveEncKey(oprfOutput []byte) []byte {
	animate("\n🔑 Key Derivation:", 10)
	animate(fmt.Sprintf("   OPRF output: %s", peek(oprfOutput)), 5)

	hkdf := hkdf.New(sha256.New, oprfOutput, nil, []byte("OPAQUE-ENCRYPTION-KEY"))
	key := make([]byte, 32)
	io.ReadFull(hkdf, key)

	animate(fmt.Sprintf("   HKDF-SHA256 output (AES key): %s", peek(key)), 15)
	return key
}

func createEnvelope(privateKey, encKey []byte) []byte {
	animate("\n✉️ Creating Envelope:", 10)
	animate(fmt.Sprintf("   Private key: %s", peek(privateKey)), 5)

	block, _ := aes.NewCipher(encKey)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)

	ciphertext := gcm.Seal(nonce, nonce, privateKey, nil)
	animate(fmt.Sprintf("   AES-GCM encrypted: %s", peek(ciphertext)), 15)
	return ciphertext
}

func openEnvelope(envelope, encKey []byte) ([]byte, error) {
	animate("\n📩 Opening Envelope:", 10)
	animate(fmt.Sprintf("   Encrypted data: %s", peek(envelope)), 5)

	block, _ := aes.NewCipher(encKey)
	gcm, _ := cipher.NewGCM(block)
	nonceSize := gcm.NonceSize()

	if len(envelope) < nonceSize {
		return nil, errors.New("invalid envelope")
	}

	nonce, ciphertext := envelope[:nonceSize], envelope[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		animate("❌ Decryption failed!", 10)
		return nil, err
	}

	animate(fmt.Sprintf("   Decrypted private key: %s", peek(plaintext)), 15)
	return plaintext, nil
}

/* Protocol Flow */
func register(username, password string) {
	animate("\n\n🌟 ===== REGISTRATION =====", 20)
	animate(fmt.Sprintf("Registering user: %s", username), 10)

	// Server setup
	oprfSecret := generateOPRFSecret()
	
	// Client computations
	oprfOutput := computeOPRF([]byte(password), oprfSecret)
	
	// Simulate client key generation
	privateKey := make([]byte, 32)
	rand.Read(privateKey)
	animate(fmt.Sprintf("\n🗝️ Generated client private key: %s", peek(privateKey)), 15)

	// Create envelope
	encKey := deriveEncKey(oprfOutput)
	envelope := createEnvelope(privateKey, encKey)

	// Server stores credentials
	userDB[username] = struct {
		oprfSecret []byte
		envelope   []byte
	}{oprfSecret, envelope}

	animate("\n💾 Server stored:", 10)
	animate(fmt.Sprintf("   OPRF secret: %s", peek(oprfSecret)), 5)
	animate(fmt.Sprintf("   Envelope: %s", peek(envelope)), 5)
}

func login(username, password string) bool {
	animate("\n\n🔑 ===== LOGIN =====", 20)
	animate(fmt.Sprintf("Authenticating user: %s", username), 10)

	// Retrieve user record
	record, exists := userDB[username]
	if !exists {
		animate("❌ User not found!", 10)
		return false
	}

	// Client recomputes OPRF
	oprfOutput := computeOPRF([]byte(password), record.oprfSecret)

	// Derive decryption key
	encKey := deriveEncKey(oprfOutput)

	// Open envelope
	privateKey, err := openEnvelope(record.envelope, encKey)
	if err != nil {
		return false
	}

	animate(fmt.Sprintf("\n✅ Success! Retrieved private key: %s", peek(privateKey)), 20)
	return true
}

func main() {
	// Demo
	register("alice", "correct_password")
	register("bob", "password123")

	// Successful login
	animate("\n\n=== TEST 1: Correct Password ===", 20)
	login("alice", "correct_password")

	// Failed login
	animate("\n\n=== TEST 2: Wrong Password ===", 20)
	login("bob", "wrong_password")
}
