package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
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

type UserRecord struct {
	Username    string
	OPRFSecret  []byte
	Envelope    []byte
	ServerPrivKey *ecdsa.PrivateKey
	ServerPubKey  *ecdsa.PublicKey
}

var ServerDatabase = make(map[string]UserRecord)

func animate(msg string, speed time.Duration) {
	for _, c := range msg {
		fmt.Printf("%c", c)
		time.Sleep(speed * time.Millisecond)
	}
	fmt.Println()
}

func peek(data []byte) string {
	if len(data) > 8 {
		return hex.EncodeToString(data[:4]) + "..." + hex.EncodeToString(data[len(data)-4:])
	}
	return hex.EncodeToString(data)
}

/* Key Generation Explanations */
func explainOPRF() {
	animate("\n🔍 OPRF Secret Generation:", 20)
	animate("1. Server generates 32-byte random value", 10)
	animate("2. Used as HMAC-SHA256 key for password blinding", 10)
}

func explainHKDF() {
	animate("\n🔍 HKDF Key Derivation:", 20)
	animate("1. Takes OPRF output as input key material", 10)
	animate("2. Uses SHA-256 hash function", 10)
	animate("3. Adds optional salt (nil here) and context info", 10)
	animate("4. Outputs 32-byte AES encryption key", 10)
}

func explainEnvelope() {
	animate("\n🔍 Envelope Creation:", 20)
	animate("1. Client generates ephemeral private key", 10)
	animate("2. Encrypts it using AES-GCM with derived key", 10)
	animate("3. Includes 12-byte random nonce for GCM", 10)
}

func explainSessionKeys() {
	animate("\n🔍 Session Key Establishment:", 20)
	animate("1. Client and server perform ECDH key exchange", 10)
	animate("2. Client uses decrypted private key", 10)
	animate("3. Server uses long-term private key", 10)
	animate("4. HKDF derives 3 keys from shared secret:", 10)
	animate("   - Encryption key (32 bytes)", 10)
	animate("   - MAC key (32 bytes)", 10)
	animate("   - Initialization Vector (16 bytes)", 10)
}

/* Core Cryptographic Functions */
func generateOPRFSecret() []byte {
	explainOPRF()
	secret := make([]byte, 32)
	rand.Read(secret)
	animate(fmt.Sprintf("✅ Generated: %s", peek(secret)), 20)
	return secret
}

func computeOPRF(password, secret []byte) []byte {
	animate("\n📝 Client OPRF Calculation:", 10)
	animate(fmt.Sprintf("Inputs:\n- Password: '%s'\n- Secret: %s", password, peek(secret)), 5)

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(password))
	result := mac.Sum(nil)

	animate(fmt.Sprintf("HMAC-SHA256:\n- Key: %s\n- Data: '%s'\n- Output: %s", 
		peek(secret), password, peek(result)), 15)
	return result
}

func deriveKeys(ikm []byte, info string) []byte {
	explainHKDF()
	animate(fmt.Sprintf("Inputs:\n- IKM: %s\n- Info: '%s'", peek(ikm), info), 10)

	hkdf := hkdf.New(sha256.New, ikm, nil, []byte(info))
	key := make([]byte, 32)
	io.ReadFull(hkdf, key)

	animate(fmt.Sprintf("HKDF Output (%s): %s", info, peek(key)), 15)
	return key
}

func createEnvelope(data, key []byte) []byte {
	explainEnvelope()
	animate(fmt.Sprintf("Inputs:\n- Data: %s\n- Key: %s", peek(data), peek(key)), 10)

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	animate(fmt.Sprintf("AES-GCM:\n- Nonce: %s\n- Ciphertext: %s", 
		peek(nonce), peek(ciphertext[gcm.NonceSize():])), 15)
	return ciphertext
}

func openEnvelope(envelope, key []byte) ([]byte, error) {
	animate("\n📩 Envelope Decryption:", 10)
	animate(fmt.Sprintf("Inputs:\n- Envelope: %s\n- Key: %s", peek(envelope), peek(key)), 10)

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonceSize := gcm.NonceSize()

	if len(envelope) < nonceSize {
		return nil, errors.New("invalid envelope")
	}

	nonce, ciphertext := envelope[:nonceSize], envelope[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		animate("❌ Failed: "+err.Error(), 10)
		return nil, err
	}

	animate(fmt.Sprintf("✅ Decrypted: %s", peek(plaintext)), 15)
	return plaintext, nil
}

func establishSession(clientPrivKey []byte, serverPrivKey *ecdsa.PrivateKey) ([]byte, []byte, []byte) {
	explainSessionKeys()
	
	// Convert client private key to ECDSA
	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	clientKey.D.SetBytes(clientPrivKey)

	// ECDH Key Exchange
	animate("\n🤝 ECDH Key Exchange:", 10)
	sharedX, _ := serverPrivKey.PublicKey.ScalarMult(
		clientKey.PublicKey.X,
		clientKey.PublicKey.Y,
		serverPrivKey.D.Bytes(),
	)
	sharedSecret := sharedX.Bytes()
	animate(fmt.Sprintf("Shared Secret: %s", peek(sharedSecret)), 15)

	// Derive session keys
	hkdf := hkdf.New(sha256.New, sharedSecret, nil, []byte("OPAQUE-SESSION-KEYS"))
	encKey := make([]byte, 32)
	macKey := make([]byte, 32)
	iv := make([]byte, 16)
	io.ReadFull(hkdf, encKey)
	io.ReadFull(hkdf, macKey)
	io.ReadFull(hkdf, iv)

	animate("\n🔑 Derived Session Keys:", 10)
	animate(fmt.Sprintf("Encryption Key: %s", peek(encKey)), 5)
	animate(fmt.Sprintf("MAC Key: %s", peek(macKey)), 5)
	animate(fmt.Sprintf("IV: %s", peek(iv)), 5)

	return encKey, macKey, iv
}

/* Protocol Flow */
func register(username, password string) {
	animate("\n\n🌟 ===== REGISTRATION =====", 20)
	
	// Server generates OPRF secret
	oprfSecret := generateOPRFSecret()
	
	// Server generates long-term key pair
	serverPrivKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serverPubKey := &serverPrivKey.PublicKey

	// Client computes OPRF
	oprfOutput := computeOPRF([]byte(password), oprfSecret)
	
	// Client generates ephemeral key pair
	clientPrivKey := make([]byte, 32)
	rand.Read(clientPrivKey)
	animate(fmt.Sprintf("\n🗝️ Client Ephemeral Private Key: %s", peek(clientPrivKey)), 15)

	// Create envelope
	encKey := deriveKeys(oprfOutput, "OPAQUE-ENCRYPTION-KEY")
	envelope := createEnvelope(clientPrivKey, encKey)

	// Server stores credentials
	ServerDatabase[username] = UserRecord{
		Username:    username,
		OPRFSecret:  oprfSecret,
		Envelope:    envelope,
		ServerPrivKey: serverPrivKey,
		ServerPubKey:  serverPubKey,
	}
}

func login(username, password string) bool {
	animate("\n\n🔑 ===== LOGIN =====", 20)

	record, exists := ServerDatabase[username]
	if !exists {
		animate("❌ User not found!", 10)
		return false
	}

	// Client recomputes OPRF
	oprfOutput := computeOPRF([]byte(password), record.OPRFSecret)

	// Open envelope
	encKey := deriveKeys(oprfOutput, "OPAQUE-ENCRYPTION-KEY")
	clientPrivKey, err := openEnvelope(record.Envelope, encKey)
	if err != nil {
		return false
	}

	// Establish session
	encKey, macKey, iv := establishSession(clientPrivKey, record.ServerPrivKey)

	animate("\n🎉 Secure Session Established!", 20)
	animate(fmt.Sprintf("Use these for secure communication:\n- Enc Key: %s\n- MAC Key: %s\n- IV: %s", 
		peek(encKey), peek(macKey), peek(iv)), 10)
	return true
}

func main() {
	// Demo
	register("alice", "correct_password")
	login("alice", "correct_password")
}
