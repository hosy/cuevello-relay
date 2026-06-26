package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReadTLSClientHelloExtractsSNI(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		tlsConn := tls.Client(clientConn, &tls.Config{
			ServerName:         "abc123.relay.example.com",
			InsecureSkipVerify: true,
		})
		_ = tlsConn.Handshake()
		_ = tlsConn.Close()
	}()

	payload, serverName, err := readTLSClientHello(serverConn, defaultClientHelloLimitBytes)
	if err != nil {
		t.Fatalf("readTLSClientHello failed: %v", err)
	}
	if serverName != "abc123.relay.example.com" {
		t.Fatalf("unexpected server name %q", serverName)
	}
	if len(payload) == 0 {
		t.Fatal("expected buffered TLS payload")
	}

	_ = serverConn.Close()
	<-done
}

func TestVerifyRegistrationSignature(t *testing.T) {
	reg, publicKeyBase64 := signedRegistration(t, "abc123", "secret", time.Now())

	if !verifyRegistrationSignature(reg, publicKeyBase64) {
		t.Fatal("expected registration signature to verify")
	}

	reg.DeviceID = "changed"
	if verifyRegistrationSignature(reg, publicKeyBase64) {
		t.Fatal("expected tampered registration to fail")
	}
}

func TestVerifyRegistrationSignatureRejectsReplayWindow(t *testing.T) {
	staleReg, stalePublicKey := signedRegistration(t, "abc123", "secret", time.Now().Add(-registrationSignatureMaxSkew-time.Second))
	if verifyRegistrationSignature(staleReg, stalePublicKey) {
		t.Fatal("expected stale registration to fail")
	}

	futureReg, futurePublicKey := signedRegistration(t, "abc123", "secret", time.Now().Add(registrationSignatureMaxSkew+time.Second))
	if verifyRegistrationSignature(futureReg, futurePublicKey) {
		t.Fatal("expected future-dated registration to fail")
	}
}

func TestDeviceStoreRejectsUnsignedRegistrationWithoutPoisoningSecret(t *testing.T) {
	store := testDeviceStore(t)
	unsignedAttack := registration{
		Type:     "register",
		DeviceID: "abc123",
		Secret:   "attacker-secret",
		App:      "cuevello-server",
		Version:  2,
	}

	if store.authorize(unsignedAttack, true) {
		t.Fatal("expected unsigned registration to fail when signatures are required")
	}
	if _, ok := store.Hashes["abc123"]; ok {
		t.Fatal("unsigned failed registration poisoned the device secret hash")
	}

	validReg, _ := signedRegistration(t, "abc123", "legitimate-secret", time.Now())
	if !store.authorize(validReg, true) {
		t.Fatal("expected valid signed registration to succeed after unsigned attack")
	}
}

func TestDeviceStorePinsPublicKeyAfterFirstSignedRegistration(t *testing.T) {
	store := testDeviceStore(t)
	firstReg, firstPublicKey := signedRegistration(t, "abc123", "secret", time.Now())
	if !store.authorize(firstReg, true) {
		t.Fatal("expected first signed registration to succeed")
	}
	if store.PublicKeys["abc123"] != firstPublicKey {
		t.Fatal("expected relay to pin the first public key")
	}

	secondReg, _ := signedRegistration(t, "abc123", "secret", time.Now())
	if store.authorize(secondReg, true) {
		t.Fatal("expected registration signed by a different key to fail")
	}
}

func TestDeviceStoreRejectsWrongSecretAfterSignedRegistration(t *testing.T) {
	store := testDeviceStore(t)
	privateKey, publicKey := registrationKeyPair(t)
	validReg := signRegistrationWithKey(t, "abc123", "secret", time.Now(), publicKey, privateKey)
	if !store.authorize(validReg, true) {
		t.Fatal("expected first signed registration to succeed")
	}

	attackerReg := signRegistrationWithKey(t, "abc123", "wrong-secret", time.Now(), publicKey, privateKey)
	if store.authorize(attackerReg, true) {
		t.Fatal("expected wrong secret to fail even with the pinned public key")
	}
}

func TestReadTLSClientHelloRejectsNonTLSInput(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		_, _ = clientConn.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
		_ = clientConn.Close()
	}()

	if _, _, err := readTLSClientHello(serverConn, defaultClientHelloLimitBytes); err == nil {
		t.Fatal("expected non-TLS input to fail")
	}
}

func TestReadLimitedLineRejectsOversizedRegistration(t *testing.T) {
	reader := bufio.NewReaderSize(
		stringsReader("aaaaaaaaaaaa\n"),
		4,
	)
	if _, err := readLimitedLine(reader, 8); err == nil {
		t.Fatal("expected oversized registration line to fail")
	}
}

func TestFixedWindowLimiterRejectsExcessAttempts(t *testing.T) {
	limiter := newFixedWindowLimiter(2, time.Minute)
	if !limiter.allow("203.0.113.10") {
		t.Fatal("expected first attempt to pass")
	}
	if !limiter.allow("203.0.113.10") {
		t.Fatal("expected second attempt to pass")
	}
	if limiter.allow("203.0.113.10") {
		t.Fatal("expected third attempt to be rate limited")
	}
	if !limiter.allow("203.0.113.11") {
		t.Fatal("expected a different source to have its own limit")
	}
}

func testDeviceStore(t *testing.T) *deviceStore {
	t.Helper()
	store, err := loadDeviceStore(filepath.Join(t.TempDir(), "devices.json"), "pepper")
	if err != nil {
		t.Fatalf("loadDeviceStore: %v", err)
	}
	return store
}

func signedRegistration(t *testing.T, deviceID string, secret string, signedAt time.Time) (registration, string) {
	t.Helper()
	privateKey, publicKeyBase64 := registrationKeyPair(t)
	return signRegistrationWithKey(t, deviceID, secret, signedAt, publicKeyBase64, privateKey), publicKeyBase64
}

func registrationKeyPair(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	publicKey := elliptic.Marshal(elliptic.P256(), privateKey.PublicKey.X, privateKey.PublicKey.Y)
	publicKeyBase64 := base64.StdEncoding.EncodeToString(publicKey)
	return privateKey, publicKeyBase64
}

func signRegistrationWithKey(
	t *testing.T,
	deviceID string,
	secret string,
	signedAt time.Time,
	publicKeyBase64 string,
	privateKey *ecdsa.PrivateKey,
) registration {
	t.Helper()
	if privateKey == nil {
		var err error
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
	}
	reg := registration{
		Type:               "register",
		DeviceID:           deviceID,
		Secret:             secret,
		App:                "cuevello-server",
		Version:            2,
		PublicKey:          publicKeyBase64,
		SignatureAlgorithm: registrationSignatureAlgorithm,
		SignedAt:           signedAt.Unix(),
	}
	digest := sha256.Sum256(registrationSignatureMessage(reg, publicKeyBase64))
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatalf("sign registration: %v", err)
	}
	reg.Signature = base64.StdEncoding.EncodeToString(signature)
	return reg
}

func stringsReader(value string) *strings.Reader {
	return strings.NewReader(value)
}
