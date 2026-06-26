package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"net"
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
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	publicKey := elliptic.Marshal(elliptic.P256(), privateKey.PublicKey.X, privateKey.PublicKey.Y)
	publicKeyBase64 := base64.StdEncoding.EncodeToString(publicKey)

	reg := registration{
		Type:               "register",
		DeviceID:           "abc123",
		Secret:             "secret",
		App:                "cuevello-server",
		Version:            2,
		PublicKey:          publicKeyBase64,
		SignatureAlgorithm: registrationSignatureAlgorithm,
		SignedAt:           time.Now().Unix(),
	}
	digest := sha256.Sum256(registrationSignatureMessage(reg, publicKeyBase64))
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatalf("sign registration: %v", err)
	}
	reg.Signature = base64.StdEncoding.EncodeToString(signature)

	if !verifyRegistrationSignature(reg, publicKeyBase64) {
		t.Fatal("expected registration signature to verify")
	}

	reg.DeviceID = "changed"
	if verifyRegistrationSignature(reg, publicKeyBase64) {
		t.Fatal("expected tampered registration to fail")
	}
}
