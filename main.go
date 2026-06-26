package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	frameOpen  byte = 1
	frameData  byte = 2
	frameClose byte = 3
	framePing  byte = 4
	framePong  byte = 5

	frameHeaderLength = 21
	maxPayloadLength  = 16 * 1024 * 1024

	defaultMaxStreamsPerDevice        = 32
	defaultClientRateLimitPerMinute   = 120
	defaultControlRateLimitPerMinute  = 30
	defaultRegistrationLineLimitBytes = 8192
	defaultClientHelloLimitBytes      = 64 * 1024
	defaultHandshakeTimeout           = 15 * time.Second
	defaultWriteTimeout               = 30 * time.Second
	defaultRequireSignedRegistration  = true
	registrationSignatureMaxSkew      = 5 * time.Minute

	registrationSignatureAlgorithm = "p256-x963-sha256"
)

type registration struct {
	Type               string `json:"type"`
	DeviceID           string `json:"deviceID"`
	Secret             string `json:"secret"`
	App                string `json:"app"`
	Version            int    `json:"version"`
	PublicKey          string `json:"publicKey,omitempty"`
	Signature          string `json:"signature,omitempty"`
	SignatureAlgorithm string `json:"signatureAlgorithm,omitempty"`
	SignedAt           int64  `json:"signedAt,omitempty"`
}

type frame struct {
	Kind     byte
	StreamID [16]byte
	Payload  []byte
}

type deviceStore struct {
	path       string
	pepper     string
	mu         sync.Mutex
	Hashes     map[string]string `json:"hashes"`
	PublicKeys map[string]string `json:"publicKeys,omitempty"`
}

type relayServer struct {
	tlsConfig           *tls.Config
	store               *deviceStore
	clientLimiter       *fixedWindowLimiter
	controlLimiter      *fixedWindowLimiter
	maxStreamsPerDevice int
	requireSignedReg    bool
	mu                  sync.RWMutex
	devices             map[string]*controlSession
}

type controlSession struct {
	deviceID string
	conn     net.Conn
	server   *relayServer
	writeMu  sync.Mutex
	mu       sync.Mutex
	streams  map[[16]byte]net.Conn
	closed   chan struct{}
}

type rateWindow struct {
	resetAt time.Time
	count   int
}

type fixedWindowLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	entries map[string]rateWindow
}

func main() {
	clientAddr := env("CLIENT_ADDR", ":443")
	controlAddr := env("CONTROL_ADDR", ":8443")
	certFile := env("TLS_CERT_FILE", "/certs/fullchain.pem")
	keyFile := env("TLS_KEY_FILE", "/certs/privkey.pem")
	pepper := strings.TrimSpace(os.Getenv("RELAY_SECRET_PEPPER"))
	dataFile := env("RELAY_DATA_FILE", "/data/devices.json")
	maxStreamsPerDevice := envInt("MAX_STREAMS_PER_DEVICE", defaultMaxStreamsPerDevice)
	clientRateLimit := envInt("CLIENT_RATE_LIMIT_PER_MINUTE", defaultClientRateLimitPerMinute)
	controlRateLimit := envInt("CONTROL_RATE_LIMIT_PER_MINUTE", defaultControlRateLimitPerMinute)
	requireSignedRegistration := envBool("REQUIRE_SIGNED_REGISTRATION", defaultRequireSignedRegistration)

	if pepper == "" {
		log.Fatal("RELAY_SECRET_PEPPER is required")
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("load tls certificate: %v", err)
	}

	store, err := loadDeviceStore(dataFile, pepper)
	if err != nil {
		log.Fatalf("load device store: %v", err)
	}

	server := &relayServer{
		tlsConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{cert},
		},
		store:               store,
		clientLimiter:       newFixedWindowLimiter(clientRateLimit, time.Minute),
		controlLimiter:      newFixedWindowLimiter(controlRateLimit, time.Minute),
		maxStreamsPerDevice: maxStreamsPerDevice,
		requireSignedReg:    requireSignedRegistration,
		devices:             make(map[string]*controlSession),
	}

	go server.listenControl(controlAddr)
	server.listenClients(clientAddr)
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func envInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		log.Printf("ignoring invalid %s=%q", key, value)
		return fallback
	}
	return parsed
}

func envBool(key string, fallback bool) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if value == "" {
		return fallback
	}
	switch value {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		log.Printf("ignoring invalid %s=%q", key, value)
		return fallback
	}
}

func newFixedWindowLimiter(limit int, window time.Duration) *fixedWindowLimiter {
	return &fixedWindowLimiter{
		limit:   limit,
		window:  window,
		entries: map[string]rateWindow{},
	}
}

func (l *fixedWindowLimiter) allow(key string) bool {
	if l == nil || l.limit <= 0 {
		return true
	}
	key = strings.TrimSpace(key)
	if key == "" {
		key = "unknown"
	}

	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	for entryKey, entry := range l.entries {
		if now.After(entry.resetAt) {
			delete(l.entries, entryKey)
		}
	}

	entry := l.entries[key]
	if entry.resetAt.IsZero() || now.After(entry.resetAt) {
		entry = rateWindow{resetAt: now.Add(l.window)}
	}
	if entry.count >= l.limit {
		l.entries[key] = entry
		return false
	}
	entry.count++
	l.entries[key] = entry
	return true
}

func loadDeviceStore(path, pepper string) (*deviceStore, error) {
	store := &deviceStore{
		path:       path,
		pepper:     pepper,
		Hashes:     map[string]string{},
		PublicKeys: map[string]string{},
	}

	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return store, nil
	}
	if err := json.Unmarshal(data, store); err != nil {
		return nil, err
	}
	if store.Hashes == nil {
		store.Hashes = map[string]string{}
	}
	if store.PublicKeys == nil {
		store.PublicKeys = map[string]string{}
	}
	store.path = path
	store.pepper = pepper
	return store, nil
}

func (s *deviceStore) authorize(reg registration, requireSignedRegistration bool) bool {
	deviceID := normalizeDeviceID(reg.DeviceID)
	secret := strings.TrimSpace(reg.Secret)
	if deviceID == "" || secret == "" {
		return false
	}

	nextHash := s.secretHash(deviceID, secret)
	s.mu.Lock()
	defer s.mu.Unlock()

	_, hasExistingHash := s.Hashes[deviceID]
	if existing, ok := s.Hashes[deviceID]; ok {
		if !hmac.Equal([]byte(existing), []byte(nextHash)) {
			return false
		}
	}

	existingPublicKey := strings.TrimSpace(s.PublicKeys[deviceID])
	nextPublicKey := strings.TrimSpace(reg.PublicKey)
	var publicKeyToStore string
	if existingPublicKey != "" {
		if nextPublicKey == "" || nextPublicKey != existingPublicKey {
			return false
		}
		if !verifyRegistrationSignature(reg, existingPublicKey) {
			return false
		}
	} else if nextPublicKey != "" {
		if !verifyRegistrationSignature(reg, nextPublicKey) {
			return false
		}
		publicKeyToStore = nextPublicKey
	} else if requireSignedRegistration {
		return false
	}

	if !hasExistingHash {
		s.Hashes[deviceID] = nextHash
	}
	if publicKeyToStore != "" {
		s.PublicKeys[deviceID] = publicKeyToStore
	}

	if err := s.saveLocked(); err != nil {
		log.Printf("save device store: %v", err)
	}
	return true
}

func verifyRegistrationSignature(reg registration, publicKey string) bool {
	if strings.TrimSpace(reg.SignatureAlgorithm) != registrationSignatureAlgorithm {
		return false
	}
	if reg.SignedAt <= 0 {
		return false
	}
	signedAt := time.Unix(reg.SignedAt, 0)
	if time.Since(signedAt) > registrationSignatureMaxSkew || time.Until(signedAt) > registrationSignatureMaxSkew {
		return false
	}

	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return false
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), publicKeyBytes)
	if x == nil || y == nil {
		return false
	}

	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(reg.Signature))
	if err != nil {
		return false
	}

	digest := sha256.Sum256(registrationSignatureMessage(reg, publicKey))
	key := ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	return ecdsa.VerifyASN1(&key, digest[:], signature)
}

func registrationSignatureMessage(reg registration, publicKey string) []byte {
	message := fmt.Sprintf(
		"cuevello-relay-register-v2\n%s\n%s\n%d\n%d\n%s",
		normalizeDeviceID(reg.DeviceID),
		strings.TrimSpace(reg.App),
		reg.Version,
		reg.SignedAt,
		strings.TrimSpace(publicKey),
	)
	return []byte(message)
}

func (s *deviceStore) secretHash(deviceID, secret string) string {
	mac := hmac.New(sha256.New, []byte(s.pepper))
	mac.Write([]byte(deviceID))
	mac.Write([]byte{0})
	mac.Write([]byte(secret))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *deviceStore) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o600)
}

func (s *relayServer) listenControl(addr string) {
	listener, err := tls.Listen("tcp", addr, s.tlsConfig)
	if err != nil {
		log.Fatalf("listen control %s: %v", addr, err)
	}
	defer listener.Close()
	log.Printf("control listener ready on %s", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept control: %v", err)
			continue
		}
		if !s.controlLimiter.allow(remoteIP(conn.RemoteAddr())) {
			log.Printf("control rate limit exceeded for %s", conn.RemoteAddr())
			conn.Close()
			continue
		}
		go s.handleControl(conn)
	}
}

func (s *relayServer) listenClients(addr string) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen clients %s: %v", addr, err)
	}
	defer listener.Close()
	log.Printf("client listener ready on %s", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept client: %v", err)
			continue
		}
		if !s.clientLimiter.allow(remoteIP(conn.RemoteAddr())) {
			log.Printf("client rate limit exceeded for %s", conn.RemoteAddr())
			conn.Close()
			continue
		}
		go s.handleClient(conn)
	}
}

func (s *relayServer) handleControl(conn net.Conn) {
	tlsConn, ok := conn.(*tls.Conn)
	if ok {
		_ = tlsConn.SetDeadline(time.Now().Add(defaultHandshakeTimeout))
		if err := tlsConn.Handshake(); err != nil {
			log.Printf("control handshake: %v", err)
			conn.Close()
			return
		}
		_ = tlsConn.SetDeadline(time.Now().Add(defaultHandshakeTimeout))
	}

	reader := bufio.NewReader(conn)
	line, err := readLimitedLine(reader, defaultRegistrationLineLimitBytes)
	if err != nil {
		log.Printf("read registration: %v", err)
		conn.Close()
		return
	}
	if ok {
		_ = tlsConn.SetDeadline(time.Time{})
	}

	var reg registration
	if err := json.Unmarshal(bytesTrimSpace(line), &reg); err != nil {
		log.Printf("decode registration: %v", err)
		conn.Close()
		return
	}

	deviceID := normalizeDeviceID(reg.DeviceID)
	if reg.Type != "register" || deviceID == "" || !s.store.authorize(reg, s.requireSignedReg) {
		log.Printf("rejected control registration for device %q", reg.DeviceID)
		conn.Close()
		return
	}

	session := &controlSession{
		deviceID: deviceID,
		conn:     conn,
		server:   s,
		streams:  map[[16]byte]net.Conn{},
		closed:   make(chan struct{}),
	}

	s.registerDevice(session)
	log.Printf("device %s connected", deviceID)
	session.readLoop(reader)
}

func (s *relayServer) registerDevice(session *controlSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if previous := s.devices[session.deviceID]; previous != nil {
		previous.close()
	}
	s.devices[session.deviceID] = session
}

func (s *relayServer) unregisterDevice(session *controlSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if current := s.devices[session.deviceID]; current == session {
		delete(s.devices, session.deviceID)
	}
}

func (s *relayServer) session(deviceID string) *controlSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.devices[normalizeDeviceID(deviceID)]
}

func (s *relayServer) handleClient(conn net.Conn) {
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(defaultHandshakeTimeout))
	initialPayload, serverName, err := readTLSClientHello(conn, defaultClientHelloLimitBytes)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		log.Printf("client hello: %v", err)
		return
	}

	deviceID := deviceIDFromServerName(serverName)
	if deviceID == "" {
		log.Printf("client without device SNI from %s", conn.RemoteAddr())
		return
	}

	session := s.session(deviceID)
	if session == nil {
		log.Printf("client requested offline device %s", deviceID)
		return
	}

	streamID, err := randomStreamID()
	if err != nil {
		log.Printf("stream id: %v", err)
		return
	}

	if !session.addStream(streamID, conn, s.maxStreamsPerDevice) {
		log.Printf("device %s stream limit reached", deviceID)
		return
	}
	defer session.removeStream(streamID)

	if err := session.send(frame{Kind: frameOpen, StreamID: streamID}); err != nil {
		log.Printf("open stream %s: %v", hex.EncodeToString(streamID[:]), err)
		return
	}
	defer session.send(frame{Kind: frameClose, StreamID: streamID})

	if len(initialPayload) > 0 {
		if err := session.send(frame{
			Kind:     frameData,
			StreamID: streamID,
			Payload:  initialPayload,
		}); err != nil {
			log.Printf("send client hello to device %s: %v", deviceID, err)
			return
		}
	}

	buffer := make([]byte, 64*1024)
	for {
		n, err := conn.Read(buffer)
		if n > 0 {
			if sendErr := session.send(frame{
				Kind:     frameData,
				StreamID: streamID,
				Payload:  append([]byte(nil), buffer[:n]...),
			}); sendErr != nil {
				log.Printf("send data to device %s: %v", deviceID, sendErr)
				return
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) && !isClosedNetworkError(err) {
				log.Printf("client read %s: %v", deviceID, err)
			}
			return
		}
	}
}

func (s *controlSession) readLoop(reader *bufio.Reader) {
	defer s.close()
	defer s.server.unregisterDevice(s)
	defer log.Printf("device %s disconnected", s.deviceID)

	for {
		next, err := readFrame(reader)
		if err != nil {
			if !errors.Is(err, io.EOF) && !isClosedNetworkError(err) {
				log.Printf("read frame from %s: %v", s.deviceID, err)
			}
			return
		}

		switch next.Kind {
		case frameData:
			s.mu.Lock()
			stream := s.streams[next.StreamID]
			s.mu.Unlock()
			if stream != nil && len(next.Payload) > 0 {
				_ = stream.SetWriteDeadline(time.Now().Add(defaultWriteTimeout))
				_, err := stream.Write(next.Payload)
				_ = stream.SetWriteDeadline(time.Time{})
				if err != nil {
					s.removeStream(next.StreamID)
				}
			}
		case frameClose:
			s.removeStream(next.StreamID)
		case framePing:
			_ = s.send(frame{Kind: framePong, StreamID: next.StreamID})
		case framePong:
		default:
			log.Printf("unknown frame kind %d from %s", next.Kind, s.deviceID)
			return
		}
	}
}

func (s *controlSession) addStream(streamID [16]byte, conn net.Conn, maxStreams int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if maxStreams > 0 && len(s.streams) >= maxStreams {
		return false
	}
	s.streams[streamID] = conn
	return true
}

func (s *controlSession) removeStream(streamID [16]byte) {
	s.mu.Lock()
	conn := s.streams[streamID]
	delete(s.streams, streamID)
	s.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

func (s *controlSession) send(next frame) error {
	payload, err := encodeFrame(next)
	if err != nil {
		return err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_ = s.conn.SetWriteDeadline(time.Now().Add(defaultWriteTimeout))
	_, err = s.conn.Write(payload)
	_ = s.conn.SetWriteDeadline(time.Time{})
	return err
}

func (s *controlSession) close() {
	select {
	case <-s.closed:
		return
	default:
		close(s.closed)
	}
	_ = s.conn.Close()
	s.mu.Lock()
	streams := s.streams
	s.streams = map[[16]byte]net.Conn{}
	s.mu.Unlock()
	for _, stream := range streams {
		_ = stream.Close()
	}
}

func readFrame(reader *bufio.Reader) (frame, error) {
	var header [frameHeaderLength]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return frame{}, err
	}
	length := binary.BigEndian.Uint32(header[17:21])
	if length > maxPayloadLength {
		return frame{}, fmt.Errorf("frame payload too large: %d", length)
	}

	next := frame{Kind: header[0]}
	copy(next.StreamID[:], header[1:17])
	if length > 0 {
		next.Payload = make([]byte, length)
		if _, err := io.ReadFull(reader, next.Payload); err != nil {
			return frame{}, err
		}
	}
	return next, nil
}

func readLimitedLine(reader *bufio.Reader, maxLength int) ([]byte, error) {
	var line []byte
	for {
		part, isPrefix, err := reader.ReadLine()
		if err != nil {
			return nil, err
		}
		line = append(line, part...)
		if len(line) > maxLength {
			return nil, fmt.Errorf("line too long: %d bytes", len(line))
		}
		if !isPrefix {
			return line, nil
		}
	}
}

func readTLSClientHello(conn net.Conn, maxLength int) ([]byte, string, error) {
	var payload []byte
	var handshake []byte

	for len(payload) < maxLength {
		var header [5]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			return nil, "", err
		}

		recordLength := int(binary.BigEndian.Uint16(header[3:5]))
		if recordLength == 0 {
			return nil, "", errors.New("empty TLS record")
		}
		if len(payload)+len(header)+recordLength > maxLength {
			return nil, "", fmt.Errorf("client hello too large: %d bytes", len(payload)+len(header)+recordLength)
		}
		if header[0] != 22 {
			return nil, "", fmt.Errorf("unexpected TLS record type %d", header[0])
		}

		record := make([]byte, recordLength)
		if _, err := io.ReadFull(conn, record); err != nil {
			return nil, "", err
		}

		payload = append(payload, header[:]...)
		payload = append(payload, record...)
		handshake = append(handshake, record...)

		if len(handshake) < 4 {
			continue
		}
		if handshake[0] != 1 {
			return nil, "", fmt.Errorf("unexpected TLS handshake type %d", handshake[0])
		}

		handshakeLength := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
		if handshakeLength <= 0 {
			return nil, "", errors.New("empty TLS client hello")
		}
		if 4+handshakeLength > maxLength {
			return nil, "", fmt.Errorf("client hello too large: %d bytes", 4+handshakeLength)
		}
		if len(handshake) < 4+handshakeLength {
			continue
		}

		serverName, err := serverNameFromClientHello(handshake[4 : 4+handshakeLength])
		if err != nil {
			return nil, "", err
		}
		return payload, serverName, nil
	}

	return nil, "", fmt.Errorf("client hello exceeded %d bytes", maxLength)
}

func serverNameFromClientHello(body []byte) (string, error) {
	offset := 0
	advance := func(count int) ([]byte, bool) {
		if count < 0 || offset+count > len(body) {
			return nil, false
		}
		value := body[offset : offset+count]
		offset += count
		return value, true
	}

	if _, ok := advance(2 + 32); !ok {
		return "", errors.New("truncated TLS client hello")
	}

	sessionIDLength, ok := readUint8(body, &offset)
	if !ok {
		return "", errors.New("truncated TLS session id")
	}
	if _, ok := advance(int(sessionIDLength)); !ok {
		return "", errors.New("truncated TLS session id")
	}

	cipherSuitesLength, ok := readUint16(body, &offset)
	if !ok {
		return "", errors.New("truncated TLS cipher suites")
	}
	if _, ok := advance(int(cipherSuitesLength)); !ok {
		return "", errors.New("truncated TLS cipher suites")
	}

	compressionMethodsLength, ok := readUint8(body, &offset)
	if !ok {
		return "", errors.New("truncated TLS compression methods")
	}
	if _, ok := advance(int(compressionMethodsLength)); !ok {
		return "", errors.New("truncated TLS compression methods")
	}

	extensionsLength, ok := readUint16(body, &offset)
	if !ok {
		return "", errors.New("missing TLS extensions")
	}
	if offset+int(extensionsLength) > len(body) {
		return "", errors.New("truncated TLS extensions")
	}

	extensionsEnd := offset + int(extensionsLength)
	for offset < extensionsEnd {
		extensionType, ok := readUint16(body, &offset)
		if !ok {
			return "", errors.New("truncated TLS extension type")
		}
		extensionLength, ok := readUint16(body, &offset)
		if !ok {
			return "", errors.New("truncated TLS extension length")
		}
		if offset+int(extensionLength) > extensionsEnd {
			return "", errors.New("truncated TLS extension data")
		}
		extensionData := body[offset : offset+int(extensionLength)]
		offset += int(extensionLength)

		if extensionType == 0 {
			return serverNameFromSNIExtension(extensionData)
		}
	}

	return "", errors.New("missing TLS SNI extension")
}

func serverNameFromSNIExtension(data []byte) (string, error) {
	offset := 0
	listLength, ok := readUint16(data, &offset)
	if !ok || offset+int(listLength) > len(data) {
		return "", errors.New("truncated TLS SNI extension")
	}
	listEnd := offset + int(listLength)
	for offset < listEnd {
		nameType, ok := readUint8(data, &offset)
		if !ok {
			return "", errors.New("truncated TLS SNI name type")
		}
		nameLength, ok := readUint16(data, &offset)
		if !ok || offset+int(nameLength) > listEnd {
			return "", errors.New("truncated TLS SNI name")
		}
		name := data[offset : offset+int(nameLength)]
		offset += int(nameLength)
		if nameType == 0 && len(name) > 0 {
			return string(name), nil
		}
	}
	return "", errors.New("missing TLS SNI hostname")
}

func readUint8(data []byte, offset *int) (uint8, bool) {
	if *offset+1 > len(data) {
		return 0, false
	}
	value := data[*offset]
	*offset += 1
	return value, true
}

func readUint16(data []byte, offset *int) (uint16, bool) {
	if *offset+2 > len(data) {
		return 0, false
	}
	value := binary.BigEndian.Uint16(data[*offset : *offset+2])
	*offset += 2
	return value, true
}

func encodeFrame(next frame) ([]byte, error) {
	if len(next.Payload) > maxPayloadLength {
		return nil, fmt.Errorf("frame payload too large: %d", len(next.Payload))
	}
	data := make([]byte, frameHeaderLength+len(next.Payload))
	data[0] = next.Kind
	copy(data[1:17], next.StreamID[:])
	binary.BigEndian.PutUint32(data[17:21], uint32(len(next.Payload)))
	copy(data[frameHeaderLength:], next.Payload)
	return data, nil
}

func randomStreamID() ([16]byte, error) {
	var id [16]byte
	_, err := rand.Read(id[:])
	return id, err
}

func normalizeDeviceID(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var builder strings.Builder
	for _, char := range value {
		if char >= 'a' && char <= 'z' ||
			char >= '0' && char <= '9' ||
			char == '-' ||
			char == '_' {
			builder.WriteRune(char)
		}
	}
	return builder.String()
}

func remoteIP(address net.Addr) string {
	if address == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(address.String())
	if err != nil {
		return address.String()
	}
	return host
}

func deviceIDFromServerName(serverName string) string {
	serverName = strings.Trim(strings.ToLower(serverName), ".")
	if serverName == "" {
		return ""
	}
	parts := strings.Split(serverName, ".")
	if len(parts) < 3 {
		return ""
	}
	return normalizeDeviceID(parts[0])
}

func bytesTrimSpace(data []byte) []byte {
	return []byte(strings.TrimSpace(string(data)))
}

func isClosedNetworkError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "use of closed network connection") ||
		strings.Contains(message, "connection reset by peer") ||
		strings.Contains(message, "broken pipe")
}
