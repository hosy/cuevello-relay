package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
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
)

type registration struct {
	Type     string `json:"type"`
	DeviceID string `json:"deviceID"`
	Secret   string `json:"secret"`
	App      string `json:"app"`
	Version  int    `json:"version"`
}

type frame struct {
	Kind     byte
	StreamID [16]byte
	Payload  []byte
}

type deviceStore struct {
	path   string
	pepper string
	mu     sync.Mutex
	Hashes map[string]string `json:"hashes"`
}

type relayServer struct {
	tlsConfig *tls.Config
	store     *deviceStore
	mu        sync.RWMutex
	devices   map[string]*controlSession
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

func main() {
	clientAddr := env("CLIENT_ADDR", ":443")
	controlAddr := env("CONTROL_ADDR", ":8443")
	certFile := env("TLS_CERT_FILE", "/certs/fullchain.pem")
	keyFile := env("TLS_KEY_FILE", "/certs/privkey.pem")
	pepper := strings.TrimSpace(os.Getenv("RELAY_SECRET_PEPPER"))
	dataFile := env("RELAY_DATA_FILE", "/data/devices.json")

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
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
		},
		store:   store,
		devices: make(map[string]*controlSession),
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

func loadDeviceStore(path, pepper string) (*deviceStore, error) {
	store := &deviceStore{
		path:   path,
		pepper: pepper,
		Hashes: map[string]string{},
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
	store.path = path
	store.pepper = pepper
	return store, nil
}

func (s *deviceStore) authorize(deviceID, secret string) bool {
	deviceID = normalizeDeviceID(deviceID)
	secret = strings.TrimSpace(secret)
	if deviceID == "" || secret == "" {
		return false
	}

	nextHash := s.secretHash(deviceID, secret)
	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.Hashes[deviceID]; ok {
		return hmac.Equal([]byte(existing), []byte(nextHash))
	}

	s.Hashes[deviceID] = nextHash
	if err := s.saveLocked(); err != nil {
		log.Printf("save device store: %v", err)
	}
	return true
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
		go s.handleControl(conn)
	}
}

func (s *relayServer) listenClients(addr string) {
	listener, err := tls.Listen("tcp", addr, s.tlsConfig)
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
		go s.handleClient(conn)
	}
}

func (s *relayServer) handleControl(conn net.Conn) {
	tlsConn, ok := conn.(*tls.Conn)
	if ok {
		_ = tlsConn.SetDeadline(time.Now().Add(15 * time.Second))
		if err := tlsConn.Handshake(); err != nil {
			log.Printf("control handshake: %v", err)
			conn.Close()
			return
		}
		_ = tlsConn.SetDeadline(time.Time{})
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		log.Printf("read registration: %v", err)
		conn.Close()
		return
	}

	var reg registration
	if err := json.Unmarshal(bytesTrimSpace(line), &reg); err != nil {
		log.Printf("decode registration: %v", err)
		conn.Close()
		return
	}

	deviceID := normalizeDeviceID(reg.DeviceID)
	if reg.Type != "register" || deviceID == "" || !s.store.authorize(deviceID, reg.Secret) {
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

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}
	_ = tlsConn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("client handshake: %v", err)
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})

	deviceID := deviceIDFromServerName(tlsConn.ConnectionState().ServerName)
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

	session.addStream(streamID, conn)
	defer session.removeStream(streamID)

	if err := session.send(frame{Kind: frameOpen, StreamID: streamID}); err != nil {
		log.Printf("open stream %s: %v", hex.EncodeToString(streamID[:]), err)
		return
	}
	defer session.send(frame{Kind: frameClose, StreamID: streamID})

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
				_, _ = stream.Write(next.Payload)
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

func (s *controlSession) addStream(streamID [16]byte, conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.streams[streamID] = conn
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
	_, err = s.conn.Write(payload)
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
