package broker

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

type PollResult int

const (
	PollPending PollResult = iota
	PollSlowDown
	PollSuccess
	PollInvalid
)

type deviceSession struct {
	clientID  string
	userCode  string
	status    int // 0 pending, 1 done
	grant     Grant
	expiresAt time.Time
	nextPoll  time.Time
}

const (
	devicePending = 0
	deviceDone    = 1
)

type DeviceStore struct {
	mu           sync.Mutex
	byCode       map[string]*deviceSession
	byUC         map[string]string
	ttl          time.Duration
	pollInterval time.Duration
	stop         chan struct{}
	done         chan struct{}
}

func NewDeviceStore(ttl, pollInterval time.Duration) *DeviceStore {
	s := &DeviceStore{
		byCode:       make(map[string]*deviceSession),
		byUC:         make(map[string]string),
		ttl:          ttl,
		pollInterval: pollInterval,
		stop:         make(chan struct{}),
		done:         make(chan struct{}),
	}
	go s.cleanupLoop()
	return s
}

func (s *DeviceStore) Create(clientID string) (deviceCode, userCode string, expiresAt time.Time, err error) {
	if clientID == "" {
		return "", "", time.Time{}, fmt.Errorf("device create: client id is empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for i := 0; i < 4; i++ {
		deviceCode, err = randomCode(32)
		if err != nil {
			return "", "", time.Time{}, err
		}
		userCode, err = randomCode(16)
		if err != nil {
			return "", "", time.Time{}, err
		}
		if _, codeDup := s.byCode[deviceCode]; codeDup {
			continue
		}
		if _, ucDup := s.byUC[userCode]; ucDup {
			continue
		}
		break
	}
	if deviceCode == "" || userCode == "" {
		return "", "", time.Time{}, fmt.Errorf("device create: failed to generate unique codes")
	}

	expiresAt = time.Now().Add(s.ttl)
	s.byCode[deviceCode] = &deviceSession{
		clientID:  clientID,
		userCode:  userCode,
		status:    devicePending,
		expiresAt: expiresAt,
	}
	s.byUC[userCode] = deviceCode
	return deviceCode, userCode, expiresAt, nil
}

// SessionByUserCode validates a user code and returns the bound device code
// together with the client that owns the session.
func (s *DeviceStore) SessionByUserCode(userCode string) (deviceCode, clientID string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	deviceCode, session := s.sessionByUCLocked(userCode)
	if session == nil {
		return "", "", false
	}
	return deviceCode, session.clientID, true
}

// Complete binds tokens to a pending device session identified by its user code.
func (s *DeviceStore) Complete(userCode, clientID string, grant Grant) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, session := s.sessionByUCLocked(userCode)
	if session == nil || session.clientID != clientID || grant.ClientID != clientID {
		return false
	}
	if session.status != devicePending {
		return false
	}

	session.status = deviceDone
	session.grant = grant
	return true
}

// Poll advances the device session state: pending sessions are rate-limited
// by pollInterval; completed sessions return their grant exactly once.
func (s *DeviceStore) Poll(deviceCode, clientID string) (PollResult, Grant) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.byCode[deviceCode]
	if !ok {
		return PollInvalid, Grant{}
	}
	if time.Now().After(session.expiresAt) {
		s.deleteLocked(deviceCode, session)
		return PollInvalid, Grant{}
	}
	if session.clientID != clientID {
		return PollInvalid, Grant{}
	}

	switch session.status {
	case devicePending:
		now := time.Now()
		if now.Before(session.nextPoll) {
			return PollSlowDown, Grant{}
		}
		session.nextPoll = now.Add(s.pollInterval)
		return PollPending, Grant{}
	case deviceDone:
		grant := session.grant
		s.deleteLocked(deviceCode, session)
		return PollSuccess, grant
	default:
		return PollInvalid, Grant{}
	}
}

func (s *DeviceStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reapExpiredLocked()
	return len(s.byCode)
}

func (s *DeviceStore) Close() {
	select {
	case <-s.stop:
		return
	default:
	}
	close(s.stop)
	<-s.done
}

func (s *DeviceStore) sessionByUCLocked(userCode string) (string, *deviceSession) {
	deviceCode, ok := s.byUC[userCode]
	if !ok {
		return "", nil
	}
	session, ok := s.byCode[deviceCode]
	if !ok {
		delete(s.byUC, userCode)
		return "", nil
	}
	if time.Now().After(session.expiresAt) {
		s.deleteLocked(deviceCode, session)
		return "", nil
	}
	return deviceCode, session
}

func (s *DeviceStore) deleteLocked(deviceCode string, session *deviceSession) {
	delete(s.byCode, deviceCode)
	if session != nil {
		delete(s.byUC, session.userCode)
	}
}

func (s *DeviceStore) reapExpiredLocked() {
	now := time.Now()
	for code, session := range s.byCode {
		if now.After(session.expiresAt) {
			s.deleteLocked(code, session)
		}
	}
}

func (s *DeviceStore) cleanupLoop() {
	defer close(s.done)
	interval := s.ttl / 2
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			s.mu.Lock()
			s.reapExpiredLocked()
			s.mu.Unlock()
		}
	}
}

func randomCode(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate code: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
