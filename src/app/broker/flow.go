package broker

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var (
	ErrInvalidCookie = errors.New("invalid flow cookie")
	ErrExpiredCookie = errors.New("expired flow cookie")
)

type FlowClaim struct {
	ClientID string `json:"cid"`
	State    string `json:"state"`
	Kind     string `json:"kind"`
}

const (
	FlowKindWeb    = "web"
	FlowKindDevice = "device"
)

type flowValue struct {
	V   int    `json:"v"`
	CID string `json:"cid"`
	ST  string `json:"st"`
	K   string `json:"k"`
	Exp int64  `json:"exp"`
}

type FlowSigner struct {
	key    []byte
	maxAge time.Duration
}

func NewFlowSigner(key []byte, maxAge time.Duration) *FlowSigner {
	return &FlowSigner{key: key, maxAge: maxAge}
}

func (s *FlowSigner) Issue(kind, clientID, state string) (string, error) {
	if kind != FlowKindWeb && kind != FlowKindDevice {
		return "", fmt.Errorf("issue flow cookie: unknown kind %q", kind)
	}
	value := flowValue{
		V:   2,
		CID: clientID,
		ST:  state,
		K:   kind,
		Exp: time.Now().Add(s.maxAge).Unix(),
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("issue flow cookie: %w", err)
	}

	encoded := base64.RawStdEncoding.EncodeToString(payload)
	sig := s.sign([]byte(encoded))
	return encoded + "." + base64.RawStdEncoding.EncodeToString(sig), nil
}

func (s *FlowSigner) Verify(value string) (FlowClaim, error) {
	var claim FlowClaim

	sep := -1
	for i := len(value) - 1; i >= 0; i-- {
		if value[i] == '.' {
			sep = i
			break
		}
	}
	if sep <= 0 || sep == len(value)-1 {
		return claim, ErrInvalidCookie
	}

	encoded := value[:sep]
	gotSig, err := base64.RawStdEncoding.DecodeString(value[sep+1:])
	if err != nil {
		return claim, ErrInvalidCookie
	}

	wantSig := s.sign([]byte(encoded))
	if !hmac.Equal(gotSig, wantSig) {
		return claim, ErrInvalidCookie
	}

	payload, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return claim, ErrInvalidCookie
	}

	var v flowValue
	if err := json.Unmarshal(payload, &v); err != nil {
		return claim, ErrInvalidCookie
	}

	if v.V != 2 || v.CID == "" {
		return claim, ErrInvalidCookie
	}
	if v.K != FlowKindWeb && v.K != FlowKindDevice {
		return claim, ErrInvalidCookie
	}
	if time.Now().Unix() > v.Exp {
		return claim, ErrExpiredCookie
	}

	claim.ClientID = v.CID
	claim.State = v.ST
	claim.Kind = v.K
	return claim, nil
}

func (s *FlowSigner) sign(data []byte) []byte {
	mac := hmac.New(sha256.New, s.key)
	mac.Write(data)
	return mac.Sum(nil)
}
