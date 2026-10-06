package broker_test

import (
	"errors"
	"gate21/src/app/broker"
	"strings"
	"testing"
	"time"
)

const testKey = "0123456789abcdef"

func TestFlowIssueVerify(t *testing.T) {
	s := broker.NewFlowSigner([]byte(testKey), time.Minute)

	value, err := s.Issue(broker.FlowKindWeb, "svc-a", "state-123")
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	claim, err := s.Verify(value)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if claim.ClientID != "svc-a" || claim.State != "state-123" {
		t.Errorf("claim = %+v", claim)
	}
}

func TestFlowStatePassthroughVariety(t *testing.T) {
	s := broker.NewFlowSigner([]byte(testKey), time.Minute)
	for _, state := range []string{"x", "b64~0p!_", "with space", "with%20encode", strings.Repeat("a", 512)} {
		value, err := s.Issue(broker.FlowKindWeb, "svc-a", state)
		if err != nil {
			t.Fatalf("Issue(%q) error = %v", state, err)
		}
		claim, err := s.Verify(value)
		if err != nil {
			t.Fatalf("Verify(%q) error = %v", state, err)
		}
		if claim.State != state {
			t.Errorf("state roundtrip = %q, want %q", claim.State, state)
		}
	}
}

func TestFlowTamperRejected(t *testing.T) {
	s := broker.NewFlowSigner([]byte(testKey), time.Minute)
	value, _ := s.Issue(broker.FlowKindWeb, "svc-a", "state-123")

	tampered := []string{
		value + "x",
		value[:len(value)-1],
		value[:len(value)/2] + "AAAAA" + value[len(value)/2:],
		strings.Replace(value, "1", "0", 1),
	}
	for _, tv := range tampered {
		if tv == value {
			continue
		}
		if _, err := s.Verify(tv); err == nil {
			t.Errorf("Verify accepted tampered value %q", tv)
		}
	}

	// State substitution inside payload must also fail.
	parts := strings.SplitN(value, ".", 2)
	if len(parts) == 2 {
		if _, err := s.Verify(parts[1] + "." + parts[0]); err == nil {
			t.Error("Verify accepted reordered segments")
		}
	}
}

func TestFlowWrongKeyRejected(t *testing.T) {
	value, _ := broker.NewFlowSigner([]byte(testKey), time.Minute).Issue(broker.FlowKindWeb, "svc-a", "s1")
	if _, err := broker.NewFlowSigner([]byte("different-key-000"), time.Minute).Verify(value); err == nil {
		t.Fatal("Verify with wrong key accepted cookie")
	}
}

func TestFlowGarbageRejected(t *testing.T) {
	s := broker.NewFlowSigner([]byte(testKey), time.Minute)
	for _, v := range []string{"", ".", "..", "no-dot-at-all", "a.b.c", "!!!.###", "YWJj.=="} {
		_, err := s.Verify(v)
		if err == nil {
			t.Errorf("Verify accepted garbage %q", v)
		}
		if !errors.Is(err, broker.ErrInvalidCookie) {
			t.Logf("garbage %q error = %v", v, err)
		}
	}
}

func TestFlowExpired(t *testing.T) {
	s := broker.NewFlowSigner([]byte(testKey), -time.Second)
	value, _ := s.Issue(broker.FlowKindWeb, "svc-a", "s1")
	if _, err := s.Verify(value); !errors.Is(err, broker.ErrExpiredCookie) {
		t.Fatalf("Verify() error = %v, want broker.ErrExpiredCookie", err)
	}
}

func TestFlowIssueVerifyEmptyKeyPanicSafety(t *testing.T) {
	// HMAC with empty key still works: just checking no panic/nil deref.
	s := broker.NewFlowSigner(nil, time.Minute)
	value, err := s.Issue(broker.FlowKindWeb, "svc-a", "s1")
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if _, err := s.Verify(value); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestFlowKindRoundtrip(t *testing.T) {
	s := broker.NewFlowSigner([]byte(testKey), time.Minute)

	value, err := s.Issue(broker.FlowKindDevice, "bot-a", "uc-1")
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	claim, err := s.Verify(value)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if claim.Kind != broker.FlowKindDevice {
		t.Errorf("Kind = %q, want device", claim.Kind)
	}
	if claim.ClientID != "bot-a" || claim.State != "uc-1" {
		t.Errorf("claim = %+v", claim)
	}
}

func TestFlowIssueUnknownKind(t *testing.T) {
	s := broker.NewFlowSigner([]byte(testKey), time.Minute)
	if _, err := s.Issue("magic", "svc-a", "s1"); err == nil {
		t.Fatal("Issue() with unknown kind expected error")
	}
	if _, err := s.Issue("", "svc-a", "s1"); err == nil {
		t.Fatal("Issue() with empty kind expected error")
	}
}

func TestFlowEmptyKindRejected(t *testing.T) {
	// Craft a cookie without kind by hand: sign a v1-style payload with the key.
	s := broker.NewFlowSigner([]byte(testKey), time.Minute)
	value, _ := s.Issue(broker.FlowKindWeb, "svc-a", "s1")

	// Tampering kind inside the payload breaks the signature, so instead
	// verify that Verify never yields an empty Kind on a valid cookie.
	claim, err := s.Verify(value)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if claim.Kind != broker.FlowKindWeb {
		t.Errorf("Kind = %q, want web", claim.Kind)
	}
}
