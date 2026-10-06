package broker_test

import (
	"gate21/src/app/broker"
	"sync"
	"testing"
	"time"
)

func deviceGrant(cid string) broker.Grant {
	return broker.Grant{
		ClientID:     cid,
		AccessToken:  "at-" + cid,
		RefreshToken: "rt-" + cid,
		ExpiresIn:    300,
		Scope:        "openid",
	}
}

func TestDeviceCreateLookup(t *testing.T) {
	s := broker.NewDeviceStore(time.Minute, time.Second)
	defer s.Close()

	dc1, uc1, exp, err := s.Create("bot-a")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if dc1 == "" || uc1 == "" {
		t.Fatal("empty codes returned")
	}
	if dc1 == uc1 {
		t.Fatal("device code must differ from user code")
	}
	if !exp.After(time.Now()) {
		t.Errorf("expiresAt = %v, want future", exp)
	}

	gotDC, gotCID, ok := s.SessionByUserCode(uc1)
	if !ok || gotDC != dc1 || gotCID != "bot-a" {
		t.Fatalf("SessionByUserCode = %q/%q/%v, want %q/bot-a/true", gotDC, gotCID, ok, dc1)
	}

	dc2, uc2, _, err := s.Create("bot-a")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if dc2 == dc1 || uc2 == uc1 {
		t.Fatal("codes are not unique across sessions")
	}
}

func TestDeviceCreateEmptyClient(t *testing.T) {
	s := broker.NewDeviceStore(time.Minute, time.Second)
	defer s.Close()
	if _, _, _, err := s.Create(""); err == nil {
		t.Fatal("Create with empty client id expected error")
	}
}

func TestDeviceSessionLookupFailures(t *testing.T) {
	s := broker.NewDeviceStore(time.Minute, time.Second)
	defer s.Close()
	s.Create("bot-a")

	if _, _, ok := s.SessionByUserCode("nope"); ok {
		t.Error("SessionByUserCode of unknown user code succeeded")
	}
	if _, cid, ok := s.SessionByUserCode(""); ok || cid != "" {
		t.Error("SessionByUserCode of empty user code succeeded")
	}
}

func TestDevicePendingThenSlowDown(t *testing.T) {
	s := broker.NewDeviceStore(time.Minute, time.Hour)
	defer s.Close()
	dc, _, _, _ := s.Create("bot-a")

	if res, _ := s.Poll(dc, "bot-a"); res != broker.PollPending {
		t.Errorf("first Poll = %v, want broker.PollPending", res)
	}
	if res, _ := s.Poll(dc, "bot-a"); res != broker.PollSlowDown {
		t.Errorf("second Poll = %v, want broker.PollSlowDown", res)
	}
}

func TestDeviceCompleteThenSingleSuccess(t *testing.T) {
	s := broker.NewDeviceStore(time.Minute, time.Second)
	defer s.Close()
	dc, uc, _, _ := s.Create("bot-a")

	if !s.Complete(uc, "bot-a", deviceGrant("bot-a")) {
		t.Fatal("Complete() failed")
	}

	res, grant := s.Poll(dc, "bot-a")
	if res != broker.PollSuccess {
		t.Fatalf("Poll = %v, want broker.PollSuccess", res)
	}
	if grant.AccessToken != "at-bot-a" || grant.RefreshToken != "rt-bot-a" {
		t.Errorf("grant = %+v", grant)
	}

	if res, _ := s.Poll(dc, "bot-a"); res != broker.PollInvalid {
		t.Errorf("second Poll = %v, want broker.PollInvalid (single-use)", res)
	}
}

func TestDeviceCompleteTwiceFails(t *testing.T) {
	s := broker.NewDeviceStore(time.Minute, time.Second)
	defer s.Close()
	_, uc, _, _ := s.Create("bot-a")

	if !s.Complete(uc, "bot-a", deviceGrant("bot-a")) {
		t.Fatal("first Complete() failed")
	}
	if s.Complete(uc, "bot-a", deviceGrant("bot-a")) {
		t.Error("second Complete() succeeded, want failure")
	}
}

func TestDeviceCompleteWrongClient(t *testing.T) {
	s := broker.NewDeviceStore(time.Minute, time.Second)
	defer s.Close()
	_, uc, _, _ := s.Create("bot-a")

	if s.Complete(uc, "bot-b", deviceGrant("bot-a")) {
		t.Error("Complete by wrong client succeeded")
	}
	if s.Complete(uc, "bot-a", deviceGrant("bot-b")) {
		t.Error("Complete with mismatched grant client succeeded")
	}
	if _, uc2, _, _ := s.Create("bot-b"); uc2 == "" {
		t.Fatal("store broken after failed completes")
	}
}

func TestDevicePollFailures(t *testing.T) {
	s := broker.NewDeviceStore(time.Minute, time.Hour)
	defer s.Close()
	dc, _, _, _ := s.Create("bot-a")

	if res, _ := s.Poll("unknown-code", "bot-a"); res != broker.PollInvalid {
		t.Errorf("unknown code Poll = %v", res)
	}
	if res, _ := s.Poll(dc, "bot-b"); res != broker.PollInvalid {
		t.Errorf("wrong client Poll = %v", res)
	}
}

func TestDeviceExpired(t *testing.T) {
	s := broker.NewDeviceStore(-time.Second, time.Second)
	defer s.Close()
	dc, uc, _, _ := s.Create("bot-a")

	if _, _, ok := s.SessionByUserCode(uc); ok {
		t.Error("SessionByUserCode of expired session succeeded")
	}
	if s.Complete(uc, "bot-a", deviceGrant("bot-a")) {
		t.Error("Complete on expired session succeeded")
	}
	if res, _ := s.Poll(dc, "bot-a"); res != broker.PollInvalid {
		t.Errorf("Poll of expired session = %v", res)
	}
}

func TestDeviceLenReapsExpired(t *testing.T) {
	s := broker.NewDeviceStore(40*time.Millisecond, time.Second)
	defer s.Close()
	s.Create("bot-a")
	s.Create("bot-a")
	if n := s.Len(); n != 2 {
		t.Fatalf("Len() = %d, want 2", n)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if n := s.Len(); n == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("expired device sessions were not reaped")
}

func TestDeviceConcurrentPollSingleWinner(t *testing.T) {
	s := broker.NewDeviceStore(time.Minute, time.Millisecond)
	defer s.Close()
	dc, uc, _, _ := s.Create("bot-a")
	if !s.Complete(uc, "bot-a", deviceGrant("bot-a")) {
		t.Fatal("Complete() failed")
	}
	// Let the poll interval elapse so every worker is allowed to poll.
	time.Sleep(5 * time.Millisecond)

	var mu sync.Mutex
	successes := 0
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if res, _ := s.Poll(dc, "bot-a"); res == broker.PollSuccess {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if successes != 1 {
		t.Fatalf("concurrent successful polls = %d, want exactly 1", successes)
	}
}
