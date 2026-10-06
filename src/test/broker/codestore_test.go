package broker_test

import (
	"gate21/src/app/broker"
	"sync"
	"testing"
	"time"
)

func grant(cid string) broker.Grant {
	return broker.Grant{
		ClientID:     cid,
		AccessToken:  "access-" + cid,
		RefreshToken: "refresh-" + cid,
		ExpiresIn:    300,
		Scope:        "openid",
	}
}

func TestMintExchangeHappyPath(t *testing.T) {
	store := broker.NewCodeStore(time.Minute)
	defer store.Close()

	code, err := store.Mint(grant("svc-a"))
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	if len(code) != 43 {
		t.Errorf("code length = %d, want 43 (32 raw bytes base64url)", len(code))
	}

	got, ok := store.Exchange(code, "svc-a")
	if !ok {
		t.Fatal("Exchange() = not ok, want ok")
	}
	if got.AccessToken != "access-svc-a" || got.RefreshToken != "refresh-svc-a" {
		t.Errorf("tokens mismatch: %+v", got)
	}
}

func TestExchangeSingleUse(t *testing.T) {
	store := broker.NewCodeStore(time.Minute)
	defer store.Close()

	code, err := store.Mint(grant("svc-a"))
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}

	if _, ok := store.Exchange(code, "svc-a"); !ok {
		t.Fatal("first exchange failed")
	}
	if _, ok := store.Exchange(code, "svc-a"); ok {
		t.Fatal("second exchange succeeded, want failure (one-time)")
	}
}

func TestExchangeWrongClient(t *testing.T) {
	store := broker.NewCodeStore(time.Minute)
	defer store.Close()

	code, _ := store.Mint(grant("svc-a"))
	if _, ok := store.Exchange(code, "svc-b"); ok {
		t.Fatal("exchange by other client succeeded, want failure")
	}
	if _, ok := store.Exchange(code, "svc-a"); !ok {
		t.Fatal("original client could not exchange (code consumed by wrong client)")
	}
}

func TestExchangeUnknownCode(t *testing.T) {
	store := broker.NewCodeStore(time.Minute)
	defer store.Close()

	if _, ok := store.Exchange("does-not-exist", "svc-a"); ok {
		t.Fatal("exchange of unknown code succeeded")
	}
}

func TestExchangeExpired(t *testing.T) {
	store := broker.NewCodeStore(-time.Second)
	defer store.Close()

	code, _ := store.Mint(grant("svc-a"))
	if _, ok := store.Exchange(code, "svc-a"); ok {
		t.Fatal("exchange of already-expired code succeeded")
	}
}

func TestMintEmptyClient(t *testing.T) {
	store := broker.NewCodeStore(time.Minute)
	defer store.Close()

	if _, err := store.Mint(grant("")); err == nil {
		t.Fatal("Mint with empty client id expected error")
	}
}

func TestLenReapsExpired(t *testing.T) {
	store := broker.NewCodeStore(40 * time.Millisecond)
	defer store.Close()

	store.Mint(grant("svc-a"))
	store.Mint(grant("svc-a"))
	if n := store.Len(); n != 2 {
		t.Fatalf("Len() = %d, want 2", n)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if n := store.Len(); n == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("expired codes were not reaped within deadline")
}

func TestConcurrentExchangeSingleWinner(t *testing.T) {
	store := broker.NewCodeStore(time.Minute)
	defer store.Close()

	code, _ := store.Mint(grant("svc-a"))

	const workers = 16
	var mu sync.Mutex
	successes := 0
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := store.Exchange(code, "svc-a"); ok {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if successes != 1 {
		t.Fatalf("concurrent exchanges succeeded %d times, want exactly 1", successes)
	}
}

func TestConcurrentMintNoDuplicateCodes(t *testing.T) {
	store := broker.NewCodeStore(time.Minute)
	defer store.Close()

	const n = 64
	var wg sync.WaitGroup
	codes := make([]string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := store.Mint(grant("svc-a"))
			if err != nil {
				t.Errorf("Mint() error = %v", err)
				return
			}
			codes[i] = c
		}(i)
	}
	wg.Wait()

	seen := make(map[string]struct{}, n)
	for _, c := range codes {
		if c == "" {
			t.Fatal("empty code produced")
		}
		if _, dup := seen[c]; dup {
			t.Fatal("duplicate code produced")
		}
		seen[c] = struct{}{}
	}
}
