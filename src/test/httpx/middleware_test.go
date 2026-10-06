package httpx_test

import (
	"bytes"
	"gate21/src/app/httpx"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWithRequestIDGenerates(t *testing.T) {
	var gotID string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotID = r.Header.Get(httpx.RequestIDHeader)
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)

	httpx.WithRequestID(next).ServeHTTP(rec, req)

	if gotID == "" {
		t.Fatal("request id not generated")
	}
	if rec.Header().Get(httpx.RequestIDHeader) != gotID {
		t.Errorf("response header = %q, want %q", rec.Header().Get(httpx.RequestIDHeader), gotID)
	}
}

func TestWithRequestIDPassesThrough(t *testing.T) {
	var gotID string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotID = r.Header.Get(httpx.RequestIDHeader)
	})
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set(httpx.RequestIDHeader, "client-provided-id")
	rec := httptest.NewRecorder()

	httpx.WithRequestID(next).ServeHTTP(rec, req)

	if gotID != "client-provided-id" {
		t.Errorf("request id = %q, want passthrough", gotID)
	}
}

func TestRecoverCatchesPanic(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	panics := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/boom", nil)
	req.Header.Set(httpx.RequestIDHeader, "id-1")

	httpx.Recover(logger)(panics).ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	if !strings.Contains(buf.String(), "request_id=id-1") {
		t.Errorf("log missing request id: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "boom") {
		t.Errorf("log missing panic error: %s", buf.String())
	}
}

func TestAccessLogDoesNotLeakBody(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)

	secret := "S3cret-Password-For-Test"
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		io.Copy(io.Discard, bytes.NewReader(body))
		w.WriteHeader(http.StatusTeapot)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader("username=alice&password="+secret))
	req.Header.Set(httpx.RequestIDHeader, "id-log")
	rec := httptest.NewRecorder()

	httpx.AccessLog(logger)(next).ServeHTTP(rec, req)

	logged := buf.String()
	if !strings.Contains(logged, "method=POST") {
		t.Errorf("log missing method: %s", logged)
	}
	if !strings.Contains(logged, "path=/api/login") {
		t.Errorf("log missing path: %s", logged)
	}
	if !strings.Contains(logged, "status=418") {
		t.Errorf("log missing status: %s", logged)
	}
	if !strings.Contains(logged, "request_id=id-log") {
		t.Errorf("log missing request id: %s", logged)
	}
	if strings.Contains(logged, secret) || strings.Contains(logged, "alice") {
		t.Errorf("log leaked request body: %s", logged)
	}
}

func TestRateLimitEnforcesBurst(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := httpx.RateLimit(0, 2)(next)
	req := func() *http.Response {
		r := httptest.NewRequest(http.MethodGet, "/x", nil)
		r.RemoteAddr = "192.0.2.1:5555"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)
		return rec.Result()
	}

	if got := req().StatusCode; got != http.StatusOK {
		t.Fatalf("first request = %d, want 200", got)
	}
	if got := req().StatusCode; got != http.StatusOK {
		t.Fatalf("second request = %d, want 200", got)
	}
	if got := req().StatusCode; got != http.StatusTooManyRequests {
		t.Fatalf("third request = %d, want 429", got)
	}
}

func TestRateLimitSeparateClients(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := httpx.RateLimit(0, 1)(next)

	req := func(ip string) int {
		r := httptest.NewRequest(http.MethodGet, "/x", nil)
		r.RemoteAddr = ip + ":5555"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)
		return rec.Code
	}

	if req("192.0.2.1") != http.StatusOK {
		t.Fatal("client A first request blocked")
	}
	if req("192.0.2.2") != http.StatusOK {
		t.Fatal("client B blocked by client A's quota")
	}
	if req("192.0.2.1") != http.StatusTooManyRequests {
		t.Fatal("client A not limited after burst")
	}
}

func TestRateLimitRefills(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := httpx.RateLimit(1000, 1)(next)

	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.RemoteAddr = "192.0.2.1:5555"

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("first request = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, r)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("burst consumed: second request = %d, want 429", rec.Code)
	}

	time.Sleep(20 * time.Millisecond)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("request after refill = %d, want 200", rec.Code)
	}
}

func TestRateLimitClientIPFromForwardedFor(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := httpx.RateLimit(0, 1)(next)

	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.RemoteAddr = "10.0.0.1:4444"
	r.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.1")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatal("request blocked")
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, r)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second request = %d, want 429 (same XFF client)", rec.Code)
	}
}

func TestRateLimitConcurrentSafe(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := httpx.RateLimit(0, 100)(next)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r := httptest.NewRequest(http.MethodGet, "/x", nil)
			r.RemoteAddr = "192.0.2.1:5555"
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, r)
		}(i)
	}
	wg.Wait()
}

func TestClientIP(t *testing.T) {
	tests := []struct {
		name      string
		forwarded string
		addr      string
		want      string
	}{
		{"xf first hop", "203.0.113.9, 10.0.0.1", "10.0.0.1:4444", "203.0.113.9"},
		{"xf single", "203.0.113.9", "10.0.0.1:4444", "203.0.113.9"},
		{"no xf", "", "203.0.113.9:4444", "203.0.113.9"},
		{"no port", "", "203.0.113.9:0", "203.0.113.9"},
		{"empty remote", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tt.addr
			r.Header.Set("X-Forwarded-For", tt.forwarded)
			if got := httpx.ClientIP(r); got != tt.want {
				t.Errorf("httpx.ClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}
