package httpx

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

const RequestIDHeader = "X-Request-Id"

func nextRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return time.Now().UTC().Format("20060102T150405.000000000")
	}
	return hex.EncodeToString(b[:])
}

func WithRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(RequestIDHeader)
		if id == "" || len(id) > 128 {
			id = nextRequestID()
		}
		r.Header.Set(RequestIDHeader, id)
		w.Header().Set(RequestIDHeader, id)
		next.ServeHTTP(w, r)
	})
}

func Recover(logger *log.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					logger.Printf("panic request_id=%s path=%s err=%v\n%s",
						r.Header.Get(RequestIDHeader), r.URL.Path, rec, debug.Stack())
					http.Error(w, "internal error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func AccessLog(logger *log.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			cw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(cw, r)
			logger.Printf("access request_id=%s method=%s path=%s status=%d dur=%s remote=%s",
				r.Header.Get(RequestIDHeader), r.Method, r.URL.Path, cw.status,
				time.Since(start).Round(time.Microsecond), ClientIP(r))
		})
	}
}

// RateLimit returns a middleware that throttles requests per client key
// (first X-Forwarded-For entry, falling back to the TCP peer).
func RateLimit(rate float64, burst int) func(http.Handler) http.Handler {
	limiter := newRateLimiter(rate, burst)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !limiter.allow(ClientIP(r)) {
				http.Error(w, "too many requests", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func ClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.IndexByte(xff, ','); idx >= 0 {
			xff = xff[:idx]
		}
		if ip := strings.TrimSpace(xff); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

type rateLimiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	buckets map[string]*bucket
	stop    chan struct{}
	done    chan struct{}
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(rate float64, burst int) *rateLimiter {
	if rate <= 0 {
		rate = 1
	}
	if burst <= 0 {
		burst = 1
	}
	l := &rateLimiter{
		rate:    rate,
		burst:   float64(burst),
		buckets: make(map[string]*bucket),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	go l.cleanupLoop()
	return l
}

func (l *rateLimiter) allow(key string) bool {
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		l.buckets[key] = &bucket{tokens: l.burst - 1, last: now}
		return true
	}

	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *rateLimiter) close() {
	select {
	case <-l.stop:
		return
	default:
	}
	close(l.stop)
	<-l.done
}

func (l *rateLimiter) cleanupLoop() {
	defer close(l.done)
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-ticker.C:
			l.mu.Lock()
			cutoff := time.Now().Add(-10 * time.Minute)
			for key, b := range l.buckets {
				if b.last.Before(cutoff) {
					delete(l.buckets, key)
				}
			}
			l.mu.Unlock()
		}
	}
}
