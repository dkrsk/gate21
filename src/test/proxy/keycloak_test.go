package proxy_test

import (
	"bytes"
	"context"
	"encoding/json"
	"gate21/src/app/proxy"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTokenURL(t *testing.T) {
	k, err := proxy.New("https://auth.example.com", "MyRealm", time.Second)
	if err != nil {
		t.Fatalf("proxy.New() error = %v", err)
	}
	want := "https://auth.example.com/auth/realms/MyRealm/protocol/openid-connect/token"
	if k.TokenURL() != want {
		t.Errorf("TokenURL() = %q, want %q", k.TokenURL(), want)
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := proxy.New("", "r", time.Second); err == nil {
		t.Fatal("proxy.New() expected error for empty base")
	}
	if _, err := proxy.New("https://x.example.com", "", time.Second); err == nil {
		t.Fatal("proxy.New() expected error for empty realm")
	}
}

func TestLoginPassesBodyUnchanged(t *testing.T) {
	// The security contract: the request body (which contains the user
	// password) must reach proxy.Keycloak byte-for-byte, never parsed or rebuilt.
	formBody := []byte("client_id=school21&username=johndoe&password=S3cret%21p%40ss&grant_type=password")

	var gotBody []byte
	var gotContentType string
	var gotPath string
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		gotBody = b
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token":"at","refresh_token":"rt","expires_in":300}`)
	}))
	defer fake.Close()

	base := strings.TrimSuffix(fake.URL, "/")
	k, err := proxy.New(base, "MyRealm", time.Second)
	if err != nil {
		t.Fatalf("proxy.New() error = %v", err)
	}

	resp, err := k.Login(context.Background(), formBody)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
	if gotPath != "/auth/realms/MyRealm/protocol/openid-connect/token" {
		t.Errorf("path = %q", gotPath)
	}
	if gotContentType != "application/x-www-form-urlencoded" {
		t.Errorf("content-type = %q", gotContentType)
	}
	if !bytes.Equal(gotBody, formBody) {
		t.Errorf("body not passthrough:\n got  %q\n want %q", gotBody, formBody)
	}

	var parsed proxy.TokenResponse
	if err := json.Unmarshal(resp.Body, &parsed); err != nil {
		t.Fatalf("unmarshal token response: %v", err)
	}
	if parsed.AccessToken != "at" || parsed.RefreshToken != "rt" || parsed.ExpiresIn != 300 {
		t.Errorf("parsed = %+v", parsed)
	}
}

func TestLoginErrorPassthrough(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":"invalid_grant","error_description":"Invalid user credentials"}`)
	}))
	defer fake.Close()

	k, err := proxy.New(fake.URL, "MyRealm", time.Second)
	if err != nil {
		t.Fatalf("proxy.New() error = %v", err)
	}

	resp, err := k.Login(context.Background(), []byte("grant_type=password"))
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("StatusCode = %d, want 401", resp.StatusCode)
	}
	if !strings.Contains(string(resp.Body), `"error":"invalid_grant"`) {
		t.Errorf("error body not passthrough: %s", resp.Body)
	}
}

func TestLoginTimeout(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		io.WriteString(w, `{}`)
	}))
	defer fake.Close()

	k, err := proxy.New(fake.URL, "MyRealm", 30*time.Millisecond)
	if err != nil {
		t.Fatalf("proxy.New() error = %v", err)
	}

	_, err = k.Login(context.Background(), []byte("grant_type=password"))
	if err == nil {
		t.Fatal("Login() expected timeout error")
	}
}

func TestLoginServerDown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	k, err := proxy.New(url, "MyRealm", time.Second)
	if err != nil {
		t.Fatalf("proxy.New() error = %v", err)
	}

	_, err = k.Login(context.Background(), []byte("grant_type=password"))
	if err == nil {
		t.Fatal("Login() expected connection error")
	}
}
