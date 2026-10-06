package registry_test

import (
	"gate21/src/app/registry"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeClients(t *testing.T, data string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "clients.json")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write clients file: %v", err)
	}
	return path
}

const validClients = `{
  "clients": [
    {"id": "svc-a", "redirect_uri": "https://svc-a.example.com/oauth/cb", "secret": "secret-a"},
    {"id": "svc-b", "redirect_uri": "https://svc-b.example.com/oauth/cb", "secret": "secret-b"}
  ]
}`

func TestLoadValid(t *testing.T) {
	path := writeClients(t, validClients)
	r, err := registry.Load(path)
	if err != nil {
		t.Fatalf("registry.Load() error = %v", err)
	}
	if r.Len() != 2 {
		t.Fatalf("loaded %d clients, want 2", r.Len())
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := registry.Load(filepath.Join(t.TempDir(), "nope.json"))
	if err == nil {
		t.Fatal("registry.Load() expected error for missing file")
	}
}

func TestLoadMalformedJSON(t *testing.T) {
	path := writeClients(t, "{not json")
	_, err := registry.Load(path)
	if err == nil {
		t.Fatal("registry.Load() expected error for malformed json")
	}
}

func TestLoadDuplicateClient(t *testing.T) {
	path := writeClients(t, `{
	  "clients": [
	    {"id": "a", "redirect_uri": "https://a.example.com/cb", "secret": "s1"},
	    {"id": "a", "redirect_uri": "https://b.example.com/cb", "secret": "s2"}
	  ]
	}`)
	_, err := registry.Load(path)
	if err == nil {
		t.Fatal("registry.Load() expected error for duplicate id")
	}
}

func TestLoadEmptyFields(t *testing.T) {
	path := writeClients(t, `{"clients": [{"id": ""}]}`)
	_, err := registry.Load(path)
	if err == nil {
		t.Fatal("registry.Load() expected error for empty id")
	}
}

func TestAllowedRedirectExactMatch(t *testing.T) {
	path := writeClients(t, validClients)
	r, err := registry.Load(path)
	if err != nil {
		t.Fatalf("registry.Load() error = %v", err)
	}

	want := "https://svc-a.example.com/oauth/cb"
	tests := []struct {
		name string
		id   string
		uri  string
		ok   bool
	}{
		{"exact", "svc-a", want, true},
		{"prefix only", "svc-a", "https://svc-a.example.com/oauth", false},
		{"suffix only", "svc-a", "/oauth/cb", false},
		{"trailing slash", "svc-a", want + "/", false},
		{"extra params", "svc-a", want + "?x=1", false},
		{"case differs", "svc-a", "https://SVC-A.EXAMPLE.COM/oauth/cb", false},
		{"unknown client", "svc-zzz", want, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := r.AllowedRedirect(tt.id, tt.uri); got != tt.ok {
				t.Errorf("AllowedRedirect(%q, %q) = %v, want %v", tt.id, tt.uri, got, tt.ok)
			}
		})
	}
}

func TestVerifySecret(t *testing.T) {
	path := writeClients(t, validClients)
	r, err := registry.Load(path)
	if err != nil {
		t.Fatalf("registry.Load() error = %v", err)
	}

	tests := []struct {
		name   string
		id     string
		secret string
		ok     bool
	}{
		{"correct", "svc-a", "secret-a", true},
		{"wrong", "svc-a", "secret-x", false},
		{"missing", "svc-a", "", false},
		{"unknown client", "svc-zzz", "secret-a", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := r.VerifySecret(tt.id, tt.secret); got != tt.ok {
				t.Errorf("registry.VerifySecret(%q, %q) = %v, want %v", tt.id, tt.secret, got, tt.ok)
			}
		})
	}
}

func TestNoOpenRedirect(t *testing.T) {
	// The anti pattern this guards: redirect_uri validation via prefix or substring.
	path := writeClients(t, `{
	  "clients": [
	    {"id": "a", "redirect_uri": "https://a.example.com/cb", "secret": "s"}
	  ]
	}`)
	r, err := registry.Load(path)
	if err != nil {
		t.Fatalf("registry.Load() error = %v", err)
	}

	if r.Allowed("b") {
		t.Fatal("registry.Allowed(b) = true, want false")
	}
	for _, uri := range []string{
		"https://a.example.com/cb/../../evil",
		"https://a.example.com/cb.evil.com",
		"https://evil.com/https://a.example.com/cb",
		"https://a.example.com/cb@evil.com",
		strings.Repeat("x", len("https://a.example.com/cb")),
	} {
		if r.AllowedRedirect("a", uri) {
			t.Errorf("AllowedRedirect accepted dangerous uri %q", uri)
		}
	}
}

func TestLoadValidatesEmptyRegistry(t *testing.T) {
	path := writeClients(t, `{"clients": []}`)
	r, err := registry.Load(path)
	if err != nil {
		t.Fatalf("registry.Load() error = %v", err)
	}
	if r.Allowed("anything") {
		t.Fatal("registry.Allowed = true on empty registry")
	}
}

func TestFlowDefaultIsWeb(t *testing.T) {
	path := writeClients(t, validClients)
	r, err := registry.Load(path)
	if err != nil {
		t.Fatalf("registry.Load() error = %v", err)
	}
	c, ok := r.Lookup("svc-a")
	if !ok {
		t.Fatal("registry.Lookup failed")
	}
	if c.Flow != registry.FlowWeb || c.IsDevice() {
		t.Errorf("default flow = %q, want web", c.Flow)
	}
}

func TestLoadDeviceClient(t *testing.T) {
	path := writeClients(t, `{
	  "clients": [
	    {"id": "bot-a", "secret": "s-bot", "flow": "device"}
	  ]
	}`)
	r, err := registry.Load(path)
	if err != nil {
		t.Fatalf("registry.Load() error = %v", err)
	}
	c, ok := r.Lookup("bot-a")
	if !ok || !c.IsDevice() {
		t.Fatalf("registry.Lookup/IsDevice = %v/%v, want true", ok, c)
	}
	if r.AllowedRedirect("bot-a", "") {
		t.Error("AllowedRedirect = true for device client")
	}
}

func TestLoadFlowValidation(t *testing.T) {
	tests := []struct {
		name    string
		clients string
	}{
		{"web without redirect_uri", `{"clients":[{"id":"a","secret":"s","flow":"web"}]}`},
		{"device with redirect_uri", `{"clients":[{"id":"a","redirect_uri":"https://a.example.com/cb","secret":"s","flow":"device"}]}`},
		{"unknown flow", `{"clients":[{"id":"a","secret":"s","flow":"magic"}]}`},
		{"missing secret", `{"clients":[{"id":"a","redirect_uri":"https://a.example.com/cb"}]}`},
		{"device missing secret", `{"clients":[{"id":"a","flow":"device"}]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := registry.Load(writeClients(t, tt.clients)); err == nil {
				t.Fatal("registry.Load() expected error")
			}
		})
	}
}
