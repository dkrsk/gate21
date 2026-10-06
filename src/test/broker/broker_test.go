package broker_test

import (
	"encoding/json"
	"gate21/src/app/broker"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gate21/src/app/proxy"
	"gate21/src/app/registry"
)

const context = "0123456789abcdef"

func newTestServer(t *testing.T, kcHandler http.HandlerFunc) (*httptest.Server, *registry.Registry) {
	return newTestServerWith(t, kcHandler, nil)
}

func newTestServerWith(t *testing.T, kcHandler http.HandlerFunc, tweak func(*broker.Options)) (*httptest.Server, *registry.Registry) {
	t.Helper()

	dir := t.TempDir()
	clientsPath := filepath.Join(dir, "clients.json")
	clientsJSON := `{
	  "clients": [
	    {"id": "svc-a", "redirect_uri": "https://svc-a.example.com/oauth/cb", "secret": "secret-a"},
	    {"id": "bot-a", "flow": "device", "secret": "secret-bot"}
	  ]
	}`
	if err := os.WriteFile(clientsPath, []byte(clientsJSON), 0o600); err != nil {
		t.Fatalf("write clients: %v", err)
	}
	reg, err := registry.Load(clientsPath)
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}

	kc := httptest.NewServer(kcHandler)
	t.Cleanup(kc.Close)

	kp, err := proxy.New(kc.URL, "MyRealm", 2*time.Second)
	if err != nil {
		t.Fatalf("new keycloak proxy: %v", err)
	}

	opts := broker.Options{
		Logger:        log.New(io.Discard, "", 0),
		Keycloak:      kp,
		Registry:      reg,
		SignerKey:     []byte(context),
		FlowMaxAge:    time.Minute,
		CodeTTL:       time.Minute,
		DeviceTTL:     time.Minute,
		PollInterval:  time.Hour,
		PublicBase:    "https://auth.example.com",
		SecureCookies: false,
	}
	if tweak != nil {
		tweak(&opts)
	}

	br, err := broker.New(opts)
	if err != nil {
		t.Fatalf("new broker: %v", err)
	}
	t.Cleanup(br.Close)

	srv := httptest.NewServer(br.Routes())
	t.Cleanup(srv.Close)
	return srv, reg
}

func successfulKeycloak() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token":"at-123","refresh_token":"rt-456","expires_in":300,"scope":"openid"}`)
	}
}

func failingKeycloak() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":"invalid_grant","error_description":"Invalid user credentials"}`)
	}
}

func performAuthorize(t *testing.T, srv *httptest.Server, clientID, state string) (*http.Response, string) {
	t.Helper()
	u := srv.URL + "/authorize?client_id=" + url.QueryEscape(clientID)
	if state != "" {
		u += "&state=" + url.QueryEscape(state)
	}
	resp, err := http.Get(u)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /authorize status = %d, body = %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "login-form") {
		t.Fatalf("GET /authorize did not serve login page: %s", body[:min(len(body), 200)])
	}

	cookies := resp.Cookies()
	var flowVal string
	for _, c := range cookies {
		if c.Name == broker.FlowCookieName {
			flowVal = c.Value
		}
	}
	if flowVal == "" {
		t.Fatal("GET /authorize did not set authflow cookie")
	}
	return resp, flowVal
}

func doLogin(t *testing.T, srv *httptest.Server, flowVal, formBody string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/login", strings.NewReader(formBody))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if flowVal != "" {
		req.AddCookie(&http.Cookie{Name: broker.FlowCookieName, Value: flowVal})
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /api/login: %v", err)
	}
	return resp
}

func extractCodeFromRedirect(t *testing.T, resp *http.Response, expectState string) string {
	t.Helper()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var payload struct {
		Redirect string `json:"redirect"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("parse /api/login response: %v (body=%s)", err, body)
	}

	u, err := url.Parse(payload.Redirect)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	if u.Scheme != "https" || u.Host != "svc-a.example.com" || u.Path != "/oauth/cb" {
		t.Fatalf("redirect target = %q", payload.Redirect)
	}
	q := u.Query()
	if q.Get("state") != expectState {
		t.Fatalf("redirect state = %q, want %q", q.Get("state"), expectState)
	}
	code := q.Get("code")
	if code == "" {
		t.Fatal("redirect has no code")
	}
	return code
}

func exchangeCode(t *testing.T, srv *httptest.Server, code, clientID, secret string) (*http.Response, map[string]any) {
	t.Helper()
	form := url.Values{}
	form.Set("code", code)
	form.Set("client_id", clientID)
	form.Set("client_secret", secret)

	resp, err := http.PostForm(srv.URL+"/oauth/token", form)
	if err != nil {
		t.Fatalf("POST /oauth/token: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var payload map[string]any
	json.Unmarshal(body, &payload)
	return resp, payload
}

func TestFullLoginFlow(t *testing.T) {
	srv, _ := newTestServer(t, successfulKeycloak())

	_, flowVal := performAuthorize(t, srv, "svc-a", "state-xyz")

	formBody := "client_id=school21&username=alice&password=hunter2&grant_type=password"
	resp := doLogin(t, srv, flowVal, formBody)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/login status = %d", resp.StatusCode)
	}
	code := extractCodeFromRedirect(t, resp, "state-xyz")

	tokenResp, payload := exchangeCode(t, srv, code, "svc-a", "secret-a")
	if tokenResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /oauth/token status = %d, body = %v", tokenResp.StatusCode, payload)
	}
	if payload["access_token"] != "at-123" {
		t.Errorf("access_token = %v", payload["access_token"])
	}
	if payload["refresh_token"] != "rt-456" {
		t.Errorf("refresh_token = %v", payload["refresh_token"])
	}
	if payload["token_type"] != "bearer" {
		t.Errorf("token_type = %v", payload["token_type"])
	}
	if v, _ := payload["expires_in"].(float64); v != 300 {
		t.Errorf("expires_in = %v", payload["expires_in"])
	}

	reuseResp, reusePayload := exchangeCode(t, srv, code, "svc-a", "secret-a")
	if reuseResp.StatusCode != http.StatusBadRequest {
		t.Errorf("code reuse status = %d, want 400", reuseResp.StatusCode)
	}
	if reusePayload["error"] != "invalid_grant" {
		t.Errorf("code reuse error = %v", reusePayload["error"])
	}
}

func TestAuthorizeUnknownClient(t *testing.T) {
	srv, _ := newTestServer(t, successfulKeycloak())
	resp, err := http.Get(srv.URL + "/authorize?client_id=unknown")
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAuthorizeWithoutClientID(t *testing.T) {
	srv, _ := newTestServer(t, successfulKeycloak())
	resp, err := http.Get(srv.URL + "/authorize")
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestLoginWithoutFlowCookie(t *testing.T) {
	srv, _ := newTestServer(t, successfulKeycloak())
	resp := doLogin(t, srv, "", "grant_type=password&username=a&password=b")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestLoginWithTamperedFlowCookie(t *testing.T) {
	srv, _ := newTestServer(t, successfulKeycloak())
	_, flowVal := performAuthorize(t, srv, "svc-a", "s1")

	tampered := flowVal[:len(flowVal)-1] + "x"
	resp := doLogin(t, srv, tampered, "grant_type=password&username=a&password=b")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestLoginKeycloakRejectsCredentials(t *testing.T) {
	srv, _ := newTestServer(t, failingKeycloak())
	_, flowVal := performAuthorize(t, srv, "svc-a", "s1")

	formBody := "client_id=school21&username=alice&password=wrong&grant_type=password"
	resp := doLogin(t, srv, flowVal, formBody)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"error":"invalid_grant"`) {
		t.Errorf("error passthrough missing: %s", body)
	}
	// The fatal anti-pattern would be echoing the submitted password back.
	if strings.Contains(string(body), "wrong") || strings.Contains(string(body), "alice") {
		t.Errorf("error response leaked credentials: %s", body)
	}
}

func TestLoginRequestBodyTooLarge(t *testing.T) {
	srv, _ := newTestServer(t, successfulKeycloak())
	_, flowVal := performAuthorize(t, srv, "svc-a", "s1")

	huge := strings.Repeat("p", broker.LoginBodyLimit+100)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/login", strings.NewReader("username=u&password="+huge))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: broker.FlowCookieName, Value: flowVal})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /api/login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", resp.StatusCode)
	}
}

func TestTokenExchangeRejectsWrongSecret(t *testing.T) {
	srv, _ := newTestServer(t, successfulKeycloak())
	_, flowVal := performAuthorize(t, srv, "svc-a", "s1")
	resp := doLogin(t, srv, flowVal, "grant_type=password&username=a&password=b")
	code := extractCodeFromRedirect(t, resp, "s1")

	badResp, payload := exchangeCode(t, srv, code, "svc-a", "wrong-secret")
	if badResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", badResp.StatusCode)
	}
	if payload["error"] != "invalid_client" {
		t.Errorf("error = %v", payload["error"])
	}

	// Wrong secret must NOT consume the code.
	goodResp, _ := exchangeCode(t, srv, code, "svc-a", "secret-a")
	if goodResp.StatusCode != http.StatusOK {
		t.Errorf("exchange with correct secret after failed attempt = %d, want 200", goodResp.StatusCode)
	}
}

func TestTokenExchangeMissingFields(t *testing.T) {
	srv, _ := newTestServer(t, successfulKeycloak())
	for _, form := range []string{
		"",
		"client_id=svc-a&client_secret=secret-a",
		"code=x&client_secret=secret-a",
		"code=x&client_id=svc-a",
	} {
		resp, err := http.PostForm(srv.URL+"/oauth/token", mustParseForm(t, form))
		if err != nil {
			t.Fatalf("POST /oauth/token (%q): %v", form, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("form %q status = %d, want 400", form, resp.StatusCode)
		}
	}
}

func TestLoginSetsSecureCookieAttrs(t *testing.T) {
	srv, _ := newTestServer(t, successfulKeycloak())
	// newTestServer uses SecureCookies=false; craft a secure one here via direct
	// broker check: verify HttpOnly, Path, SameSite on the Set-Cookie header.
	resp, _ := http.Get(srv.URL + "/authorize?client_id=svc-a&state=s1")
	resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.Name != broker.FlowCookieName {
			continue
		}
		if !c.HttpOnly {
			t.Error("cookie is not HttpOnly")
		}
		if c.Path != "/" {
			t.Errorf("cookie Path = %q", c.Path)
		}
		if c.SameSite != http.SameSiteLaxMode {
			t.Errorf("cookie SameSite = %v, want lax", c.SameSite)
		}
	}
	if len(resp.Cookies()) == 0 {
		t.Fatal("no cookies set")
	}
}

func mustParseForm(t *testing.T, s string) url.Values {
	t.Helper()
	v, err := url.ParseQuery(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return v
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestLoginPageCSPAllowsSameOriginFetch(t *testing.T) {
	srv, _ := newTestServer(t, successfulKeycloak())
	resp, err := http.Get(srv.URL + "/authorize?client_id=svc-a")
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()

	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("login page has no Content-Security-Policy header")
	}
	for _, directive := range []string{
		"default-src 'none'",
		"script-src 'self'",
		"connect-src 'self'",
	} {
		if !strings.Contains(csp, directive) {
			t.Errorf("CSP %q missing %q", csp, directive)
		}
	}
}
