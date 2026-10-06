package broker_test

import (
	"encoding/json"
	"gate21/src/app/broker"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func deviceStart(t *testing.T, srv *httptest.Server, clientID, secret string) (*http.Response, map[string]any) {
	t.Helper()
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("client_secret", secret)
	resp, err := http.PostForm(srv.URL+"/oauth/device", form)
	if err != nil {
		t.Fatalf("POST /oauth/device: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var payload map[string]any
	json.Unmarshal(body, &payload)
	return resp, payload
}

func devicePoll(t *testing.T, srv *httptest.Server, deviceCode, clientID, secret string) (*http.Response, map[string]any) {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", broker.DeviceGrantType)
	form.Set("device_code", deviceCode)
	form.Set("client_id", clientID)
	form.Set("client_secret", secret)
	resp, err := http.PostForm(srv.URL+"/oauth/token", form)
	if err != nil {
		t.Fatalf("POST /oauth/token (device): %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var payload map[string]any
	json.Unmarshal(body, &payload)
	return resp, payload
}

func TestDeviceFlowFull(t *testing.T) {
	srv, _ := newTestServer(t, successfulKeycloak())

	// 1. Bot starts the session.
	resp, payload := deviceStart(t, srv, "bot-a", "secret-bot")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /oauth/device status = %d, body = %v", resp.StatusCode, payload)
	}
	deviceCode, _ := payload["device_code"].(string)
	verificationURL, _ := payload["verification_url"].(string)
	if deviceCode == "" || verificationURL == "" {
		t.Fatalf("start response = %v", payload)
	}
	if expires, _ := payload["expires_in"].(float64); expires <= 0 {
		t.Errorf("expires_in = %v", payload["expires_in"])
	}
	if interval, _ := payload["interval"].(float64); interval < 1 {
		t.Errorf("interval = %v, want >= 1", payload["interval"])
	}
	u, err := url.Parse(verificationURL)
	if err != nil {
		t.Fatalf("parse verification_url: %v", err)
	}
	if u.Path != "/device" {
		t.Errorf("verification_url path = %q, want /device", u.Path)
	}
	userCode := u.Query().Get("uc")
	if userCode == "" {
		t.Fatalf("verification_url has no uc: %q", verificationURL)
	}

	// 2. User opens the verification URL.
	pageResp, err := http.Get(srv.URL + "/device?uc=" + url.QueryEscape(userCode))
	if err != nil {
		t.Fatalf("GET /device: %v", err)
	}
	pageBody, _ := io.ReadAll(pageResp.Body)
	pageResp.Body.Close()
	if pageResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /device status = %d, body = %s", pageResp.StatusCode, pageBody)
	}
	if !strings.Contains(string(pageBody), "login-form") {
		t.Fatalf("GET /device did not serve login page: %s", pageBody)
	}
	var flowVal string
	for _, c := range pageResp.Cookies() {
		if c.Name == broker.FlowCookieName {
			flowVal = c.Value
		}
	}
	if flowVal == "" {
		t.Fatal("GET /device did not set authflow cookie")
	}

	// 3. User logs in; tokens complete the device session (no redirect).
	loginResp := doLogin(t, srv, flowVal,
		"client_id=school21&username=alice&password=hunter2&grant_type=password")
	loginBody, _ := io.ReadAll(loginResp.Body)
	loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/login status = %d, body = %s", loginResp.StatusCode, loginBody)
	}
	var loginPayload map[string]any
	json.Unmarshal(loginBody, &loginPayload)
	if loginPayload["done"] != true {
		t.Errorf("POST /api/login = %v, want {done: true}", loginPayload)
	}
	if _, hasRedirect := loginPayload["redirect"]; hasRedirect {
		t.Errorf("device login must not return redirect: %v", loginPayload)
	}

	// 4. Bot polls for the tokens.
	pollResp, pollPayload := devicePoll(t, srv, deviceCode, "bot-a", "secret-bot")
	if pollResp.StatusCode != http.StatusOK {
		t.Fatalf("poll status = %d, body = %v", pollResp.StatusCode, pollPayload)
	}
	if pollPayload["access_token"] != "at-123" || pollPayload["refresh_token"] != "rt-456" {
		t.Errorf("poll payload = %v", pollPayload)
	}

	// 5. The grant is single-use.
	reuseResp, reusePayload := devicePoll(t, srv, deviceCode, "bot-a", "secret-bot")
	if reuseResp.StatusCode != http.StatusBadRequest || reusePayload["error"] != "invalid_grant" {
		t.Errorf("reuse poll = %d/%v, want 400/invalid_grant", reuseResp.StatusCode, reusePayload["error"])
	}
}

func TestDevicePollPendingThenSlowDown(t *testing.T) {
	srv, _ := newTestServer(t, successfulKeycloak())

	_, payload := deviceStart(t, srv, "bot-a", "secret-bot")
	deviceCode, _ := payload["device_code"].(string)

	resp, pollPayload := devicePoll(t, srv, deviceCode, "bot-a", "secret-bot")
	if resp.StatusCode != http.StatusBadRequest || pollPayload["error"] != "authorization_pending" {
		t.Fatalf("first poll = %d/%v, want 400/authorization_pending", resp.StatusCode, pollPayload["error"])
	}
	resp, pollPayload = devicePoll(t, srv, deviceCode, "bot-a", "secret-bot")
	if resp.StatusCode != http.StatusBadRequest || pollPayload["error"] != "slow_down" {
		t.Fatalf("second poll = %d/%v, want 400/slow_down", resp.StatusCode, pollPayload["error"])
	}
}

func TestDeviceStartAuthFailures(t *testing.T) {
	srv, _ := newTestServer(t, successfulKeycloak())

	resp, payload := deviceStart(t, srv, "bot-a", "wrong-secret")
	if resp.StatusCode != http.StatusUnauthorized || payload["error"] != "invalid_client" {
		t.Errorf("bad secret = %d/%v, want 401/invalid_client", resp.StatusCode, payload["error"])
	}

	resp, payload = deviceStart(t, srv, "bot-a", "")
	if resp.StatusCode != http.StatusBadRequest || payload["error"] != "invalid_request" {
		t.Errorf("missing secret = %d/%v, want 400/invalid_request", resp.StatusCode, payload["error"])
	}

	// Web clients cannot use the device endpoint.
	resp, payload = deviceStart(t, srv, "svc-a", "secret-a")
	if resp.StatusCode != http.StatusBadRequest || payload["error"] != "unsupported_grant_type" {
		t.Errorf("web client = %d/%v, want 400/unsupported_grant_type", resp.StatusCode, payload["error"])
	}
}

func TestDeviceAuthorizeRejectsDeviceClient(t *testing.T) {
	srv, _ := newTestServer(t, successfulKeycloak())
	resp, err := http.Get(srv.URL + "/authorize?client_id=bot-a")
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestDevicePageInvalidUserCode(t *testing.T) {
	srv, _ := newTestServer(t, successfulKeycloak())

	for _, u := range []string{"/device", "/device?uc=nope"} {
		resp, err := http.Get(srv.URL + u)
		if err != nil {
			t.Fatalf("GET %s: %v", u, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("GET %s status = %d, want 400", u, resp.StatusCode)
		}
	}
}

func TestDevicePollAuthFailures(t *testing.T) {
	srv, _ := newTestServer(t, successfulKeycloak())

	resp, payload := devicePoll(t, srv, "unknown-code", "bot-a", "secret-bot")
	if resp.StatusCode != http.StatusBadRequest || payload["error"] != "invalid_grant" {
		t.Errorf("unknown code = %d/%v, want 400/invalid_grant", resp.StatusCode, payload["error"])
	}
	resp, payload = devicePoll(t, srv, "some-code", "bot-a", "wrong-secret")
	if resp.StatusCode != http.StatusUnauthorized || payload["error"] != "invalid_client" {
		t.Errorf("bad secret = %d/%v, want 401/invalid_client", resp.StatusCode, payload["error"])
	}
}

func TestDeviceUnsupportedGrantType(t *testing.T) {
	srv, _ := newTestServer(t, successfulKeycloak())
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", "bot-a")
	form.Set("client_secret", "secret-bot")
	resp, err := http.PostForm(srv.URL+"/oauth/token", form)
	if err != nil {
		t.Fatalf("POST /oauth/token: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "unsupported_grant_type") {
		t.Errorf("status = %d, body = %s", resp.StatusCode, body)
	}
}

func TestDeviceLoginAfterSessionExpired(t *testing.T) {
	srv, _ := newTestServerWith(t, successfulKeycloak(), func(o *broker.Options) {
		o.DeviceTTL = 300 * time.Millisecond
	})

	_, payload := deviceStart(t, srv, "bot-a", "secret-bot")
	userCode, _ := payload["user_code"].(string)
	if userCode == "" {
		t.Fatalf("start response = %v", payload)
	}

	pageResp, err := http.Get(srv.URL + "/device?uc=" + url.QueryEscape(userCode))
	if err != nil {
		t.Fatalf("GET /device: %v", err)
	}
	io.Copy(io.Discard, pageResp.Body)
	pageResp.Body.Close()
	var flowVal string
	for _, c := range pageResp.Cookies() {
		if c.Name == broker.FlowCookieName {
			flowVal = c.Value
		}
	}
	if flowVal == "" {
		t.Fatal("GET /device did not set authflow cookie")
	}

	time.Sleep(400 * time.Millisecond)

	loginResp := doLogin(t, srv, flowVal, "grant_type=password&username=a&password=b")
	defer loginResp.Body.Close()
	body, _ := io.ReadAll(loginResp.Body)
	if loginResp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", loginResp.StatusCode)
	}
	if !strings.Contains(string(body), "session_expired") {
		t.Errorf("body = %s, want session_expired", body)
	}
}
