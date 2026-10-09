package broker

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"gate21/src/app/proxy"
	"gate21/src/app/registry"
	webassets "gate21/src/app/web"
)

const (
	FlowCookieName = "authflow"
	LoginBodyLimit = 1 << 20

	DeviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"
)

type Broker struct {
	log        *log.Logger
	kc         *proxy.Keycloak
	reg        *registry.Registry
	signer     *FlowSigner
	codes      *CodeStore
	devices    *DeviceStore
	publicBase string
	pollEvery  time.Duration
	secureCook bool
}

type Options struct {
	Logger        *log.Logger
	Keycloak      *proxy.Keycloak
	Registry      *registry.Registry
	SignerKey     []byte
	FlowMaxAge    time.Duration
	CodeTTL       time.Duration
	DeviceTTL     time.Duration
	PollInterval  time.Duration
	PublicBase    string
	SecureCookies bool
}

func New(opts Options) (*Broker, error) {
	if opts.Logger == nil {
		opts.Logger = log.Default()
	}
	if opts.Keycloak == nil || opts.Registry == nil {
		return nil, fmt.Errorf("broker: keycloak and registry are required")
	}
	if len(opts.SignerKey) == 0 {
		return nil, fmt.Errorf("broker: signer key is required")
	}
	if opts.FlowMaxAge <= 0 {
		opts.FlowMaxAge = 5 * time.Minute
	}
	if opts.CodeTTL <= 0 {
		opts.CodeTTL = 2 * time.Minute
	}
	if opts.DeviceTTL <= 0 {
		opts.DeviceTTL = 5 * time.Minute
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = 5 * time.Second
	}

	return &Broker{
		log:        opts.Logger,
		kc:         opts.Keycloak,
		reg:        opts.Registry,
		signer:     NewFlowSigner(opts.SignerKey, opts.FlowMaxAge),
		codes:      NewCodeStore(opts.CodeTTL),
		devices:    NewDeviceStore(opts.DeviceTTL, opts.PollInterval),
		publicBase: strings.TrimRight(opts.PublicBase, "/"),
		pollEvery:  opts.PollInterval,
		secureCook: opts.SecureCookies,
	}, nil
}

func (b *Broker) Close() {
	b.codes.Close()
	b.devices.Close()
}

func (b *Broker) Routes() http.Handler {
	mux := http.NewServeMux()

	assets, err := fs.Sub(webassets.FS, ".")
	if err != nil {
		panic(fmt.Sprintf("broker: embed web assets: %v", err))
	}
	assetServer := http.FileServerFS(assets)

	mux.Handle("GET /app.js", assetServer)
	mux.Handle("GET /style.css", assetServer)
	mux.Handle("GET /favicon.svg", assetServer)
	mux.HandleFunc("GET /{$}", b.handleLanding)
	mux.HandleFunc("GET /authorize", b.handleAuthorize)
	mux.HandleFunc("GET /device", b.handleDevicePage)
	mux.HandleFunc("POST /api/login", b.handleAPILogin)
	mux.HandleFunc("POST /oauth/device", b.handleDeviceStart)
	mux.HandleFunc("POST /oauth/token", b.handleToken)

	return mux
}

func (b *Broker) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	client, ok := b.reg.Lookup(clientID)
	if !ok {
		b.writeText(w, http.StatusBadRequest, "unknown client_id\n")
		return
	}
	if client.IsDevice() {
		b.writeText(w, http.StatusBadRequest, "client uses device flow\n")
		return
	}
	state := r.URL.Query().Get("state")

	value, err := b.signer.Issue(FlowKindWeb, clientID, state)
	if err != nil {
		b.log.Printf("authorize: issue flow cookie: %v", err)
		b.writeText(w, http.StatusInternalServerError, "internal error\n")
		return
	}

	b.setFlowCookie(w, value, int(b.signer.maxAge.Seconds()))
	b.serveIndex(w)
}

// handleDeviceStart issues a device authorization session for clients that
// cannot receive a browser callback (e.g. Telegram bots behind NAT).
func (b *Broker) handleDeviceStart(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		b.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	clientID := r.PostForm.Get("client_id")
	clientSecret := r.PostForm.Get("client_secret")
	if clientID == "" || clientSecret == "" {
		b.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if !b.reg.VerifySecret(clientID, clientSecret) {
		b.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	client, _ := b.reg.Lookup(clientID)
	if !client.IsDevice() {
		b.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
		return
	}
	if b.publicBase == "" {
		b.log.Printf("oauth/device: AUTH_PUBLIC_BASE is not configured")
		b.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	deviceCode, userCode, expiresAt, err := b.devices.Create(clientID)
	if err != nil {
		b.log.Printf("oauth/device: create session: %v", err)
		b.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	verificationURL := b.publicBase + "/device?uc=" + url.QueryEscape(userCode)
	b.writeJSON(w, http.StatusOK, map[string]any{
		"device_code":      deviceCode,
		"user_code":        userCode,
		"verification_url": verificationURL,
		"expires_in":       secondsUntil(expiresAt),
		"interval":         secondsOf(b.pollEvery),
	})
}

// handleDevicePage serves the login page for a device session created by a bot.
func (b *Broker) handleDevicePage(w http.ResponseWriter, r *http.Request) {
	userCode := r.URL.Query().Get("uc")
	if userCode == "" {
		b.writeText(w, http.StatusBadRequest, "missing user code\n")
		return
	}

	_, clientID, ok := b.devices.SessionByUserCode(userCode)
	if !ok {
		b.writeText(w, http.StatusBadRequest, "link is expired or invalid\n")
		return
	}
	client, ok := b.reg.Lookup(clientID)
	if !ok || !client.IsDevice() {
		b.writeText(w, http.StatusBadRequest, "link is expired or invalid\n")
		return
	}

	value, err := b.signer.Issue(FlowKindDevice, clientID, userCode)
	if err != nil {
		b.log.Printf("device: issue flow cookie: %v", err)
		b.writeText(w, http.StatusInternalServerError, "internal error\n")
		return
	}

	b.setFlowCookie(w, value, int(b.signer.maxAge.Seconds()))
	b.serveIndex(w)
}

func (b *Broker) handleAPILogin(w http.ResponseWriter, r *http.Request) {
	claim, err := b.readFlowCookie(r)
	if err != nil {
		b.writeText(w, http.StatusUnauthorized, "no active authorization flow\n")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, LoginBodyLimit+1))
	if err != nil {
		b.writeText(w, http.StatusBadRequest, "failed to read request body\n")
		return
	}
	if int64(len(body)) > LoginBodyLimit {
		b.writeText(w, http.StatusRequestEntityTooLarge, "request body too large\n")
		return
	}

	kcResp, err := b.kc.Login(r.Context(), body)
	if err != nil {
		b.log.Printf("api/login: keycloak call failed: %v", err)
		b.writeText(w, http.StatusBadGateway, "upstream authentication service unavailable\n")
		return
	}

	if kcResp.StatusCode != http.StatusOK {
		b.log.Printf("api/login: keycloak returned %d", kcResp.StatusCode)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(kcResp.StatusCode)
		w.Write(kcResp.Body)
		return
	}

	var tr proxy.TokenResponse
	if err := json.Unmarshal(kcResp.Body, &tr); err != nil {
		b.log.Printf("api/login: parse keycloak response: %v", err)
		b.writeText(w, http.StatusBadGateway, "malformed response from upstream\n")
		return
	}
	if tr.AccessToken == "" {
		b.log.Printf("api/login: upstream response missing access_token")
		b.writeText(w, http.StatusBadGateway, "malformed response from upstream\n")
		return
	}

	grant := Grant{
		ClientID:     claim.ClientID,
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		ExpiresIn:    tr.ExpiresIn,
		Scope:        tr.Scope,
	}

	if claim.Kind == FlowKindDevice {
		if !b.devices.Complete(claim.State, claim.ClientID, grant) {
			b.log.Printf("api/login: device session %q not completable", claim.ClientID)
			b.writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "session_expired",
				"error_description": "authorization session expired, start again from the bot link",
			})
			return
		}
		b.setFlowCookie(w, "", -1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"done": true})
		return
	}

	code, err := b.codes.Mint(grant)
	if err != nil {
		b.log.Printf("api/login: mint code: %v", err)
		b.writeText(w, http.StatusInternalServerError, "internal error\n")
		return
	}

	redirect, err := b.redirectFor(claim.ClientID, claim.State, code)
	if err != nil {
		b.log.Printf("api/login: build redirect: %v", err)
		b.writeText(w, http.StatusInternalServerError, "internal error\n")
		return
	}

	b.setFlowCookie(w, "", -1)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"redirect": redirect})
}

func (b *Broker) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		b.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}

	switch grantType := r.PostForm.Get("grant_type"); grantType {
	case "":
		b.exchangeCode(w, r)
	case "device_code", DeviceGrantType:
		b.pollDevice(w, r)
	default:
		b.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
	}
}

func (b *Broker) exchangeCode(w http.ResponseWriter, r *http.Request) {
	code := r.PostForm.Get("code")
	clientID := r.PostForm.Get("client_id")
	clientSecret := r.PostForm.Get("client_secret")

	if code == "" || clientID == "" || clientSecret == "" {
		b.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if !b.reg.VerifySecret(clientID, clientSecret) {
		b.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}

	grant, ok := b.codes.Exchange(code, clientID)
	if !ok {
		b.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant",
			"error_description": "code is invalid, expired or already used"})
		return
	}

	b.writeGrant(w, grant)
}

func (b *Broker) pollDevice(w http.ResponseWriter, r *http.Request) {
	deviceCode := r.PostForm.Get("device_code")
	clientID := r.PostForm.Get("client_id")
	clientSecret := r.PostForm.Get("client_secret")

	if deviceCode == "" || clientID == "" || clientSecret == "" {
		b.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if !b.reg.VerifySecret(clientID, clientSecret) {
		b.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}

	res, grant := b.devices.Poll(deviceCode, clientID)
	switch res {
	case PollSuccess:
		b.writeGrant(w, grant)
	case PollPending:
		b.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "authorization_pending"})
	case PollSlowDown:
		b.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "slow_down"})
	default:
		b.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
	}
}

func (b *Broker) writeGrant(w http.ResponseWriter, grant Grant) {
	resp := map[string]any{
		"access_token":  grant.AccessToken,
		"refresh_token": grant.RefreshToken,
		"token_type":    "bearer",
	}
	if grant.ExpiresIn > 0 {
		resp["expires_in"] = grant.ExpiresIn
	}
	if grant.Scope != "" {
		resp["scope"] = grant.Scope
	}
	b.writeJSON(w, http.StatusOK, resp)
}

func (b *Broker) redirectFor(clientID, state, code string) (string, error) {
	client, ok := b.reg.Lookup(clientID)
	if !ok {
		return "", fmt.Errorf("client %q not in registry", clientID)
	}
	u, err := url.Parse(client.RedirectURI)
	if err != nil {
		return "", fmt.Errorf("parse redirect uri: %w", err)
	}
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (b *Broker) readFlowCookie(r *http.Request) (FlowClaim, error) {
	cookie, err := r.Cookie(FlowCookieName)
	if err != nil {
		return FlowClaim{}, err
	}
	return b.signer.Verify(cookie.Value)
}

func (b *Broker) setFlowCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     FlowCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   b.secureCook,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

// handleLanding serves a static stub at the site root explaining what the
// service is; the login page itself is only served by the authorize/device flows.
func (b *Broker) handleLanding(w http.ResponseWriter, _ *http.Request) {
	b.serveHTML(w, "index.html")
}

func (b *Broker) serveIndex(w http.ResponseWriter) {
	b.serveHTML(w, "login.html")
}

func (b *Broker) serveHTML(w http.ResponseWriter, name string) {
	data, err := fs.ReadFile(webassets.FS, name)
	if err != nil {
		b.log.Printf("serve %s: %v", name, err)
		b.writeText(w, http.StatusInternalServerError, "internal error\n")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.Write(data)
}

func (b *Broker) writeText(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	w.Write([]byte(msg))
}

func (b *Broker) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func secondsUntil(t time.Time) int {
	d := time.Until(t)
	if d < 0 {
		return 0
	}
	return int(d / time.Second)
}

func secondsOf(d time.Duration) int {
	if d <= 0 {
		return 1
	}
	return int((d + time.Second - 1) / time.Second)
}
