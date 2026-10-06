package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type LoginResponse struct {
	StatusCode int
	Body       []byte
}

type Keycloak struct {
	tokenURL string
	client   *http.Client
}

func New(base, realm string, timeout time.Duration) (*Keycloak, error) {
	if base == "" || realm == "" {
		return nil, fmt.Errorf("keycloak base and realm are required")
	}
	u, err := url.JoinPath(base, "/auth/realms/", realm, "/protocol/openid-connect/token")
	if err != nil {
		return nil, fmt.Errorf("build token endpoint: %w", err)
	}

	return &Keycloak{
		tokenURL: u,
		client: &http.Client{
			Timeout: timeout,
		},
	}, nil
}

func (k *Keycloak) TokenURL() string { return k.tokenURL }

// Login forwards the raw form body to the Keycloak token endpoint without
// parsing or rebuilding it. The caller is responsible for deciding how to
// interpret the status code; the body is returned verbatim.
func (k *Keycloak) Login(ctx context.Context, formBody []byte) (LoginResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, k.tokenURL, bytes.NewReader(formBody))
	if err != nil {
		return LoginResponse{}, fmt.Errorf("build login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := k.client.Do(req)
	if err != nil {
		return LoginResponse{}, fmt.Errorf("call keycloak: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return LoginResponse{}, fmt.Errorf("read keycloak response: %w", err)
	}

	return LoginResponse{StatusCode: resp.StatusCode, Body: body}, nil
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
}

type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}
