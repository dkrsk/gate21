package registry

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"os"
)

type Client struct {
	ID          string `json:"id"`
	RedirectURI string `json:"redirect_uri,omitempty"`
	Secret      string `json:"secret"`
	Flow        string `json:"flow,omitempty"` // "web" (default) or "device"
}

const (
	FlowWeb    = "web"
	FlowDevice = "device"
)

func (c *Client) IsDevice() bool { return c.Flow == FlowDevice }

type file struct {
	Clients []Client `json:"clients"`
}

type Registry struct {
	byID map[string]*Client
}

func Load(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read clients file %q: %w", path, err)
	}

	var f file
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse clients file %q: %w", path, err)
	}

	r := &Registry{byID: make(map[string]*Client, len(f.Clients))}
	for i := range f.Clients {
		c := &f.Clients[i]
		if c.ID == "" {
			return nil, fmt.Errorf("client at index %d: id is required", i)
		}
		if c.Secret == "" {
			return nil, fmt.Errorf("client %q: secret is required", c.ID)
		}
		if c.Flow == "" {
			c.Flow = FlowWeb
		}
		switch c.Flow {
		case FlowWeb:
			if c.RedirectURI == "" {
				return nil, fmt.Errorf("client %q: redirect_uri is required for flow %q", c.ID, FlowWeb)
			}
		case FlowDevice:
			if c.RedirectURI != "" {
				return nil, fmt.Errorf("client %q: redirect_uri must not be set for flow %q", c.ID, FlowDevice)
			}
		default:
			return nil, fmt.Errorf("client %q: unknown flow %q (want %q or %q)", c.ID, c.Flow, FlowWeb, FlowDevice)
		}
		if _, dup := r.byID[c.ID]; dup {
			return nil, fmt.Errorf("duplicate client id %q", c.ID)
		}
		r.byID[c.ID] = c
	}

	return r, nil
}

func (r *Registry) Lookup(id string) (*Client, bool) {
	c, ok := r.byID[id]
	return c, ok
}

func (r *Registry) AllowedRedirect(id, uri string) bool {
	c, ok := r.byID[id]
	if !ok {
		return false
	}
	if c.RedirectURI == "" {
		return false
	}
	if len(uri) != len(c.RedirectURI) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(uri), []byte(c.RedirectURI)) == 1
}

func (r *Registry) VerifySecret(id, secret string) bool {
	c, ok := r.byID[id]
	if !ok || c.Secret == "" {
		return false
	}
	s, _ := []byte(secret), []byte(c.Secret)
	if len(s) != len(c.Secret) {
		return false
	}
	return subtle.ConstantTimeCompare(s, []byte(c.Secret)) == 1
}

func (r *Registry) Allowed(id string) bool {
	_, ok := r.byID[id]
	return ok
}

func (r *Registry) Len() int {
	return len(r.byID)
}
