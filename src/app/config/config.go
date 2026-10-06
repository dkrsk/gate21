package config

import (
	"fmt"
	"net/url"
	"os"
	"time"
)

type Config struct {
	ListenAddr    string
	KeycloakBase  string
	KeycloakRealm string
	CookieKey     string
	ClientsPath   string
	PublicBase    string
	CodeTTL       time.Duration
	FlowMaxAge    time.Duration
	HTTPTimeout   time.Duration
	DeviceTTL     time.Duration
	PollInterval  time.Duration
	SecureCookies bool
}

func Load() (Config, error) {
	cfg := Config{
		ListenAddr:    env("AUTH_LISTEN_ADDR", ":8080"),
		KeycloakBase:  env("AUTH_KEYCLOAK_BASE", "https://auth.21-school.ru"),
		KeycloakRealm: env("AUTH_KEYCLOAK_REALM", "EduPowerKeycloak"),
		CookieKey:     env("AUTH_COOKIE_KEY", ""),
		ClientsPath:   env("AUTH_CLIENTS_PATH", "clients.json"),
		PublicBase:    env("AUTH_PUBLIC_BASE", ""),
		CodeTTL:       durationEnv("AUTH_CODE_TTL", 120*time.Second),
		FlowMaxAge:    durationEnv("AUTH_FLOW_MAX_AGE", 5*time.Minute),
		HTTPTimeout:   durationEnv("AUTH_HTTP_TIMEOUT", 10*time.Second),
		DeviceTTL:     durationEnv("AUTH_DEVICE_TTL", 5*time.Minute),
		PollInterval:  durationEnv("AUTH_POLL_INTERVAL", 5*time.Second),
		SecureCookies: boolEnv("AUTH_COOKIE_SECURE", true),
	}

	if cfg.CookieKey == "" {
		return Config{}, fmt.Errorf("AUTH_COOKIE_KEY is required: used to sign flow cookies")
	}
	if len(cfg.CookieKey) < 16 {
		return Config{}, fmt.Errorf("AUTH_COOKIE_KEY must be at least 16 bytes")
	}
	if cfg.ListenAddr == "" || cfg.KeycloakBase == "" || cfg.KeycloakRealm == "" {
		return Config{}, fmt.Errorf("listen addr, keycloak base and realm must not be empty")
	}
	if cfg.DeviceTTL <= 0 {
		return Config{}, fmt.Errorf("AUTH_DEVICE_TTL must be positive")
	}
	if cfg.PollInterval <= 0 {
		return Config{}, fmt.Errorf("AUTH_POLL_INTERVAL must be positive")
	}
	if cfg.PublicBase != "" {
		u, err := url.Parse(cfg.PublicBase)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return Config{}, fmt.Errorf("AUTH_PUBLIC_BASE must be an absolute http(s) URL, got %q", cfg.PublicBase)
		}
	}

	return cfg, nil
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func durationEnv(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

func boolEnv(key string, def bool) bool {
	v := os.Getenv(key)
	switch v {
	case "1", "true", "TRUE", "True", "yes", "on":
		return true
	case "0", "false", "FALSE", "False", "no", "off":
		return false
	default:
		return def
	}
}
