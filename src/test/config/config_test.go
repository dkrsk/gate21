package config_test

import (
	"gate21/src/app/config"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("AUTH_COOKIE_KEY", "0123456789abcdef")
	for _, k := range []string{
		"AUTH_LISTEN_ADDR", "AUTH_KEYCLOAK_BASE", "AUTH_KEYCLOAK_REALM",
		"AUTH_CLIENTS_PATH", "AUTH_CODE_TTL", "AUTH_FLOW_MAX_AGE", "AUTH_HTTP_TIMEOUT",
		"AUTH_COOKIE_SECURE", "AUTH_PUBLIC_BASE", "AUTH_DEVICE_TTL", "AUTH_POLL_INTERVAL",
	} {
		t.Setenv(k, "")
	}

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}

	if cfg.ListenAddr != ":8080" {
		t.Errorf("ListenAddr = %q, want :8080", cfg.ListenAddr)
	}
	if cfg.KeycloakBase != "https://auth.21-school.ru" {
		t.Errorf("KeycloakBase = %q", cfg.KeycloakBase)
	}
	if cfg.KeycloakRealm != "EduPowerKeycloak" {
		t.Errorf("KeycloakRealm = %q", cfg.KeycloakRealm)
	}
	if cfg.ClientsPath != "clients.json" {
		t.Errorf("ClientsPath = %q", cfg.ClientsPath)
	}
	if cfg.CodeTTL != 120*time.Second {
		t.Errorf("CodeTTL = %v", cfg.CodeTTL)
	}
	if cfg.FlowMaxAge != 5*time.Minute {
		t.Errorf("FlowMaxAge = %v", cfg.FlowMaxAge)
	}
	if cfg.HTTPTimeout != 10*time.Second {
		t.Errorf("HTTPTimeout = %v", cfg.HTTPTimeout)
	}
	if !cfg.SecureCookies {
		t.Error("SecureCookies = false, want true by default")
	}
}

func TestLoadOverrides(t *testing.T) {
	t.Setenv("AUTH_COOKIE_KEY", "0123456789abcdef")
	t.Setenv("AUTH_LISTEN_ADDR", ":9090")
	t.Setenv("AUTH_KEYCLOAK_BASE", "https://kc.example.com")
	t.Setenv("AUTH_KEYCLOAK_REALM", "realmA")
	t.Setenv("AUTH_CLIENTS_PATH", "/etc/clients.json")
	t.Setenv("AUTH_CODE_TTL", "1m30s")
	t.Setenv("AUTH_HTTP_TIMEOUT", "3s")
	t.Setenv("AUTH_COOKIE_SECURE", "false")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}

	if cfg.ListenAddr != ":9090" {
		t.Errorf("ListenAddr = %q", cfg.ListenAddr)
	}
	if cfg.KeycloakBase != "https://kc.example.com" {
		t.Errorf("KeycloakBase = %q", cfg.KeycloakBase)
	}
	if cfg.KeycloakRealm != "realmA" {
		t.Errorf("KeycloakRealm = %q", cfg.KeycloakRealm)
	}
	if cfg.CodeTTL != 90*time.Second {
		t.Errorf("CodeTTL = %v", cfg.CodeTTL)
	}
	if cfg.HTTPTimeout != 3*time.Second {
		t.Errorf("HTTPTimeout = %v", cfg.HTTPTimeout)
	}
	if cfg.SecureCookies {
		t.Error("SecureCookies = true, want false (overridden)")
	}
}

func TestLoadDeviceDefaults(t *testing.T) {
	t.Setenv("AUTH_COOKIE_KEY", "0123456789abcdef")
	t.Setenv("AUTH_PUBLIC_BASE", "")
	t.Setenv("AUTH_DEVICE_TTL", "")
	t.Setenv("AUTH_POLL_INTERVAL", "")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	if cfg.PublicBase != "" {
		t.Errorf("PublicBase = %q, want empty", cfg.PublicBase)
	}
	if cfg.DeviceTTL != 5*time.Minute {
		t.Errorf("DeviceTTL = %v, want 5m", cfg.DeviceTTL)
	}
	if cfg.PollInterval != 5*time.Second {
		t.Errorf("PollInterval = %v, want 5s", cfg.PollInterval)
	}
}

func TestLoadDeviceOverrides(t *testing.T) {
	t.Setenv("AUTH_COOKIE_KEY", "0123456789abcdef")
	t.Setenv("AUTH_PUBLIC_BASE", "https://auth.example.com")
	t.Setenv("AUTH_DEVICE_TTL", "10m")
	t.Setenv("AUTH_POLL_INTERVAL", "3s")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	if cfg.PublicBase != "https://auth.example.com" {
		t.Errorf("PublicBase = %q", cfg.PublicBase)
	}
	if cfg.DeviceTTL != 10*time.Minute {
		t.Errorf("DeviceTTL = %v", cfg.DeviceTTL)
	}
	if cfg.PollInterval != 3*time.Second {
		t.Errorf("PollInterval = %v", cfg.PollInterval)
	}
}

func TestLoadInvalidPublicBase(t *testing.T) {
	t.Setenv("AUTH_COOKIE_KEY", "0123456789abcdef")
	for _, bad := range []string{"not-a-url", "ftp://x.example.com", "//no-scheme", "https://"} {
		t.Setenv("AUTH_PUBLIC_BASE", bad)
		if _, err := config.Load(); err == nil {
			t.Errorf("config.Load() with PublicBase %q expected error", bad)
		}
	}
}

func TestLoadNonPositiveDeviceDurationsRejected(t *testing.T) {
	t.Setenv("AUTH_COOKIE_KEY", "0123456789abcdef")
	t.Setenv("AUTH_DEVICE_TTL", "0s")
	if _, err := config.Load(); err == nil {
		t.Error("config.Load() expected error for zero device TTL")
	}
	t.Setenv("AUTH_DEVICE_TTL", "5m")
	t.Setenv("AUTH_POLL_INTERVAL", "-1s")
	if _, err := config.Load(); err == nil {
		t.Error("config.Load() expected error for negative poll interval")
	}
}

func TestLoadRequiresCookieKey(t *testing.T) {
	t.Setenv("AUTH_COOKIE_KEY", "")
	_, err := config.Load()
	if err == nil {
		t.Fatal("config.Load() expected error without cookie key")
	}
}

func TestLoadRequiresMinCookieKeyLength(t *testing.T) {
	t.Setenv("AUTH_COOKIE_KEY", "short")
	_, err := config.Load()
	if err == nil {
		t.Fatal("config.Load() expected error for short cookie key")
	}
}

func TestLoadInvalidDurationFallsBackToDefault(t *testing.T) {
	t.Setenv("AUTH_COOKIE_KEY", "0123456789abcdef")
	t.Setenv("AUTH_CODE_TTL", "not-a-duration")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	if cfg.CodeTTL != 120*time.Second {
		t.Errorf("CodeTTL = %v, want default", cfg.CodeTTL)
	}
}
