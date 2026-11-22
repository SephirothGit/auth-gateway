package config

import (
	"errors"
	"fmt"
	"time"

	"github.com/caarlos0/env/v11"
)

type Gateway struct {
	HTTPAddr      string        `env:"HTTP_ADDR" envDefault":8080"`
	DatabaseURL   string        `env:"DATABASE_URL,required,notEmpty"`
	RedisAddr     string        `env:"REDIS_ADDR,required,notEmpty"`
	RedisPassword string        `env:"REDIS_PASSWORD"`
	TokenSvcAddr  string        `env:"TOKENSVC_ADDR,required,notEmpty"`
	CookieSecure  bool          `env:"COOKIE_SECURE" envDefault:"true"`
	SessionTTL    time.Duration `env:"SESSION_TTL" envDefault:"24h"`
	SessionMaxAge time.Duration `env:"SESSION_MAX_AGE" envDefault:"720h"`

	GitHubClientID     string `env:"GITHUB_CLIENT_ID"`
	GitHubClientSecret string `env:"GITHUB_CLIENT_SECRET"`
	GitHubRedirectURL  string `env:"GITHUB_REDIRECT_URL"`
}

func (c *Gateway) GitHubEnabled() bool {
	return c.GitHubClientID != "" && c.GitHubClientSecret != ""
}

func LoadGateway() (*Gateway, error) {
	var c Gateway
	if err := env.ParseWithOptions(&c, env.Options{Prefix: "GATEWAY_"}); err != nil {
		return nil, fmt.Errorf("parse gateway config %w", err)
	}
	return &c, nil
}

type TokenSvc struct {
	GRPCAddr       string        `env:"GRPC_ADDR" envDefault:":9090"`
	DatabaseURL    string        `env:"DATABASE_URL,required,notEmpty"`
	SigningKeyPath string        `env:"SIGNING_KEY_PATH,required,notEmpty"`
	Issuer         string        `env:"ISSUER" envDefault:"auth-gateway"`
	Audience       string        `env:"AUDIENCE" envDefault:"auth-gateway-api"`
	AccessTTL      time.Duration `env:"ACCESS_TTL" envDefault:"10m"`
	RefreshTTL     time.Duration `env:"REFRESH_TTL" envDefault:"720h"`
}

func LoadTokenSvc() (*TokenSvc, error) {
	var c TokenSvc
	if err := env.ParseWithOptions(&c, env.Options{Prefix: "TOKENSVC_"}); err != nil {
		return nil, fmt.Errorf("parse tokensvc config %w", err)
	}

	if c.AccessTTL <= 0 || c.RefreshTTL <= c.AccessTTL {
		return nil, errors.New("tokensvc config: need 0 < ACCESS_TTL < REFRESH_TTL")
	}
	return &c, nil
}
