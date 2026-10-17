package googleoauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultAuthorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth"
	defaultTokenEndpoint         = "https://oauth2.googleapis.com/token"
	defaultUserinfoEndpoint      = "https://openidconnect.googleapis.com/v1/userinfo"
	defaultRevokeEndpoint        = "https://oauth2.googleapis.com/revoke"
)

type Config struct {
	ClientID              string
	ClientSecret          string
	RedirectURL           string
	AuthorizationEndpoint string
	TokenEndpoint         string
	UserinfoEndpoint      string
	RevokeEndpoint        string
	HTTPClient            *http.Client
	Now                   func() time.Time
}

type Client struct {
	cfg  Config
	http *http.Client
}

type TokenSet struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	Scopes       []string
	Expiry       time.Time
}


type EndpointError struct {
	StatusCode int
	Code string
}

func (e *EndpointError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("google token endpoint returned %s (status %d)", e.Code, e.StatusCode)
	}
	return fmt.Sprintf("google token endpoint returned status %d", e.StatusCode)
}

func IsErrorCode(err error, code string) bool {
	var endpointErr *EndpointError
	return errors.As(err, &endpointErr) && endpointErr.Code == code
}

type Identity struct {
	Subject, Email, Name string
	EmailVerified        bool
}

func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.ClientID) == "" || strings.TrimSpace(cfg.ClientSecret) == "" || strings.TrimSpace(cfg.RedirectURL) == "" {
		return nil, errors.New("google oauth client id, secret, and redirect url are required")
	}
	cfg.AuthorizationEndpoint = first(cfg.AuthorizationEndpoint, defaultAuthorizationEndpoint)
	cfg.TokenEndpoint = first(cfg.TokenEndpoint, defaultTokenEndpoint)
	cfg.UserinfoEndpoint = first(cfg.UserinfoEndpoint, defaultUserinfoEndpoint)
	cfg.RevokeEndpoint = first(cfg.RevokeEndpoint, defaultRevokeEndpoint)
	if err := validateEndpoint("redirect url", cfg.RedirectURL, true); err != nil {
		return nil, err
	}
	for label, endpoint := range map[string]string{"authorization endpoint": cfg.AuthorizationEndpoint, "token endpoint": cfg.TokenEndpoint, "userinfo endpoint": cfg.UserinfoEndpoint, "revoke endpoint": cfg.RevokeEndpoint} {
		if err := validateEndpoint(label, endpoint, false); err != nil {
			return nil, err
		}
	}
	hc := &http.Client{Timeout: 15 * time.Second, CheckRedirect: refuseRedirect}
	if cfg.HTTPClient != nil {
		clone := *cfg.HTTPClient
		if clone.Timeout == 0 {
			clone.Timeout = 15 * time.Second
		}
		clone.CheckRedirect = refuseRedirect
		hc = &clone
	}
	return &Client{cfg: cfg, http: hc}, nil
}

func (c *Client) AuthorizationURL(scopes []string, state, challenge, loginHint string, forceConsent bool) (string, error) {
	if state == "" || challenge == "" || len(scopes) == 0 {
		return "", errors.New("state, pkce challenge, and scopes are required")
	}
	u, err := url.Parse(c.cfg.AuthorizationEndpoint)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("client_id", c.cfg.ClientID)
	q.Set("redirect_uri", c.cfg.RedirectURL)
	q.Set("response_type", "code")
	q.Set("scope", strings.Join(scopes, " "))
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("access_type", "offline")
	q.Set("include_granted_scopes", "true")
	if loginHint != "" {
		q.Set("login_hint", loginHint)
	}
	if forceConsent {
		q.Set("prompt", "consent")
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (c *Client) Exchange(ctx context.Context, code, verifier string) (TokenSet, error) {
	if code == "" || verifier == "" {
		return TokenSet{}, errors.New("authorization code and pkce verifier are required")
	}
	values := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {c.cfg.RedirectURL}, "client_id": {c.cfg.ClientID}, "client_secret": {c.cfg.ClientSecret}, "code_verifier": {verifier}}
	return c.exchange(ctx, values)
}

func (c *Client) Refresh(ctx context.Context, refreshToken string) (TokenSet, error) {
	if refreshToken == "" {
		return TokenSet{}, errors.New("refresh token is required")
	}
	values := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}, "client_id": {c.cfg.ClientID}, "client_secret": {c.cfg.ClientSecret}}
	return c.exchange(ctx, values)
}

func (c *Client) exchange(ctx context.Context, values url.Values) (TokenSet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.TokenEndpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return TokenSet{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := c.http.Do(req)
	if err != nil {
		return TokenSet{}, fmt.Errorf("google token request: %w", err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return TokenSet{}, err
	}
	if res.StatusCode/100 != 2 {
		var oauthError struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &oauthError)
		return TokenSet{}, &EndpointError{StatusCode: res.StatusCode, Code: safeErrorCode(oauthError.Error)}
	}
	var out struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
		Scope        string `json:"scope"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return TokenSet{}, err
	}
	if strings.TrimSpace(out.AccessToken) == "" {
		return TokenSet{}, errors.New("google token response missing access token")
	}
	now := time.Now
	if c.cfg.Now != nil {
		now = c.cfg.Now
	}
	expiry := time.Time{}
	if out.ExpiresIn > 0 {
		expiry = now().UTC().Add(time.Duration(out.ExpiresIn) * time.Second)
	}
	return TokenSet{AccessToken: out.AccessToken, RefreshToken: out.RefreshToken, TokenType: out.TokenType, Scopes: strings.Fields(out.Scope), Expiry: expiry}, nil
}

func (c *Client) UserInfo(ctx context.Context, accessToken string) (Identity, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.UserinfoEndpoint, nil)
	if err != nil {
		return Identity{}, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	res, err := c.http.Do(req)
	if err != nil {
		return Identity{}, fmt.Errorf("google userinfo request: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		return Identity{}, fmt.Errorf("google userinfo returned status %d", res.StatusCode)
	}
	var out struct {
		Subject       string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&out); err != nil {
		return Identity{}, err
	}
	out.Email = strings.ToLower(strings.TrimSpace(out.Email))
	if out.Subject == "" || out.Email == "" || !out.EmailVerified {
		return Identity{}, errors.New("google userinfo did not return a verified identity")
	}
	return Identity{Subject: out.Subject, Email: out.Email, Name: strings.TrimSpace(out.Name), EmailVerified: out.EmailVerified}, nil
}

func (c *Client) Revoke(ctx context.Context, token string) error {
	if token == "" {
		return errors.New("token is required")
	}
	values := url.Values{"token": {token}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.RevokeEndpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("google revoke request: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("google revoke endpoint returned status %d", res.StatusCode)
	}
	return nil
}

func validateEndpoint(label, raw string, redirect bool) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return fmt.Errorf("google %s must be an absolute URL", label)
	}
	if u.User != nil || u.Fragment != "" {
		return fmt.Errorf("google %s contains forbidden URL components", label)
	}
	if u.Scheme == "https" {
		return nil
	}
	host := strings.ToLower(u.Hostname())
	if u.Scheme == "http" && (host == "localhost" || host == "127.0.0.1" || host == "::1") {
		return nil
	}
	if redirect {
		return fmt.Errorf("google %s must use https except on loopback", label)
	}
	return fmt.Errorf("google %s must use https except on loopback", label)
}

func refuseRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
func first(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return fallback
}

func safeErrorCode(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 64 {
		return ""
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			continue
		}
		return ""
	}
	return value
}
