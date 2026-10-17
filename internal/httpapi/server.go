package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/tevriqorg/google-access-hub/internal/capability"
	"github.com/tevriqorg/google-access-hub/internal/hub"
	"github.com/tevriqorg/google-access-hub/internal/secure"
	"github.com/tevriqorg/google-access-hub/internal/store"
)

type Server struct {
	Hub            *hub.Hub
	Store          *store.Store
	AdminTokenHash string
}

type principal struct {
	ID      string
	Admin   bool
	Allowed map[string]bool
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /v1/capabilities", s.capabilities)
	mux.HandleFunc("GET /v1/accounts", s.accounts)
	mux.HandleFunc("GET /v1/scopes", s.scopes)
	mux.HandleFunc("GET /v1/clients", s.clients)
	mux.HandleFunc("POST /v1/clients", s.clients)
	mux.HandleFunc("POST /v1/oauth/google/start", s.oauthStart)
	mux.HandleFunc("GET /oauth/google/callback", s.oauthCallback)
	mux.HandleFunc("POST /v1/revoke", s.revoke)
	mux.HandleFunc("GET /v1/audit", s.audit)
	return securityHeaders(mux)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	configured := s.Hub != nil && s.Hub.Google != nil
	accounts := 0
	if s.Store != nil {
		accounts = len(s.Store.Accounts())
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "google_configured": configured, "accounts": accounts})
}

func (s *Server) capabilities(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authorize(w, r)
	if !ok {
		return
	}
	all := capability.All()
	if p.Admin {
		writeJSON(w, http.StatusOK, all)
		return
	}
	filtered := map[string][]string{}
	for name := range p.Allowed {
		if scopes, exists := all[name]; exists {
			filtered[name] = scopes
		}
	}
	writeJSON(w, http.StatusOK, filtered)
}

func (s *Server) accounts(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorize(w, r); !ok {
		return
	}
	type publicAccount struct {
		Subject       string    `json:"subject"`
		Email         string    `json:"email"`
		DisplayName   string    `json:"display_name,omitempty"`
		GrantedScopes []string  `json:"granted_scopes"`
		Status        string    `json:"status"`
		UpdatedAt     time.Time `json:"updated_at"`
		LastRefreshAt time.Time `json:"last_refresh_at,omitempty"`
	}
	accounts := s.Store.Accounts()
	out := make([]publicAccount, 0, len(accounts))
	for _, a := range accounts {
		out = append(out, publicAccount{a.Subject, a.Email, a.DisplayName, a.GrantedScopes, a.Status, a.UpdatedAt, a.LastRefreshAt})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) scopes(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authorize(w, r)
	if !ok {
		return
	}
	caps := r.URL.Query()["capability"]
	if len(caps) == 0 && !p.Admin {
		for name := range p.Allowed {
			caps = append(caps, name)
		}
	}
	if len(caps) == 0 {
		writeError(w, http.StatusBadRequest, "at least one capability is required")
		return
	}
	if !p.Admin && !allowedCapabilities(p, caps) {
		writeError(w, http.StatusForbidden, "capability is not allowed for this client")
		return
	}
	required, granted, missing, err := s.Hub.ScopeStatus(r.URL.Query().Get("subject"), caps)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"capabilities": caps, "required_scopes": required, "granted_scopes": granted, "missing_scopes": missing})
}

func (s *Server) clients(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authorize(w, r)
	if !ok {
		return
	}
	if !p.Admin {
		writeError(w, http.StatusForbidden, "admin authorization required")
		return
	}
	if r.Method == http.MethodGet {
		type publicClient struct {
			ID                  string    `json:"id"`
			Name                string    `json:"name"`
			AllowedCapabilities []string  `json:"allowed_capabilities"`
			Enabled             bool      `json:"enabled"`
			CreatedAt           time.Time `json:"created_at"`
		}
		clients := s.Store.Clients()
		out := make([]publicClient, 0, len(clients))
		for _, c := range clients {
			out = append(out, publicClient{c.ID, c.Name, c.AllowedCapabilities, c.Enabled, c.CreatedAt})
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	var in struct {
		Name         string   `json:"name"`
		Capabilities []string `json:"capabilities"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	for _, c := range in.Capabilities {
		if !capability.Known(c) {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown capability %q", c))
			return
		}
	}
	idRaw, err := secure.RandomToken(12)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to create client")
		return
	}
	secret, err := secure.RandomToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to create client")
		return
	}
	id := "svc_" + idRaw
	now := time.Now().UTC()
	client := store.Client{ID: id, Name: in.Name, TokenHash: secure.HashToken(secret), AllowedCapabilities: dedupe(in.Capabilities), Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := s.Store.PutClient(client); err != nil {
		writeError(w, http.StatusInternalServerError, "unable to persist client")
		return
	}
	token := "gahc." + id + "." + secret
	s.auditEvent(p.ID, "client.create", "", "", true, "client="+id)
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "name": in.Name, "capabilities": client.AllowedCapabilities, "token": token, "token_displayed_once": true})
}

func (s *Server) oauthStart(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authorize(w, r)
	if !ok {
		return
	}
	var in struct {
		Capabilities []string `json:"capabilities"`
		Subject      string   `json:"subject"`
		LoginHint    string   `json:"login_hint"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if !p.Admin && !allowedCapabilities(p, in.Capabilities) {
		writeError(w, http.StatusForbidden, "capability is not allowed for this client")
		return
	}
	result, err := s.Hub.StartAuthorization(hub.StartRequest{Capabilities: in.Capabilities, Subject: strings.TrimSpace(in.Subject), LoginHint: strings.TrimSpace(in.LoginHint), ClientID: p.ID})
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, hub.ErrGoogleUnconfigured) {
			status = http.StatusServiceUnavailable
		}
		s.auditEvent(p.ID, "oauth.start", in.Subject, "", false, publicError(err))
		writeError(w, status, publicError(err))
		return
	}
	s.auditEvent(p.ID, "oauth.start", in.Subject, "", true, "capabilities="+strings.Join(in.Capabilities, ","))
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) oauthCallback(w http.ResponseWriter, r *http.Request) {
	if oauthErr := strings.TrimSpace(r.URL.Query().Get("error")); oauthErr != "" {
		writeCallback(w, r, http.StatusBadRequest, "Google authorization was not completed: "+oauthErr)
		return
	}
	account, err := s.Hub.FinishAuthorization(r.Context(), r.URL.Query().Get("state"), r.URL.Query().Get("code"))
	if err != nil {
		writeCallback(w, r, http.StatusBadRequest, publicError(err))
		return
	}
	s.auditEvent("oauth-callback", "oauth.complete", account.Subject, "", true, "email="+account.Email)
	writeCallback(w, r, http.StatusOK, "Google authorization stored for "+account.Email+". You may close this window.")
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authorize(w, r)
	if !ok {
		return
	}
	if !p.Admin {
		writeError(w, http.StatusForbidden, "admin authorization required")
		return
	}
	var in struct {
		Subject string `json:"subject"`
	}
	if err := decodeJSON(r, &in); err != nil || strings.TrimSpace(in.Subject) == "" {
		writeError(w, http.StatusBadRequest, "subject is required")
		return
	}
	if err := s.Hub.RevokeAccount(r.Context(), strings.TrimSpace(in.Subject)); err != nil {
		s.auditEvent(p.ID, "account.revoke", in.Subject, "", false, publicError(err))
		writeError(w, http.StatusBadRequest, publicError(err))
		return
	}
	s.auditEvent(p.ID, "account.revoke", in.Subject, "", true, "")
	writeJSON(w, http.StatusOK, map[string]any{"revoked": true})
}

func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authorize(w, r)
	if !ok {
		return
	}
	if !p.Admin {
		writeError(w, http.StatusForbidden, "admin authorization required")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	writeJSON(w, http.StatusOK, s.Store.Audits(limit))
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) (principal, bool) {
	token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if token == "" {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeError(w, http.StatusUnauthorized, "authorization required")
		return principal{}, false
	}
	if s.AdminTokenHash != "" && secure.TokenHashEqual(s.AdminTokenHash, token) {
		return principal{ID: "admin", Admin: true, Allowed: map[string]bool{}}, true
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "gahc" {
		writeError(w, http.StatusUnauthorized, "invalid service credential")
		return principal{}, false
	}
	client, exists := s.Store.Client(parts[1])
	if !exists || !client.Enabled || !secure.TokenHashEqual(client.TokenHash, parts[2]) {
		writeError(w, http.StatusUnauthorized, "invalid service credential")
		return principal{}, false
	}
	allowed := map[string]bool{}
	for _, c := range client.AllowedCapabilities {
		allowed[c] = true
	}
	return principal{ID: client.ID, Allowed: allowed}, true
}

func allowedCapabilities(p principal, caps []string) bool {
	if len(caps) == 0 {
		return false
	}
	for _, c := range caps {
		if !p.Allowed[c] {
			return false
		}
	}
	return true
}
func (s *Server) auditEvent(clientID, action, subject, cap string, success bool, detail string) {
	id, _ := secure.RandomToken(12)
	_ = s.Store.AddAudit(store.AuditEvent{ID: id, At: time.Now().UTC(), ClientID: clientID, Action: action, Subject: subject, Capability: cap, Success: success, Detail: detail})
}
func decodeJSON(r *http.Request, out any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
func writeCallback(w http.ResponseWriter, r *http.Request, status int, message string) {
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		writeJSON(w, status, map[string]any{"ok": status < 300, "message": message})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "<!doctype html><meta charset=utf-8><title>Google Access Hub</title><p>%s</p>", html.EscapeString(message))
}
func publicError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if len(msg) > 240 {
		msg = msg[:240]
	}
	return msg
}
func dedupe(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
		next.ServeHTTP(w, r)
	})
}
