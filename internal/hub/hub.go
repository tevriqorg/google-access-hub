package hub

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/tevriqorg/google-access-hub/internal/capability"
	"github.com/tevriqorg/google-access-hub/internal/googleoauth"
	"github.com/tevriqorg/google-access-hub/internal/secure"
	"github.com/tevriqorg/google-access-hub/internal/store"
)

var ErrGoogleUnconfigured = errors.New("google oauth is not configured")

type Hub struct {
	Store     *store.Store
	Google    *googleoauth.Client
	MasterKey []byte
	Now       func() time.Time
}

type StartRequest struct {
	Capabilities                 []string
	Subject, LoginHint, ClientID string
}
type StartResult struct {
	AuthorizationURL string   `json:"authorization_url,omitempty"`
	MissingScopes    []string `json:"missing_scopes"`
	AlreadyGranted   bool     `json:"already_granted"`
}

func (h *Hub) StartAuthorization(req StartRequest) (StartResult, error) {
	if h.Google == nil {
		return StartResult{}, ErrGoogleUnconfigured
	}
	if h.Store == nil || len(h.MasterKey) != 32 {
		return StartResult{}, errors.New("hub store and 32-byte master key are required")
	}
	now := h.now()
	_ = h.Store.PurgeExpiredPending(now)
	requestedCaps := dedupe(req.Capabilities)
	if len(requestedCaps) == 0 {
		return StartResult{}, errors.New("at least one capability is required")
	}
	requestedScopes, err := capability.Scopes(requestedCaps)
	if err != nil {
		return StartResult{}, err
	}
	identityScopes, _ := capability.Scopes([]string{"identity.basic"})
	account, hasAccount, err := h.resolveAccount(req.Subject)
	if err != nil {
		return StartResult{}, err
	}
	granted := map[string]bool{}
	if hasAccount {
		for _, scope := range account.GrantedScopes {
			granted[scope] = true
		}
	}
	missing := make([]string, 0)
	for _, scope := range requestedScopes {
		if !granted[scope] {
			missing = append(missing, scope)
		}
	}
	if hasAccount && len(missing) == 0 {
		return StartResult{MissingScopes: []string{}, AlreadyGranted: true}, nil
	}
	authorizationScopes := dedupe(append(identityScopes, missing...))
	sort.Strings(authorizationScopes)
	state, err := secure.RandomToken(32)
	if err != nil {
		return StartResult{}, err
	}
	verifier, err := secure.RandomToken(48)
	if err != nil {
		return StartResult{}, err
	}
	stateHash := secure.HashToken(state)
	encryptedVerifier, err := secure.Encrypt(h.MasterKey, "pkce:"+stateHash, verifier)
	if err != nil {
		return StartResult{}, err
	}
	pending := store.PendingAuth{StateHash: stateHash, EncryptedPKCEVerifier: encryptedVerifier, RequestedCapabilities: requestedCaps, RequestedScopes: authorizationScopes, ClientID: req.ClientID, LoginHint: strings.TrimSpace(req.LoginHint), CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute)}
	if err := h.Store.PutPending(pending); err != nil {
		return StartResult{}, err
	}
	authURL, err := h.Google.AuthorizationURL(authorizationScopes, state, secure.PKCEChallenge(verifier), req.LoginHint, !hasAccount || account.EncryptedRefreshToken == "")
	if err != nil {
		return StartResult{}, err
	}
	return StartResult{AuthorizationURL: authURL, MissingScopes: missing, AlreadyGranted: false}, nil
}

func (h *Hub) FinishAuthorization(ctx context.Context, stateValue, code string) (store.Account, error) {
	if h.Google == nil {
		return store.Account{}, ErrGoogleUnconfigured
	}
	if stateValue == "" || code == "" {
		return store.Account{}, errors.New("oauth state and code are required")
	}
	stateHash := secure.HashToken(stateValue)
	pending, err := h.Store.ConsumePending(stateHash, h.now())
	if err != nil {
		return store.Account{}, err
	}
	verifier, err := secure.Decrypt(h.MasterKey, "pkce:"+stateHash, pending.EncryptedPKCEVerifier)
	if err != nil {
		return store.Account{}, err
	}
	tokens, err := h.Google.Exchange(ctx, code, verifier)
	if err != nil {
		return store.Account{}, err
	}
	identity, err := h.Google.UserInfo(ctx, tokens.AccessToken)
	if err != nil {
		return store.Account{}, err
	}
	existing, _ := h.Store.Account(identity.Subject)
	encryptedRefresh := existing.EncryptedRefreshToken
	if strings.TrimSpace(tokens.RefreshToken) != "" {
		encryptedRefresh, err = secure.Encrypt(h.MasterKey, "refresh:"+identity.Subject, tokens.RefreshToken)
		if err != nil {
			return store.Account{}, err
		}
	}
	if encryptedRefresh == "" {
		return store.Account{}, errors.New("initial google authorization did not return a refresh token")
	}
	scopes := merge(existing.GrantedScopes, tokens.Scopes)
	now := h.now()
	created := existing.CreatedAt
	if created.IsZero() {
		created = now
	}
	account := store.Account{Subject: identity.Subject, Email: identity.Email, DisplayName: identity.Name, EncryptedRefreshToken: encryptedRefresh, GrantedScopes: scopes, Status: "active", CreatedAt: created, UpdatedAt: now, LastRefreshAt: existing.LastRefreshAt}
	if err := h.Store.UpsertAccount(account); err != nil {
		return store.Account{}, err
	}
	return account, nil
}

func (h *Hub) RefreshAccount(ctx context.Context, subject string) (googleoauth.TokenSet, error) {
	if h.Google == nil {
		return googleoauth.TokenSet{}, ErrGoogleUnconfigured
	}
	account, ok := h.Store.Account(subject)
	if !ok {
		return googleoauth.TokenSet{}, errors.New("google account not found")
	}
	if account.Status != "active" || account.EncryptedRefreshToken == "" {
		return googleoauth.TokenSet{}, errors.New("google account requires authorization")
	}
	refresh, err := secure.Decrypt(h.MasterKey, "refresh:"+subject, account.EncryptedRefreshToken)
	if err != nil {
		return googleoauth.TokenSet{}, err
	}
	tokens, err := h.Google.Refresh(ctx, refresh)
	if err != nil {
		if googleoauth.IsErrorCode(err, "invalid_grant") {
			account.Status = "reauthorization_required"
			account.UpdatedAt = h.now()
			_ = h.Store.UpsertAccount(account)
		}
		return googleoauth.TokenSet{}, err
	}
	if tokens.RefreshToken != "" && tokens.RefreshToken != refresh {
		account.EncryptedRefreshToken, err = secure.Encrypt(h.MasterKey, "refresh:"+subject, tokens.RefreshToken)
		if err != nil {
			return googleoauth.TokenSet{}, err
		}
	}
	if len(tokens.Scopes) > 0 {
		account.GrantedScopes = merge(account.GrantedScopes, tokens.Scopes)
	}
	account.LastRefreshAt = h.now()
	account.UpdatedAt = account.LastRefreshAt
	account.Status = "active"
	if err := h.Store.UpsertAccount(account); err != nil {
		return googleoauth.TokenSet{}, err
	}
	tokens.RefreshToken = ""
	return tokens, nil
}

func (h *Hub) RevokeAccount(ctx context.Context, subject string) error {
	if h.Google == nil {
		return ErrGoogleUnconfigured
	}
	account, ok := h.Store.Account(subject)
	if !ok {
		return errors.New("google account not found")
	}
	if account.EncryptedRefreshToken != "" {
		refresh, err := secure.Decrypt(h.MasterKey, "refresh:"+subject, account.EncryptedRefreshToken)
		if err != nil {
			return err
		}
		if err := h.Google.Revoke(ctx, refresh); err != nil {
			return err
		}
	}
	account.EncryptedRefreshToken = ""
	account.Status = "revoked"
	account.UpdatedAt = h.now()
	return h.Store.UpsertAccount(account)
}

func (h *Hub) ScopeStatus(subject string, capabilities []string) (required, granted, missing []string, err error) {
	required, err = capability.Scopes(capabilities)
	if err != nil {
		return nil, nil, nil, err
	}
	account, ok, err := h.resolveAccount(subject)
	if err != nil {
		return nil, nil, nil, err
	}
	grantSet := map[string]bool{}
	if ok {
		granted = append([]string(nil), account.GrantedScopes...)
		for _, s := range granted {
			grantSet[s] = true
		}
	}
	for _, scope := range required {
		if !grantSet[scope] {
			missing = append(missing, scope)
		}
	}
	sort.Strings(granted)
	sort.Strings(missing)
	return required, granted, missing, nil
}

func (h *Hub) resolveAccount(subject string) (store.Account, bool, error) {
	if subject != "" {
		account, ok := h.Store.Account(subject)
		return account, ok, nil
	}
	accounts := h.Store.Accounts()
	if len(accounts) == 0 {
		return store.Account{}, false, nil
	}
	if len(accounts) > 1 {
		return store.Account{}, false, fmt.Errorf("multiple google accounts exist; subject is required")
	}
	return accounts[0], true, nil
}

func (h *Hub) now() time.Time {
	if h.Now != nil {
		return h.Now().UTC()
	}
	return time.Now().UTC()
}
func dedupe(values []string) []string {
	m := map[string]bool{}
	out := []string{}
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" && !m[v] {
			m[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
func merge(a, b []string) []string { return dedupe(append(append([]string(nil), a...), b...)) }
