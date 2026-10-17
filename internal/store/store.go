package store

import (
    "encoding/json"
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "sort"
    "sync"
    "time"
)

const schemaVersion = 1

type Account struct {
    Subject               string    `json:"subject"`
    Email                 string    `json:"email"`
    DisplayName           string    `json:"display_name,omitempty"`
    EncryptedRefreshToken string    `json:"encrypted_refresh_token,omitempty"`
    GrantedScopes         []string  `json:"granted_scopes"`
    Status                string    `json:"status"`
    CreatedAt             time.Time `json:"created_at"`
    UpdatedAt             time.Time `json:"updated_at"`
    LastRefreshAt         time.Time `json:"last_refresh_at,omitempty"`
}

type PendingAuth struct {
    StateHash             string    `json:"state_hash"`
    EncryptedPKCEVerifier string    `json:"encrypted_pkce_verifier"`
    RequestedCapabilities []string  `json:"requested_capabilities"`
    RequestedScopes       []string  `json:"requested_scopes"`
    ClientID              string    `json:"client_id"`
    LoginHint             string    `json:"login_hint,omitempty"`
    ExpiresAt             time.Time `json:"expires_at"`
    CreatedAt             time.Time `json:"created_at"`
}

type Client struct {
    ID                  string    `json:"id"`
    Name                string    `json:"name"`
    TokenHash           string    `json:"token_hash"`
    AllowedCapabilities []string  `json:"allowed_capabilities"`
    Enabled             bool      `json:"enabled"`
    CreatedAt           time.Time `json:"created_at"`
    UpdatedAt           time.Time `json:"updated_at"`
}

type AuditEvent struct {
    ID         string    `json:"id"`
    At         time.Time `json:"at"`
    ClientID   string    `json:"client_id"`
    Action     string    `json:"action"`
    Subject    string    `json:"subject,omitempty"`
    Capability string    `json:"capability,omitempty"`
    Success    bool      `json:"success"`
    Detail     string    `json:"detail,omitempty"`
}

type database struct {
    Version  int                    `json:"version"`
    Accounts map[string]Account     `json:"accounts"`
    Pending  map[string]PendingAuth `json:"pending"`
    Clients  map[string]Client      `json:"clients"`
    Audit    []AuditEvent           `json:"audit"`
}

type Store struct {
    mu   sync.Mutex
    path string
    db   database
}

func Open(path string) (*Store, error) {
    if path == "" {
        return nil, errors.New("store path is required")
    }
    s := &Store{path: path, db: newDatabase()}
    raw, err := os.ReadFile(path)
    if errors.Is(err, os.ErrNotExist) {
        if err := s.saveLocked(); err != nil {
            return nil, err
        }
        return s, nil
    }
    if err != nil {
        return nil, err
    }
    if err := json.Unmarshal(raw, &s.db); err != nil {
        return nil, fmt.Errorf("decode store: %w", err)
    }
    if s.db.Version != schemaVersion {
        return nil, fmt.Errorf("unsupported store schema version %d", s.db.Version)
    }
    s.normalizeLocked()
    return s, nil
}

func newDatabase() database {
    return database{Version: schemaVersion, Accounts: map[string]Account{}, Pending: map[string]PendingAuth{}, Clients: map[string]Client{}, Audit: []AuditEvent{}}
}

func (s *Store) normalizeLocked() {
    if s.db.Accounts == nil { s.db.Accounts = map[string]Account{} }
    if s.db.Pending == nil { s.db.Pending = map[string]PendingAuth{} }
    if s.db.Clients == nil { s.db.Clients = map[string]Client{} }
    if s.db.Audit == nil { s.db.Audit = []AuditEvent{} }
}

func (s *Store) saveLocked() error {
    s.normalizeLocked()
    dir := filepath.Dir(s.path)
    if err := os.MkdirAll(dir, 0o700); err != nil {
        return err
    }
    raw, err := json.MarshalIndent(s.db, "", "  ")
    if err != nil {
        return err
    }
    tmp := s.path + ".tmp"
    f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
    if err != nil { return err }
    ok := false
    defer func() {
        _ = f.Close()
        if !ok { _ = os.Remove(tmp) }
    }()
    if _, err := f.Write(append(raw, '
')); err != nil { return err }
    if err := f.Sync(); err != nil { return err }
    if err := f.Close(); err != nil { return err }
    if err := os.Rename(tmp, s.path); err != nil { return err }
    if err := os.Chmod(s.path, 0o600); err != nil { return err }
    if d, err := os.Open(dir); err == nil { _ = d.Sync(); _ = d.Close() }
    ok = true
    return nil
}

func (s *Store) UpsertAccount(account Account) error {
    s.mu.Lock(); defer s.mu.Unlock()
    if account.Subject == "" { return errors.New("account subject is required") }
    s.db.Accounts[account.Subject] = cloneAccount(account)
    return s.saveLocked()
}

func (s *Store) Account(subject string) (Account, bool) {
    s.mu.Lock(); defer s.mu.Unlock()
    account, ok := s.db.Accounts[subject]
    return cloneAccount(account), ok
}

func (s *Store) Accounts() []Account {
    s.mu.Lock(); defer s.mu.Unlock()
    out := make([]Account, 0, len(s.db.Accounts))
    for _, account := range s.db.Accounts { out = append(out, cloneAccount(account)) }
    sort.Slice(out, func(i, j int) bool { return out[i].Email < out[j].Email })
    return out
}

func (s *Store) PutPending(p PendingAuth) error {
    s.mu.Lock(); defer s.mu.Unlock()
    if p.StateHash == "" { return errors.New("pending state hash is required") }
    s.db.Pending[p.StateHash] = clonePending(p)
    return s.saveLocked()
}

func (s *Store) ConsumePending(stateHash string, now time.Time) (PendingAuth, error) {
    s.mu.Lock(); defer s.mu.Unlock()
    p, ok := s.db.Pending[stateHash]
    if !ok { return PendingAuth{}, errors.New("oauth state is unknown or already consumed") }
    delete(s.db.Pending, stateHash)
    if err := s.saveLocked(); err != nil { return PendingAuth{}, err }
    if !p.ExpiresAt.After(now) { return PendingAuth{}, errors.New("oauth state has expired") }
    return clonePending(p), nil
}

func (s *Store) PurgeExpiredPending(now time.Time) error {
    s.mu.Lock(); defer s.mu.Unlock()
    changed := false
    for key, p := range s.db.Pending {
        if !p.ExpiresAt.After(now) { delete(s.db.Pending, key); changed = true }
    }
    if changed { return s.saveLocked() }
    return nil
}

func (s *Store) PutClient(client Client) error {
    s.mu.Lock(); defer s.mu.Unlock()
    if client.ID == "" || client.TokenHash == "" { return errors.New("client id and token hash are required") }
    s.db.Clients[client.ID] = cloneClient(client)
    return s.saveLocked()
}

func (s *Store) Client(id string) (Client, bool) {
    s.mu.Lock(); defer s.mu.Unlock()
    client, ok := s.db.Clients[id]
    return cloneClient(client), ok
}

func (s *Store) ClientByTokenHash(tokenHash string) (Client, bool) {
    s.mu.Lock(); defer s.mu.Unlock()
    for _, client := range s.db.Clients {
        if client.Enabled && client.TokenHash == tokenHash { return cloneClient(client), true }
    }
    return Client{}, false
}

func (s *Store) Clients() []Client {
    s.mu.Lock(); defer s.mu.Unlock()
    out := make([]Client, 0, len(s.db.Clients))
    for _, client := range s.db.Clients { out = append(out, cloneClient(client)) }
    sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
    return out
}

func (s *Store) AddAudit(event AuditEvent) error {
    s.mu.Lock(); defer s.mu.Unlock()
    s.db.Audit = append(s.db.Audit, event)
    if len(s.db.Audit) > 5000 { s.db.Audit = append([]AuditEvent(nil), s.db.Audit[len(s.db.Audit)-5000:]...) }
    return s.saveLocked()
}

func (s *Store) Audits(limit int) []AuditEvent {
    s.mu.Lock(); defer s.mu.Unlock()
    if limit <= 0 || limit > 500 { limit = 100 }
    start := len(s.db.Audit) - limit
    if start < 0 { start = 0 }
    out := append([]AuditEvent(nil), s.db.Audit[start:]...)
    for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 { out[i], out[j] = out[j], out[i] }
    return out
}

func cloneAccount(in Account) Account { in.GrantedScopes = append([]string(nil), in.GrantedScopes...); return in }
func clonePending(in PendingAuth) PendingAuth { in.RequestedCapabilities = append([]string(nil), in.RequestedCapabilities...); in.RequestedScopes = append([]string(nil), in.RequestedScopes...); return in }
func cloneClient(in Client) Client { in.AllowedCapabilities = append([]string(nil), in.AllowedCapabilities...); return in }
