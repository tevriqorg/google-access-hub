package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tevriqorg/google-access-hub/internal/googleoauth"
	"github.com/tevriqorg/google-access-hub/internal/hub"
	"github.com/tevriqorg/google-access-hub/internal/secure"
	"github.com/tevriqorg/google-access-hub/internal/store"
)

func TestEndToEndOAuthPersistenceReplayRefreshAndRevoke(t *testing.T) {
	refreshRequests := 0
	revokeRequests := 0
	invalidateRefresh := false
	userinfoSubject := "google-subject-1"
	google := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			_ = r.ParseForm()
			if r.Form.Get("grant_type") == "refresh_token" && invalidateRefresh {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				writeFakeJSON(w, map[string]any{"error": "invalid_grant", "error_description": "revoked by fake provider"})
				return
			}
			switch r.Form.Get("grant_type") {
			case "authorization_code":
				if r.Form.Get("code") != "good-code" || r.Form.Get("code_verifier") == "" {
					http.Error(w, "bad exchange", 400)
					return
				}
				writeFakeJSON(w, map[string]any{"access_token": "access-initial", "refresh_token": "refresh-super-secret", "token_type": "Bearer", "expires_in": 3600, "scope": "openid email profile https://www.googleapis.com/auth/gmail.readonly"})
			case "refresh_token":
				refreshRequests++
				if r.Form.Get("refresh_token") != "refresh-super-secret" {
					http.Error(w, "bad refresh", 400)
					return
				}
				writeFakeJSON(w, map[string]any{"access_token": "access-refreshed", "token_type": "Bearer", "expires_in": 3600, "scope": "openid email profile https://www.googleapis.com/auth/gmail.readonly"})
			default:
				http.Error(w, "unsupported", 400)
			}
		case "/userinfo":
			if r.Header.Get("Authorization") != "Bearer access-initial" {
				http.Error(w, "bad access", 401)
				return
			}
			writeFakeJSON(w, map[string]any{"sub": userinfoSubject, "email": "owner@example.test", "email_verified": true, "name": "Owner"})
		case "/revoke":
			revokeRequests++
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer google.Close()

	dir := t.TempDir()
	storePath := filepath.Join(dir, "hub.json")
	st, err := store.Open(storePath)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{7}, 32)
	g, err := googleoauth.New(googleoauth.Config{ClientID: "client", ClientSecret: "secret", RedirectURL: "http://localhost/callback", AuthorizationEndpoint: google.URL + "/auth", TokenEndpoint: google.URL + "/token", UserinfoEndpoint: google.URL + "/userinfo", RevokeEndpoint: google.URL + "/revoke"})
	if err != nil {
		t.Fatal(err)
	}
	h := &hub.Hub{Store: st, Google: g, MasterKey: key}
	admin := "admin-token-admin-token-admin-token-12345"
	api := &Server{Hub: h, Store: st, AdminTokenHash: secure.HashToken(admin)}
	app := httptest.NewServer(api.Handler())
	defer app.Close()

	clientResp := requestJSON(t, http.MethodPost, app.URL+"/v1/clients", admin, map[string]any{"name": "mail-hub", "capabilities": []string{"identity.basic", "gmail.read"}})
	if clientResp.StatusCode != http.StatusCreated {
		t.Fatalf("client status=%d body=%s", clientResp.StatusCode, readBody(clientResp))
	}
	var created struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	decodeResponse(t, clientResp, &created)
	if !strings.HasPrefix(created.Token, "gahc.svc_") {
		t.Fatalf("client token=%q", created.Token)
	}

	startResp := requestJSON(t, http.MethodPost, app.URL+"/v1/oauth/google/start", created.Token, map[string]any{"capabilities": []string{"identity.basic", "gmail.read"}, "login_hint": "owner@example.test"})
	if startResp.StatusCode != http.StatusOK {
		t.Fatalf("start status=%d body=%s", startResp.StatusCode, readBody(startResp))
	}
	var started struct {
		AuthorizationURL string   `json:"authorization_url"`
		MissingScopes    []string `json:"missing_scopes"`
	}
	decodeResponse(t, startResp, &started)
	authURL, err := url.Parse(started.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	stateValue := authURL.Query().Get("state")
	if stateValue == "" {
		t.Fatal("missing oauth state")
	}
	if authURL.Query().Get("include_granted_scopes") != "true" || authURL.Query().Get("access_type") != "offline" {
		t.Fatalf("authorization query=%v", authURL.Query())
	}

	callbackReq, _ := http.NewRequest(http.MethodGet, app.URL+"/v1/oauth/google/callback?state="+url.QueryEscape(stateValue)+"&code=good-code", nil)
	callbackReq.Header.Set("Accept", "application/json")
	callbackResp, err := http.DefaultClient.Do(callbackReq)
	if err != nil {
		t.Fatal(err)
	}
	if callbackResp.StatusCode != http.StatusOK {
		t.Fatalf("callback status=%d body=%s", callbackResp.StatusCode, readBody(callbackResp))
	}
	_ = callbackResp.Body.Close()

	raw, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("refresh-super-secret")) {
		t.Fatal("store leaked refresh token plaintext")
	}
	account, ok := st.Account("google-subject-1")
	if !ok || !strings.HasPrefix(account.EncryptedRefreshToken, "v1:") {
		t.Fatalf("account=%+v ok=%v", account, ok)
	}

	replayReq, _ := http.NewRequest(http.MethodGet, app.URL+"/v1/oauth/google/callback?state="+url.QueryEscape(stateValue)+"&code=good-code", nil)
	replayReq.Header.Set("Accept", "application/json")
	replayResp, err := http.DefaultClient.Do(replayReq)
	if err != nil {
		t.Fatal(err)
	}
	if replayResp.StatusCode == http.StatusOK {
		t.Fatal("oauth state replay succeeded")
	}
	_ = replayResp.Body.Close()

	mismatchStart := requestJSON(t, http.MethodPost, app.URL+"/v1/oauth/google/start", admin, map[string]any{"capabilities": []string{"gmail.send"}, "subject": "google-subject-1"})
	if mismatchStart.StatusCode != http.StatusOK {
		t.Fatalf("mismatch start status=%d body=%s", mismatchStart.StatusCode, readBody(mismatchStart))
	}
	var mismatch struct {
		AuthorizationURL string `json:"authorization_url"`
	}
	decodeResponse(t, mismatchStart, &mismatch)
	mismatchURL, _ := url.Parse(mismatch.AuthorizationURL)
	userinfoSubject = "different-google-subject"
	mismatchReq, _ := http.NewRequest(http.MethodGet, app.URL+"/v1/oauth/google/callback?state="+url.QueryEscape(mismatchURL.Query().Get("state"))+"&code=good-code", nil)
	mismatchReq.Header.Set("Accept", "application/json")
	mismatchResp, err := http.DefaultClient.Do(mismatchReq)
	if err != nil {
		t.Fatal(err)
	}
	if mismatchResp.StatusCode == http.StatusOK {
		t.Fatal("incremental authorization accepted a different Google subject")
	}
	_ = mismatchResp.Body.Close()
	userinfoSubject = "google-subject-1"
	if _, exists := st.Account("different-google-subject"); exists {
		t.Fatal("mismatched Google subject was persisted")
	}

	reopened, err := store.Open(storePath)
	if err != nil {
		t.Fatal(err)
	}
	restartedHub := &hub.Hub{Store: reopened, Google: g, MasterKey: key}
	refreshed, err := restartedHub.RefreshAccount(context.Background(), "google-subject-1")
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.AccessToken != "access-refreshed" || refreshed.RefreshToken != "" || refreshRequests != 1 {
		t.Fatalf("refreshed=%+v requests=%d", refreshed, refreshRequests)
	}
	invalidateRefresh = true
	if _, err := restartedHub.RefreshAccount(context.Background(), "google-subject-1"); !googleoauth.IsErrorCode(err, "invalid_grant") {
		t.Fatalf("expected invalid_grant, got %v", err)
	}
	reauth, _ := reopened.Account("google-subject-1")
	if reauth.Status != "reauthorization_required" {
		t.Fatalf("account status=%q, want reauthorization_required", reauth.Status)
	}
	invalidateRefresh = false
	reauth.Status = "active"
	if err := reopened.UpsertAccount(reauth); err != nil {
		t.Fatal(err)
	}

	restartedAPI := &Server{Hub: restartedHub, Store: reopened, AdminTokenHash: secure.HashToken(admin)}
	restartedServer := httptest.NewServer(restartedAPI.Handler())
	defer restartedServer.Close()
	revokeResp := requestJSON(t, http.MethodPost, restartedServer.URL+"/v1/revoke", admin, map[string]any{"subject": "google-subject-1"})
	if revokeResp.StatusCode != http.StatusOK {
		t.Fatalf("revoke status=%d body=%s", revokeResp.StatusCode, readBody(revokeResp))
	}
	_ = revokeResp.Body.Close()
	revoked, _ := reopened.Account("google-subject-1")
	if revoked.Status != "revoked" || revoked.EncryptedRefreshToken != "" || revokeRequests != 2 {
		t.Fatalf("revoked=%+v requests=%d", revoked, revokeRequests)
	}

	rotateResp := requestJSON(t, http.MethodPost, restartedServer.URL+"/v1/clients/"+created.ID+"/rotate", admin, map[string]any{})
	if rotateResp.StatusCode != http.StatusOK {
		t.Fatalf("rotate status=%d body=%s", rotateResp.StatusCode, readBody(rotateResp))
	}
	var rotated struct {
		Token string `json:"token"`
	}
	decodeResponse(t, rotateResp, &rotated)
	oldTokenResp := requestJSON(t, http.MethodGet, restartedServer.URL+"/v1/capabilities", created.Token, nil)
	if oldTokenResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old client token status=%d", oldTokenResp.StatusCode)
	}
	_ = oldTokenResp.Body.Close()
	newTokenResp := requestJSON(t, http.MethodGet, restartedServer.URL+"/v1/capabilities", rotated.Token, nil)
	if newTokenResp.StatusCode != http.StatusOK {
		t.Fatalf("rotated client token status=%d body=%s", newTokenResp.StatusCode, readBody(newTokenResp))
	}
	_ = newTokenResp.Body.Close()
	disableResp := requestJSON(t, http.MethodPost, restartedServer.URL+"/v1/clients/"+created.ID+"/disable", admin, map[string]any{})
	if disableResp.StatusCode != http.StatusOK {
		t.Fatalf("disable status=%d body=%s", disableResp.StatusCode, readBody(disableResp))
	}
	_ = disableResp.Body.Close()
	disabledTokenResp := requestJSON(t, http.MethodGet, restartedServer.URL+"/v1/capabilities", rotated.Token, nil)
	if disabledTokenResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("disabled client token status=%d", disabledTokenResp.StatusCode)
	}
	_ = disabledTokenResp.Body.Close()
}

func requestJSON(t *testing.T, method, endpoint, token string, body any) *http.Response {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest(method, endpoint, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}
func decodeResponse(t *testing.T, res *http.Response, out any) {
	t.Helper()
	defer res.Body.Close()
	if err := json.NewDecoder(res.Body).Decode(out); err != nil {
		t.Fatal(err)
	}
}
func readBody(res *http.Response) string {
	raw, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	return string(raw)
}
func writeFakeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
