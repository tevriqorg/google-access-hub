package googleoauth

import (
    "context"
    "net/http"
    "net/http/httptest"
    "net/url"
    "strings"
    "testing"
)

func TestAuthorizationURLUsesOfflineIncrementalPKCE(t *testing.T) {
    c,err:=New(Config{ClientID:"client",ClientSecret:"secret",RedirectURL:"https://auth.example.test/oauth/google/callback"}); if err!=nil { t.Fatal(err) }
    raw,err:=c.AuthorizationURL([]string{"openid","email"},"state","challenge","me@example.test",true); if err!=nil { t.Fatal(err) }
    u,err:=url.Parse(raw); if err!=nil { t.Fatal(err) }; q:=u.Query()
    checks:=map[string]string{"access_type":"offline","include_granted_scopes":"true","code_challenge_method":"S256","prompt":"consent","login_hint":"me@example.test"}
    for k,want:=range checks { if q.Get(k)!=want { t.Fatalf("%s=%q want %q",k,q.Get(k),want) } }
    if strings.Contains(raw,"secret") { t.Fatal("authorization url leaked client secret") }
}

func TestTokenUserinfoRefreshAndRevoke(t *testing.T) {
    revokeHits:=0
    server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
        switch r.URL.Path {
        case "/token":
            _=r.ParseForm()
            if r.Form.Get("grant_type")=="authorization_code" { w.Header().Set("Content-Type","application/json"); _,_=w.Write([]byte(`{"access_token":"access-1","refresh_token":"refresh-1","token_type":"Bearer","expires_in":3600,"scope":"openid email"}`)); return }
            if r.Form.Get("grant_type")=="refresh_token" && r.Form.Get("refresh_token")=="refresh-1" { w.Header().Set("Content-Type","application/json"); _,_=w.Write([]byte(`{"access_token":"access-2","token_type":"Bearer","expires_in":3600,"scope":"openid email"}`)); return }
            http.Error(w,"bad grant",400)
        case "/userinfo":
            if r.Header.Get("Authorization")!="Bearer access-1" { http.Error(w,"bad token",401); return }
            w.Header().Set("Content-Type","application/json"); _,_=w.Write([]byte(`{"sub":"sub-1","email":"me@example.test","email_verified":true,"name":"Me"}`))
        case "/revoke": revokeHits++; w.WriteHeader(200)
        default: http.NotFound(w,r)
        }
    })); defer server.Close()
    c,err:=New(Config{ClientID:"client",ClientSecret:"secret",RedirectURL:"http://localhost/callback",AuthorizationEndpoint:server.URL+"/auth",TokenEndpoint:server.URL+"/token",UserinfoEndpoint:server.URL+"/userinfo",RevokeEndpoint:server.URL+"/revoke"}); if err!=nil { t.Fatal(err) }
    tokens,err:=c.Exchange(context.Background(),"code","verifier"); if err!=nil { t.Fatal(err) }
    if tokens.RefreshToken!="refresh-1" { t.Fatalf("refresh=%q",tokens.RefreshToken) }
    id,err:=c.UserInfo(context.Background(),tokens.AccessToken); if err!=nil || id.Subject!="sub-1" { t.Fatalf("identity=%+v err=%v",id,err) }
    refreshed,err:=c.Refresh(context.Background(),"refresh-1"); if err!=nil || refreshed.AccessToken!="access-2" { t.Fatalf("refresh result=%+v err=%v",refreshed,err) }
    if err:=c.Revoke(context.Background(),"refresh-1"); err!=nil { t.Fatal(err) }
    if revokeHits!=1 { t.Fatalf("revoke hits=%d",revokeHits) }
}
