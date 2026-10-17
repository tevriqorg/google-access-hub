package main

import (
    "context"
    "encoding/base64"
    "errors"
    "fmt"
    "log"
    "net/http"
    "os"
    "os/signal"
    "strings"
    "syscall"
    "time"

    "github.com/tevriqorg/google-access-hub/internal/googleoauth"
    "github.com/tevriqorg/google-access-hub/internal/httpapi"
    "github.com/tevriqorg/google-access-hub/internal/hub"
    "github.com/tevriqorg/google-access-hub/internal/secure"
    "github.com/tevriqorg/google-access-hub/internal/store"
)

var commit = "dev"

func main() {
    addr:=env("GAH_ADDR","127.0.0.1:18120")
    dataFile:=env("GAH_DATA_FILE","./data/google-access-hub.json")
    key,err:=parseMasterKey(os.Getenv("GAH_MASTER_KEY")); if err!=nil { log.Fatal(err) }
    admin:=strings.TrimSpace(os.Getenv("GAH_ADMIN_TOKEN")); if len(admin)<32 { log.Fatal("GAH_ADMIN_TOKEN must be at least 32 characters") }
    st,err:=store.Open(dataFile); if err!=nil { log.Fatalf("open store: %v",err) }
    googleClient,err:=loadGoogleClient(); if err!=nil { log.Fatal(err) }
    h:=&hub.Hub{Store:st,Google:googleClient,MasterKey:key}
    api:=&httpapi.Server{Hub:h,Store:st,AdminTokenHash:secure.HashToken(admin)}
    server:=&http.Server{Addr:addr,Handler:api.Handler(),ReadHeaderTimeout:5*time.Second,ReadTimeout:30*time.Second,WriteTimeout:30*time.Second,IdleTimeout:60*time.Second}
    go func(){
        log.Printf("google-access-hub commit=%s addr=%s google_configured=%t",commit,addr,googleClient!=nil)
        if err:=server.ListenAndServe(); err!=nil && !errors.Is(err,http.ErrServerClosed) { log.Fatalf("serve: %v",err) }
    }()
    stop:=make(chan os.Signal,1); signal.Notify(stop,syscall.SIGINT,syscall.SIGTERM); <-stop
    ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second); defer cancel(); _=server.Shutdown(ctx)
}

func loadGoogleClient() (*googleoauth.Client,error) {
    id:=strings.TrimSpace(os.Getenv("GOOGLE_CLIENT_ID")); secret:=strings.TrimSpace(os.Getenv("GOOGLE_CLIENT_SECRET")); redirect:=strings.TrimSpace(os.Getenv("GOOGLE_REDIRECT_URL"))
    if id==""&&secret==""&&redirect=="" { return nil,nil }
    if id==""||secret==""||redirect=="" { return nil,fmt.Errorf("GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, and GOOGLE_REDIRECT_URL must be configured together") }
    cfg:=googleoauth.Config{ClientID:id,ClientSecret:secret,RedirectURL:redirect}
    if os.Getenv("GAH_ALLOW_GOOGLE_ENDPOINT_OVERRIDE")=="1" {
        cfg.AuthorizationEndpoint=strings.TrimSpace(os.Getenv("GOOGLE_AUTHORIZATION_ENDPOINT")); cfg.TokenEndpoint=strings.TrimSpace(os.Getenv("GOOGLE_TOKEN_ENDPOINT")); cfg.UserinfoEndpoint=strings.TrimSpace(os.Getenv("GOOGLE_USERINFO_ENDPOINT")); cfg.RevokeEndpoint=strings.TrimSpace(os.Getenv("GOOGLE_REVOKE_ENDPOINT"))
    }
    return googleoauth.New(cfg)
}

func parseMasterKey(raw string) ([]byte,error) {
    raw=strings.TrimSpace(raw); if raw=="" { return nil,errors.New("GAH_MASTER_KEY is required") }
    for _,enc:=range []*base64.Encoding{base64.StdEncoding,base64.RawStdEncoding,base64.URLEncoding,base64.RawURLEncoding} {
        if key,err:=enc.DecodeString(raw); err==nil && len(key)==32 { return key,nil }
    }
    return nil,errors.New("GAH_MASTER_KEY must encode exactly 32 bytes")
}
func env(name,fallback string) string { if v:=strings.TrimSpace(os.Getenv(name)); v!="" { return v }; return fallback }
