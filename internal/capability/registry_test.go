package capability

import "testing"

func TestScopesAreDeduplicatedAndUnknownRejected(t *testing.T) {
    scopes,err:=Scopes([]string{"identity.basic","gmail.read","gmail.read"}); if err!=nil { t.Fatal(err) }
    if len(scopes)!=4 { t.Fatalf("scopes=%v",scopes) }
    if _,err:=Scopes([]string{"future.magic"}); err==nil { t.Fatal("unknown capability accepted") }
}
