package capability

import (
    "fmt"
    "sort"
)

var registry = map[string][]string{
    "identity.basic":      {"openid", "email", "profile"},
    "gmail.read":          {"https://www.googleapis.com/auth/gmail.readonly"},
    "gmail.modify":        {"https://www.googleapis.com/auth/gmail.modify"},
    "gmail.send":          {"https://www.googleapis.com/auth/gmail.send"},
    "calendar.read":       {"https://www.googleapis.com/auth/calendar.readonly"},
    "calendar.write":      {"https://www.googleapis.com/auth/calendar.events"},
    "drive.metadata.read": {"https://www.googleapis.com/auth/drive.metadata.readonly"},
    "drive.file":          {"https://www.googleapis.com/auth/drive.file"},
    "drive.read":          {"https://www.googleapis.com/auth/drive.readonly"},
    "docs.read":           {"https://www.googleapis.com/auth/documents.readonly"},
    "docs.write":          {"https://www.googleapis.com/auth/documents"},
    "sheets.read":         {"https://www.googleapis.com/auth/spreadsheets.readonly"},
    "sheets.write":        {"https://www.googleapis.com/auth/spreadsheets"},
    "contacts.read":       {"https://www.googleapis.com/auth/contacts.readonly"},
    "contacts.write":      {"https://www.googleapis.com/auth/contacts"},
    "tasks.read":          {"https://www.googleapis.com/auth/tasks.readonly"},
    "tasks.write":         {"https://www.googleapis.com/auth/tasks"},
}

func Scopes(capabilities []string) ([]string, error) {
    unique := map[string]bool{}
    for _, name := range capabilities {
        scopes, ok := registry[name]
        if !ok {
            return nil, fmt.Errorf("unknown capability %q", name)
        }
        for _, scope := range scopes {
            unique[scope] = true
        }
    }
    out := make([]string, 0, len(unique))
    for scope := range unique {
        out = append(out, scope)
    }
    sort.Strings(out)
    return out, nil
}

func Known(name string) bool {
    _, ok := registry[name]
    return ok
}

func All() map[string][]string {
    out := make(map[string][]string, len(registry))
    for name, scopes := range registry {
        out[name] = append([]string(nil), scopes...)
    }
    return out
}
