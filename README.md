# Google Access Hub

Google Access Hub is a private credential and authorization broker for the owner's services. It centralizes Google user OAuth grants so downstream services can request capabilities without storing Google refresh tokens themselves.

Authority: [`tevriqorg/infra#46`](https://github.com/tevriqorg/infra/issues/46).

## Design

- OAuth 2.0 authorization-code flow with PKCE S256.
- Offline access and incremental authorization.
- Encrypted refresh-token vault.
- Capability-to-Google-scope registry.
- Per-service capability credentials.
- Metadata-only audit trail.
- Tailnet-only internal API by deployment policy.
- No arbitrary Google proxy and no refresh-token export.

## Runtime configuration

The service can start without Google OAuth credentials for pre-auth testing. Real Google OAuth remains blocked until G4 in the authority Issue.

Required runtime secrets:

- `GAH_MASTER_KEY`: base64/base64url encoded 32-byte key.
- `GAH_ADMIN_TOKEN`: bootstrap administration bearer token, at least 32 characters.

Optional until real OAuth:

- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `GOOGLE_REDIRECT_URL`

Other settings:

- `GAH_ADDR` (default `127.0.0.1:18120`)
- `GAH_DATA_FILE` (default `./data/google-access-hub.json`)

## Build

Release artifacts are built only by GitHub Actions. See `.github/workflows/runtime-artifacts.yml`.
