# AGENTS.md

## Authority

Before changing Google Access Hub, fresh-read `tevriqorg/infra#46`. It is the requirement and implementation authority. Chat history and old comments do not override it.

## Security rules

- Never commit Google client secrets, refresh tokens, service credentials, master keys, real account data, or production audit payloads.
- Refresh tokens belong only to Google Access Hub. Downstream services must never receive them.
- Request Google scopes incrementally and only for a real implemented consumer.
- Do not add an arbitrary URL proxy. Google upstream hosts, methods, and paths must be explicitly modeled.
- Real Google OAuth/API access is blocked until `tevriqorg/infra#46` reaches G4.
- Mail Hub Gmail Census/backfill remains separately governed by `tevriqorg/infra#39`.

## Build and deployment governance

This is a public repository. All release compilation and tests run in GitHub Actions. Runtime hosts only download, verify, and deploy Actions artifacts. Do not run release `go build`, `go test`, or equivalent production build commands on Vela.

Every deployable artifact must include commit/run provenance and SHA256 verification.
