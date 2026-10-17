# Architecture

## Trust boundaries

Google Access Hub is the only component that owns Google refresh tokens. Internal callers authenticate with independent service credentials and can request only capabilities registered for that service.

The internal management and broker API is intended to be Tailnet-only. The Google OAuth callback is a narrow browser-facing HTTPS route on a domain owned and verifiable by the operator. A `.ts.net` name is not the final Google OAuth domain because the operator does not own that parent domain.

## Capability model

Stable internal capabilities map to Google scope strings. Callers reason about capabilities; Google scopes remain an implementation detail. Scope grants are incremental and recorded per Google subject.

## Credential lanes

v0.1 implements Google User OAuth. Future lanes may add service accounts and product-specific credentials without changing downstream client identity or audit semantics.

## Token handling

Refresh tokens are AES-256-GCM encrypted at rest with a versioned envelope. PKCE verifiers stored for pending authorization transactions use the same encrypted envelope and expire quickly. Google access tokens are not persisted.

The default downstream pattern is provider-specific brokerage, not raw token export. A future token lease escape hatch, if ever enabled, must be explicitly high-trust and may never export refresh tokens.

Authenticated admin and service principals are independently rate-limited; the v0.1 default is 120 requests per minute per principal. OAuth state plus PKCE bind the authorization flow. The Hub does not consume Google ID tokens in v0.1, so an OIDC nonce is not part of this userinfo-based flow; a nonce becomes mandatory if a future implementation consumes ID tokens.
