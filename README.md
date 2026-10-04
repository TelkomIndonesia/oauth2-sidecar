# oauth2-sidecar

Local OAuth2/OIDC-authenticated reverse proxy for OAuth-unaware clients. It performs OIDC discovery, Authorization Code + PKCE login, secure localhost callback handling, refresh-token rotation, and injects the current OAuth2 access token into an upstream request.

## Quick start

```sh
curl -fsSL https://raw.githubusercontent.com/TelkomIndonesia/oauth2-sidecar/main/install.sh | sh
oauth2-sidecar --issuer https://auth.example.com --client-id my-client --scope "openid offline_access api" --upstream https://api.example.com --listen 127.0.0.1:8080
curl http://127.0.0.1:8080/v1/foo
```

The default listener is loopback. Register `http://127.0.0.1:<port>/callback`; use `--redirect-port` for a stable port. Flags have precedence over `OAUTH2_SIDECAR_*` environment variables. Use `--logout` to remove the saved token.

## Security

OIDC discovery and ID-token verification use `go-oidc`; OAuth flows and refresh use `x/oauth2`. State and PKCE values are cryptographically random. Incoming Authorization headers are overwritten. Tokens are written with restrictive permissions to the configured user-state path. Keep the proxy on loopback unless the network is deliberately secured.

## Development

```sh
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/oauth2-sidecar
```

Provider setup is standard for Keycloak, Authentik, Dex, Microsoft Entra ID, and generic OIDC: create a public/native Authorization Code + PKCE client, register the callback, and request `offline_access` when refresh tokens are required. Releases target Linux and macOS amd64/arm64 and publish SHA256 checksums.

Apache-2.0 licensed.
