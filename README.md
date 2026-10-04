# oauth2-sidecar

Local OAuth2/OIDC-authenticated reverse proxy for applications that cannot implement OAuth2 themselves. It performs OIDC discovery, Authorization Code + PKCE login, secure localhost callback handling, token persistence and refresh, then injects the current access token into requests sent to the configured API.

## Quick start

```sh
curl -fsSL https://raw.githubusercontent.com/TelkomIndonesia/oauth2-sidecar/main/install.sh | sh
oauth2-sidecar \
  --issuer https://auth.example.com \
  --client-id my-client \
  --scope "openid offline_access api" \
  --upstream https://api.example.com \
  --listen 127.0.0.1:8080
```

The first run opens a browser. The client can then call `http://127.0.0.1:8080/v1/foo`; the sidecar forwards it to the upstream with `Authorization: Bearer <access_token>`. The default listener is loopback. Register `http://127.0.0.1:<port>/callback` with the provider, or use `--redirect-port` for a stable callback port.

## Host mapping

Use the repeatable `--host-mapping source-host=upstream-host` option when the upstream URL and the HTTP virtual host are different:

```sh
oauth2-sidecar ... \
  --upstream https://10.0.0.20 \
  --host-mapping api.local=api.internal.example
```

The source is matched against the incoming client `Host` header (case-insensitively), and the destination becomes the upstream request's `Host` header. Use `--host-mapping '*=default.internal.example'` as a fallback. Multiple mappings can be supplied. The equivalent environment variable is comma-separated, for example `OAUTH2_SIDECAR_HOST_MAPPING=api.local=api.internal.example,admin.local=admin.internal.example`. The configured upstream URL still determines the destination scheme and network address.

## Configuration

Flags take precedence over environment variables. Supported environment variables include `OAUTH2_SIDECAR_ISSUER`, `OAUTH2_SIDECAR_CLIENT_ID`, `OAUTH2_SIDECAR_SCOPE`, `OAUTH2_SIDECAR_UPSTREAM`, `OAUTH2_SIDECAR_LISTEN`, `OAUTH2_SIDECAR_REDIRECT_PORT`, `OAUTH2_SIDECAR_TOKEN_STORE`, and `OAUTH2_SIDECAR_HOST_MAPPING`. Use `--login` to force authentication, `--logout` to remove the saved token, and `--version` to print the build version.

## Security

OIDC discovery and ID-token verification use `github.com/coreos/go-oidc/v3/oidc`; OAuth flows and refresh use `golang.org/x/oauth2`. State and PKCE values are cryptographically random. Incoming Authorization headers are overwritten so local credentials are not forwarded. Tokens are written with restrictive permissions to the configured user-state path. Keep the proxy on loopback unless the network is deliberately secured, and never commit token files.

## Development

```sh
go mod tidy
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/oauth2-sidecar
```

Provider setup is standard for Keycloak, Authentik, Dex, Microsoft Entra ID, and generic OIDC: create a public/native Authorization Code + PKCE client, register the localhost callback, and request `offline_access` when refresh tokens are required. Verify provider-specific scopes and callback policies with the provider documentation. Releases target Linux and macOS amd64/arm64 and publish SHA256 checksums.

## License

Apache-2.0.
