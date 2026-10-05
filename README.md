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

## Host routes

Use the repeatable `--host-route local-host=scheme://remote-host[/path][=remote-ip]` option to send requests for a specific local hostname to a different origin and base path:

```sh
oauth2-sidecar ... \
  --upstream https://api.example.com \
  --host-route app.local=https://app.internal.example:8443/base
```

A request with `Host: app.local` is forwarded to `https://app.internal.example:8443/base` plus the incoming request path (for example `/v1/foo` becomes `/base/v1/foo`). Both `http` and `https` targets are allowed. The source is matched against the incoming client `Host` header (case-insensitively, with the port stripped). Routes take precedence over the `--upstream` destination. Multiple routes can be supplied. The equivalent environment variable is comma-separated, for example `OAUTH2_SIDECAR_HOST_ROUTE=app.local=https://app.internal.example:8443/base,admin.local=https://admin.internal.example`.

`--upstream` is optional when `--host-route` already defines where a request goes. Without `--upstream`, only routed hosts are proxied and requests whose host matches no route are rejected with `502 Bad Gateway`.

### Upstream IP override

Append `=remote-ip` to a route to connect to a specific IPv4 or IPv6 address while keeping the URL hostname for the `Host` header, TLS SNI, and certificate verification — the upstream equivalent of `--issuer-ip`:

```sh
oauth2-sidecar ... \
  --host-route app.local=https://app.internal.example:8443=10.0.0.30
```

The sidecar dials `10.0.0.30:8443` but still sends `Host: app.internal.example:8443` and TLS SNI `app.internal.example`, so certificate verification is unchanged. Requests whose target host has an IP override bypass any configured HTTP proxy. The remote IP must be a bare IPv4 or IPv6 address (no port); malformed values fail at startup.

## TLS verification

Proxied upstream requests verify TLS certificates by default. Use `--insecure-skip-verify` to skip certificate verification for proxied upstream requests only:

```sh
oauth2-sidecar ... \
  --upstream https://10.0.0.20 \
  --insecure-skip-verify
```

This flag affects only the upstream transport. OIDC discovery, token, JWKS, ID-token issuer checks, and the `--issuer-ip` client keep verifying the issuer certificate. The equivalent environment variable is `OAUTH2_SIDECAR_INSECURE_SKIP_VERIFY`.

## Issuer IP override

Use `--issuer-ip` to connect to a specific IPv4 or IPv6 address while keeping the `--issuer` hostname for OIDC discovery, token, JWKS, TLS verification, and ID-token issuer checks:

```sh
oauth2-sidecar ... \
  --issuer https://auth.example.com \
  --issuer-ip 10.0.0.5
```

The sidecar dials `10.0.0.5` but still sends the `Host` header and TLS SNI for `auth.example.com`, so certificate verification is unchanged. This is useful when the issuer hostname does not resolve inside the sidecar network. Only the sidecar's issuer requests are affected: requests to the issuer hostname bypass any configured HTTP proxy, the embedded browser is unaffected because it uses the system resolver, and requests to any other host are unchanged. The equivalent environment variable is `OAUTH2_SIDECAR_ISSUER_IP`.

## Configuration

Flags take precedence over environment variables. Run `oauth2-sidecar --help` for the full list. Supported environment variables include `OAUTH2_SIDECAR_ISSUER`, `OAUTH2_SIDECAR_ISSUER_IP`, `OAUTH2_SIDECAR_CLIENT_ID`, `OAUTH2_SIDECAR_SCOPE`, `OAUTH2_SIDECAR_UPSTREAM`, `OAUTH2_SIDECAR_LISTEN`, `OAUTH2_SIDECAR_REDIRECT_PORT`, `OAUTH2_SIDECAR_TOKEN_STORE`, `OAUTH2_SIDECAR_HOST_ROUTE`, `OAUTH2_SIDECAR_INSECURE_SKIP_VERIFY`, and `OAUTH2_SIDECAR_VERBOSE`. Use `--login` to force authentication, `--logout` to remove the saved token, and `--version` to print the build version. Use `--verbose` (or `-v`) to enable debug logging.

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
