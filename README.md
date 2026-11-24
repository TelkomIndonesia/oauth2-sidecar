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

On Windows, install from PowerShell with `irm https://raw.githubusercontent.com/TelkomIndonesia/oauth2-sidecar/main/install.ps1 | iex`; it puts `oauth2-sidecar.exe` in `%LOCALAPPDATA%\Programs\oauth2-sidecar` and adds that folder to the user `Path`. The first run opens a browser and also logs the login URL, so it can be opened by hand where no browser starts (for example WSL without `wslu`, or over SSH). The client can then call `http://127.0.0.1:8080/v1/foo`; the sidecar forwards it to the upstream with `Authorization: Bearer <access_token>`. The default listener is loopback. Register `http://127.0.0.1:<port>/callback` with the provider, or use `--redirect-port` for a stable callback port.

## Personal access through a validator

The `device` command runs on each developer's computer. The `validate` command runs behind the HTTPS route in OpenShift. Each request carries the developer's OAuth access token to the validator. The backend receives its original application credentials and payload.

**Server.** Register a dedicated public GitLab OAuth application with the `openid` and `email` scopes and the redirect URI `http://127.0.0.1:8250/callback`. Run the validator with that application's ID, the GitLab user IDs allowed to access this backend, and a fixed backend URL:

```sh
oauth2-sidecar validate --issuer https://gitlab.example.com \
  --client-id my-public-app-id --allow-users 17,24 \
  --upstream http://my-api:8080 --listen :8080
```

Target the validator with the HTTPS route and restrict direct access to the backend according to your cluster policy. An alternative route directly to the application remains outside this check. A [Containerfile](deploy/validator.Containerfile) builds the binary for an OpenShift deployment. The runtime needs the GitLab HTTPS CA and outbound access to GitLab.

The validator checks the OAuth application ID, `openid` scope, allowed user ID, and matching subject using GitLab's `/oauth/token/info` and `/oauth/userinfo`. Each validator instance caches successful checks by token hash for up to 30 seconds, capped by the token's remaining lifetime. Revocation can take up to that long to take effect. Tokens with no reported expiry are checked on every request. When a fresh check is required and GitLab is unavailable, the request fails before forwarding. [GitLab token information](https://docs.gitlab.com/api/oauth2/#retrieve-the-token-information) · [GitLab OIDC claims](https://docs.gitlab.com/integration/openid_connect_provider/#shared-information)

Each authorized request produces an audit event with the incoming HTTP `method`, `path` (query string omitted), `oidc_issuer`, and `oidc_sub`. A verified email from GitLab adds `gitlab_email`. The validator removes the device credential header (`X-Sidecar-Authorization`) before forwarding.

**Developer computer.** Install a version that includes `device` (Linux, macOS, or Windows; amd64 or arm64). The Unix installer is in Quick start above. On Windows, the same release can be installed with curl from PowerShell:

```powershell
$installer = curl.exe -fsSL https://raw.githubusercontent.com/TelkomIndonesia/oauth2-sidecar/main/install.ps1
if ($LASTEXITCODE -eq 0) { & ([scriptblock]::Create(($installer -join [Environment]::NewLine))) }
```

Configure each computer once. Enter the GitLab issuer, public OAuth application ID, and HTTPS validator URL supplied by your administrator. Complete personal sign-in in the browser.

```sh
oauth2-sidecar device setup
oauth2-sidecar device
```

With the device command running, call the local listener from another terminal. Keep the original method, path, headers, and body. The base URL becomes `http://127.0.0.1:18080`:

```sh
curl -H 'Content-Type: application/json' -d '{"operation":"example"}' http://127.0.0.1:18080/rpc
```

Setup saves `device.json` in the OS user's configuration directory under `oauth2-sidecar`. Token storage is separate per OS profile, issuer, application, scopes, and validator URL. The client reuses valid tokens and refreshes expired ones. Stop the client before `oauth2-sidecar device logout` to delete its local cache, or use `oauth2-sidecar device login` to force a fresh sign-in. Use the listener on a personal workstation: local processes able to reach it can act through that user's session.

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

## Device login

Use `--device` (`OAUTH2_SIDECAR_DEVICE`, or `device: true` in a config file) where no browser can run, such as a server or a container. The sidecar uses the OAuth 2.0 device authorization grant ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)) and logs a verification URL and user code; approve the login from any device. The provider must advertise `device_authorization_endpoint` in its discovery document, and the verification URL must be HTTPS. Tokens are stored and refreshed the same way as with the browser login.

## Configuration

Use `--config` to load settings from a YAML or JSON file, from stdin (`-`), or from an `http://` or `https://` URL, so a team can share one routing file:

```yaml
issuer: https://auth.example.com
client-id: my-client
host-route:
  app.local: https://app.internal.example:8443/base
  admin.local: https://admin.internal.example=10.0.0.30
```

```sh
oauth2-sidecar --config https://config.example.com/oauth2-sidecar.yaml --listen 127.0.0.1:9090
```

Keys are flag names. Unknown keys are rejected, and `login`, `logout`, and `version` cannot be set from a file. The config decides where tokens are sent, so serve plain `http://` configs only on a network you trust. An `https://` config that redirects to `http://` is rejected. A `--host-route` flag replaces the file's routes rather than adding to them.

The default token cache is separate for each issuer, client ID, scope set, and listen address. Use a different fixed listen port for each independent session to reuse its cache after restarting. With port zero, the assigned listener address selects the cache. For logout, use the same profile and listen address, or use the exact cache path with `--token-store`. An explicit `--token-store` selects one file, so give independent sessions different paths. The first run with the new default requires login. The old `token.json` remains on disk.

Flags take precedence over environment variables, and both take precedence over the config file. Run `oauth2-sidecar --help` for the full list. Supported environment variables include `OAUTH2_SIDECAR_ISSUER`, `OAUTH2_SIDECAR_ISSUER_IP`, `OAUTH2_SIDECAR_CLIENT_ID`, `OAUTH2_SIDECAR_SCOPE`, `OAUTH2_SIDECAR_UPSTREAM`, `OAUTH2_SIDECAR_LISTEN`, `OAUTH2_SIDECAR_REDIRECT_PORT`, `OAUTH2_SIDECAR_TOKEN_STORE`, `OAUTH2_SIDECAR_TOKEN_HEADER`, `OAUTH2_SIDECAR_HOST_ROUTE`, `OAUTH2_SIDECAR_INSECURE_SKIP_VERIFY`, `OAUTH2_SIDECAR_DEVICE`, and `OAUTH2_SIDECAR_VERBOSE`. Use `--login` to force authentication, `--logout` to remove the saved token, and `--version` to print the build version. Use `--verbose` (or `-v`) to enable debug logging.

## Security

OIDC discovery and ID-token verification use `github.com/coreos/go-oidc/v3/oidc`; OAuth flows and refresh use `golang.org/x/oauth2`. State and PKCE values are cryptographically random. The token header (`Authorization` unless `--token-header` says otherwise) is always overwritten, so a client cannot forward its own value. With a different `--token-header`, the client's `Authorization` passes through, which lets an app send its own credentials next to the sidecar token. Tokens are written with restrictive permissions to the configured user-state path; on Windows the file mode is not enforced, so protection comes from the user profile ACL of `%AppData%`. Keep the proxy on loopback unless the network is deliberately secured, and never commit token files.

## Development

```sh
go mod tidy
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/oauth2-sidecar
```

Provider setup is standard for Keycloak, Authentik, Dex, Microsoft Entra ID, and generic OIDC: create a public/native Authorization Code + PKCE client, register the localhost callback, and request `offline_access` when refresh tokens are required. Verify provider-specific scopes and callback policies with the provider documentation. Releases target Linux, macOS, and Windows on amd64/arm64 and publish SHA256 checksums.

## License

Apache-2.0.
