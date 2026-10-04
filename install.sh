#!/bin/sh
set -e

repo="TelkomIndonesia/oauth2-sidecar"
version="$OAUTH2_SIDECAR_VERSION"
[ -n "$version" ] || version=latest
os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)

command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { echo "tar is required" >&2; exit 1; }
case "$os" in linux|darwin) ;; *) echo "unsupported OS: $os (Linux and macOS are supported)" >&2; exit 1 ;; esac
case "$arch" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) echo "unsupported architecture: $arch" >&2; exit 1 ;; esac

if [ "$version" = latest ]; then
  version=$(curl --retry 3 -fsSL "https://api.github.com/repos/$repo/releases/latest" | awk -F'"' '/tag_name/{print $4; exit}')
fi
case "$version" in v*) ;; *) version="v$version" ;; esac
[ -n "$version" ] || { echo "could not determine release version" >&2; exit 1; }
version_no_v=$(printf '%s' "$version" | sed 's/^v//')
asset="oauth2-sidecar_${version_no_v}_${os}_${arch}.tar.gz"
base="https://github.com/$repo/releases/download/$version"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl --retry 3 -fsSL "$base/$asset" -o "$tmp/$asset"
curl --retry 3 -fsSL "$base/checksums.txt" -o "$tmp/checksums.txt"
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$tmp" && grep "  $asset\$" checksums.txt | sha256sum -c -)
elif command -v shasum >/dev/null 2>&1; then
  expected=$(awk -v f="$asset" '$2 == f {print $1}' "$tmp/checksums.txt")
  actual=$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')
  [ -n "$expected" ] && [ "$expected" = "$actual" ]
else
  echo "sha256sum or shasum is required for checksum verification" >&2
  exit 1
fi

target="$INSTALL_DIR"
[ -n "$target" ] || { if [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then target=/usr/local/bin; else target="$HOME/.local/bin"; fi; }
mkdir -p "$target"
tar -xzf "$tmp/$asset" -C "$tmp"
install -m 0755 "$tmp/oauth2-sidecar" "$target/oauth2-sidecar"
echo "installed oauth2-sidecar $version to $target/oauth2-sidecar"
case ":$PATH:" in *":$target:"*) ;; *) echo "Add $target to PATH to run oauth2-sidecar directly." >&2 ;; esac
