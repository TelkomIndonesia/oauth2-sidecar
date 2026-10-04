#!/bin/sh
set -eu
repo=TelkomIndonesia/oauth2-sidecar
version=latest
os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case $os in linux|darwin) ;; *) echo unsupported OS >&2; exit 1;; esac
case $arch in x86_64|amd64) arch=amd64;; aarch64|arm64) arch=arm64;; *) echo unsupported architecture >&2; exit 1;; esac
if [ $version = latest ]; then version=$(curl -fsSL https://api.github.com/repos/$repo/releases/latest|awk -F'\"' '/tag_name/{print $4;exit}'); fi
asset=oauth2-sidecar_${version#v}_${os}_${arch}.tar.gz
base=https://github.com/$repo/releases/download/$version
tmp=$(mktemp -d); trap 'rm -rf $tmp' EXIT
curl -fsSL $base/$asset -o $tmp/$asset
curl -fsSL $base/checksums.txt -o $tmp/checksums.txt
if command -v sha256sum >/dev/null; then (cd $tmp && grep "  $asset\$" checksums.txt | sha256sum -c -); else e=$(awk -v f=$asset '$2==f{print $1}' $tmp/checksums.txt); a=$(shasum -a 256 $tmp/$asset|awk '{print $1}'); [ $e = $a ]; fi
target=${INSTALL_DIR:-$HOME/.local/bin}; mkdir -p $target; tar -xzf $tmp/$asset -C $tmp; install -m 0755 $tmp/oauth2-sidecar $target/oauth2-sidecar
echo installed to $target/oauth2-sidecar
