#!/bin/sh
# Installs the latest stackradar CLI release into /usr/local/bin (or $BINDIR).
#   curl -fsSL https://raw.githubusercontent.com/lockdep/stackradar-cli/main/install.sh | sh
set -eu
REPO=lockdep/stackradar-cli
BINDIR=${BINDIR:-/usr/local/bin}
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in x86_64) ARCH=amd64;; aarch64|arm64) ARCH=arm64;; *) echo "unsupported arch $ARCH"; exit 1;; esac
TAG=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p')
VER=${TAG#v}
URL="https://github.com/$REPO/releases/download/$TAG/stackradar_${VER}_${OS}_${ARCH}.tar.gz"
TMP=$(mktemp -d)
echo "Downloading $URL"
curl -fsSL "$URL" | tar -xz -C "$TMP"
if [ -w "$BINDIR" ]; then install -m 0755 "$TMP/stackradar" "$BINDIR/stackradar"; else sudo install -m 0755 "$TMP/stackradar" "$BINDIR/stackradar"; fi
rm -rf "$TMP"
echo "Installed $("$BINDIR/stackradar" --version) to $BINDIR/stackradar"
echo "Run:  stackradar scan"
