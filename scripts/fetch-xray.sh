#!/bin/sh
set -eu

XRAY_VERSION="${XRAY_VERSION:-v26.7.28}"
XRAY_SHA256="${XRAY_SHA256:-8195d909f1109b8f3d99eefe401a3c451d7bf4af71f24d3815420f77e5dd2a40}"
ASSET="Xray-linux-64.zip"
URL="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/${ASSET}"
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

command -v curl >/dev/null 2>&1 || {
	echo "curl is required" >&2
	exit 1
}
command -v unzip >/dev/null 2>&1 || {
	echo "unzip is required" >&2
	exit 1
}

echo "Downloading Xray-core ${XRAY_VERSION}..." >&2
curl --fail --location --retry 3 --output "$TMP/$ASSET" "$URL"
printf '%s  %s\n' "$XRAY_SHA256" "$TMP/$ASSET" | sha256sum --check -
unzip -q "$TMP/$ASSET" xray -d "$TMP"
install -m 0600 "$TMP/xray" "$ROOT/core/xray"
