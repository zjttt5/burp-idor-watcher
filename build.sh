#!/usr/bin/env bash
# Build the extension jar.
#
# Requires: JDK 17+  (javac, jar)
# Requires: lib/montoya-api.jar  -- run scripts/extract-montoya-api.sh first

set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

API_JAR="lib/montoya-api.jar"
SRC="src/IdorWatcher.java"
OUT_DIR="out"
DIST_DIR="dist"
JAR_NAME="idor-watcher.jar"

if [ ! -f "$API_JAR" ]; then
    echo "[!] missing $API_JAR" >&2
    echo "    run: ./scripts/extract-montoya-api.sh /path/to/burpsuite.jar ./lib" >&2
    exit 1
fi

if ! command -v javac >/dev/null 2>&1; then
    echo "[!] javac not found. Install a JDK (17+), not just a JRE." >&2
    exit 1
fi

echo "[*] javac: $(javac -version 2>&1)"
rm -rf "$OUT_DIR" "$DIST_DIR"
mkdir -p "$OUT_DIR" "$DIST_DIR"

javac --release 17 -encoding UTF-8 -cp "$API_JAR" -d "$OUT_DIR" "$SRC"
jar cf "$DIST_DIR/$JAR_NAME" -C "$OUT_DIR" .

echo "[+] built: $DIST_DIR/$JAR_NAME ($(wc -c < "$DIST_DIR/$JAR_NAME") bytes)"
echo "    load it in Burp: Extensions -> Installed -> Add -> Java"
