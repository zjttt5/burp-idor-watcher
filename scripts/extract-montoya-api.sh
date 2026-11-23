#!/usr/bin/env bash
# Extract montoya-api.jar from a Burp Suite installation.
#
# Usage:
#   ./extract-montoya-api.sh [path-to-burpsuite.jar] [output-dir]
#
# The API jar is bundled inside burpsuite.jar at:
#   resources/Tooling/libraries/montoya-api.jar
# Using the API that ships with your Burp guarantees version compatibility.

set -e

BURP_JAR="${1:-/usr/share/burpsuite/burpsuite.jar}"
OUT_DIR="${2:-./lib}"
OUT_FILE="${OUT_DIR}/montoya-api.jar"
ENTRY="resources/Tooling/libraries/montoya-api.jar"

if [ ! -f "$BURP_JAR" ]; then
    echo "[!] burpsuite.jar not found: $BURP_JAR" >&2
    echo "    Pass the path as the first argument, e.g." >&2
    echo "    ./extract-montoya-api.sh /opt/BurpSuite/burpsuite.jar ./lib" >&2
    exit 1
fi

mkdir -p "$OUT_DIR"

if command -v python3 >/dev/null 2>&1; then
    python3 - "$BURP_JAR" "$ENTRY" "$OUT_FILE" <<'PY'
import sys, zipfile
src, entry, dst = sys.argv[1], sys.argv[2], sys.argv[3]
with zipfile.ZipFile(src) as z:
    try:
        data = z.read(entry)
    except KeyError:
        sys.exit("[!] entry not found inside jar: " + entry)
open(dst, "wb").write(data)
print("[+] wrote %s (%d bytes)" % (dst, len(data)))
PY
elif command -v unzip >/dev/null 2>&1; then
    unzip -p "$BURP_JAR" "$ENTRY" > "$OUT_FILE"
    echo "[+] wrote $OUT_FILE ($(wc -c < "$OUT_FILE") bytes)"
else
    echo "[!] need python3 or unzip to extract the entry" >&2
    exit 1
fi

# sanity check: the API jar must contain the entry point interface
if unzip -l "$OUT_FILE" 2>/dev/null | grep -q "burp/api/montoya/MontoyaApi.class"; then
    echo "[+] verified: burp/api/montoya/MontoyaApi.class present"
else
    echo "[!] warning: MontoyaApi.class not found in extracted jar" >&2
fi
