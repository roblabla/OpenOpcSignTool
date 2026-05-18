#!/usr/bin/env bash
# Regenerate golden C14N outputs from .NET XmlDsigC14NTransform.
# Requires: dotnet SDK, an HLKX at HLKX_PATH (or uses /tmp fixtures).

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REF="$ROOT/c14n-reference"
OUT="$(cd "$(dirname "$0")" && pwd)"
DOTNET_DLL="$REF/bin/Debug/net8.0/C14nReference.dll"

dotnet build "$REF" -v q -o "$REF/bin/Debug/net8.0"

HLKX="${HLKX_PATH:-/Users/roblabla/Downloads/hlelam_4.2.0.signed.hlkx}"
if [[ ! -f "$HLKX" ]]; then
  echo "Set HLKX_PATH to a signed HLKX file" >&2
  exit 1
fi

SIG_PART="package/services/digital-signature/xml-signature"
SIG_FILE=$(unzip -Z1 "$HLKX" | grep '\.psdsxs$' | head -1)
unzip -p "$HLKX" "$SIG_FILE" > "$OUT/signature.xml"
unzip -p "$HLKX" "_rels/.rels" > "$OUT/rels.xml"

python3 - <<'PY' "$OUT/signature.xml"
import sys
sig = open(sys.argv[1]).read()
for tag in ("Object", "SignedInfo"):
    if tag == "Object":
        start = sig.find('<Object Id="idPackageObject">')
    else:
        start = sig.find("<SignedInfo")
    end = sig.find(f"</{tag}>") + len(f"</{tag}>")
    open(f"{sys.argv[1].replace('signature.xml', tag.lower() + '.xml')}", "w").write(sig[start:end])
PY

dotnet "$DOTNET_DLL" "$OUT/rels.xml" "$OUT/rels.c14n"
dotnet "$DOTNET_DLL" "$OUT/object.xml" "$OUT/object.c14n"
dotnet "$DOTNET_DLL" "$OUT/signedinfo.xml" "$OUT/signedinfo.c14n"

SI="$OUT/signedinfo.xml"
python3 -c "
s=open('$SI').read()
open('$OUT/signedinfo_xmlns.xml','w').write(s.replace('<SignedInfo>', '<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">', 1))
open('$OUT/signedinfo_wrapped.xml','w').write('<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">'+s+'</Signature>')
"
dotnet "$DOTNET_DLL" "$OUT/signedinfo_xmlns.xml" "$OUT/signedinfo_xmlns.c14n"
dotnet "$DOTNET_DLL" "$OUT/signedinfo_wrapped.xml" "$OUT/signedinfo_wrapped.c14n"

echo "Wrote golden files to $OUT"
