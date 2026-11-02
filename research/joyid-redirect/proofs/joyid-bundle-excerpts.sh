#!/usr/bin/env bash
# Downloads JoyID's live web app (testnet + mainnet), records each bundle's URL, sha256 and date, and prints the
# short excerpts the README cites, with byte offsets. JoyID's app is closed source; this is the primary evidence
# for how its pages deliver results. Usage: bash research/joyid-redirect/proofs/joyid-bundle-excerpts.sh
set -euo pipefail
dir=$(mktemp -d)
echo "fetched: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
for host in https://testnet.joyid.dev https://app.joy.id; do
  echo; echo "################ $host"
  curl -sS -D "$dir/h" -o "$dir/index.html" "$host/sign-message?type=redirect"
  echo "-- response headers of $host/sign-message (security-relevant):"
  grep -i -E '^(cross-origin|content-security|x-frame|referrer-policy|strict-transport)' "$dir/h" || true
  echo "   (no Cross-Origin-Opener-Policy / COEP / CSP header is sent)"
  main=$(grep -o 'src="/assets/index-[^"]*\.js"' "$dir/index.html" | cut -d'"' -f2)
  curl -sS -o "$dir/main.js" "$host$main"
  echo "-- main bundle $host$main sha256 $(sha256sum "$dir/main.js" | cut -d' ' -f1) bytes $(wc -c < "$dir/main.js")"
  files=("$dir/main.js")
  if [ "$host" = https://testnet.joyid.dev ]; then
    # The /sign-message route is a lazy chunk: find it by its SignMessage page wrapper.
    for p in $(grep -o '"\./[A-Za-z0-9_@.-]*\.js"' "$dir/main.js" | tr -d '"' | sed 's#^\./#/assets/#' | sort -u); do
      curl -sS -o "$dir/c.js" "$host$p"
      if grep -q 'Invalid redirectURL' "$dir/c.js" && grep -q 'requestType:g.SignMessage' "$dir/c.js"; then
        cp "$dir/c.js" "$dir/signmessage.js"; echo "-- sign-message chunk $host$p sha256 $(sha256sum "$dir/c.js" | cut -d' ' -f1)"; files+=("$dir/signmessage.js"); break
      fi
    done
  fi
  python3 -I - "${files[@]}" <<'PY'
import sys
pats = [
  ("sendMessageToDapp (popup: window.opener.postMessage; redirect: _data_ in QUERY + location.replace)", "sendMessageToDapp=async", 0, 330),
  ("useGuardRedirectUri (referrer origin must match redirectURL origin; allowed protocols)", "useGuardRedirectUri=()=>", 0, 520),
  ("generateSignedInfo (message = base64url(authenticatorData || clientDataJSON))", "generateSignedInfo=", 0, 560),
  ("sendSignedMessageToDapp (one result object for both modes)", "sendSignedMessageToDapp=async", 0, 760),
  ("useSendSignedMessageToDapp (CKB text: challenge = base64url(utf8(text)); isData: hex bytes)", "useSendSignedMessageToDapp=", 0, 1700),
  ("useSignMessage (WebAuthn startAuthentication with the mapped challenge)", "useSignMessage=(", 0, 520),
  ("AUTH_MESSAGE_PREFIX (Auth with a challenge signs a PREFIXED text)", "AUTH_MESSAGE_PREFIX=", 0, 60),
  ("useSdkPopupGuard (popup mode warns when window.opener is gone)", "useSdkPopupGuard=", 0, 420),
  ("sign-ckb-raw-tx delivery is hard-coded popup", "data:{tx:Zn}},fn,DappCommunicationType.Popup", -120, 160),
  ("SignMessage page: one component for both modes; shows name, host, message", "o(\"sign\",{title:e.name})", -40, 420),
  ("SignMessage route: type defaults to redirect, referrer check", "T=()=>{const[e]=je(),a=e.get(\"type\")", 0, 640),
]
for path in sys.argv[1:]:
    s = open(path, encoding="utf-8", errors="replace").read()
    for title, key, before, length in pats:
        i = s.find(key)
        if i < 0: continue
        print(f"\n== {title}\n   [{path.rsplit('/',1)[-1]} @ character offset {i}]\n   {s[max(0,i+before):i+length]}")
PY
done
rm -rf "$dir"
