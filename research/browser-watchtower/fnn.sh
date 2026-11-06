#!/usr/bin/env bash
# Starts or stops one of the proof's two FNN 0.9.1 testnet nodes (see README.md in this folder).
#   FNN=…/fnn CONFIG=…/config/testnet/config.yml PROOF=<dir with C/ and V/> FIBER_SECRET_KEY_PASSWORD=… fnn.sh start C|V
#   fnn.sh stop C|V
# C (the cheater) runs with Fiber's built-in watchtower as usual. V (the victim, standing in for a browser node)
# runs without one and sends its watchtower calls to the relay, as a browser node sends them to the page.
set -euo pipefail
action=$1 name=$2
dir="$PROOF/$name"
case "$name" in
  C) rpc=127.0.0.1:8237 p2p=8238 extra=() ;;
  V) rpc=127.0.0.1:8247 p2p=8248 extra=(--fiber-disable-built-in-watchtower true --fiber-standalone-watchtower-rpc-url http://127.0.0.1:18300) ;;
  *) echo "unknown node $name" >&2; exit 1 ;;
esac
if [ "$action" = start ]; then
  nohup "$FNN" -d "$dir" -c "$CONFIG" \
    --fiber-listening-addr "/ip4/127.0.0.1/tcp/$p2p" --fiber-announce-listening-addr false \
    --rpc-listening-addr "$rpc" --ckb-node-rpc-url "${CKB_RPC:-https://testnet.ckb.dev/}" "${extra[@]}" \
    >>"$dir/fnn.log" 2>&1 &
  echo $! >"$dir/pid"
  for _ in $(seq 60); do
    curl -sf -X POST "http://$rpc" -H 'content-type: application/json' -d '{"id":1,"jsonrpc":"2.0","method":"node_info","params":[]}' >/dev/null && { echo "$name up (rpc $rpc)"; exit 0; }
    sleep 1
  done
  echo "$name did not start; see $dir/fnn.log" >&2; exit 1
else
  kill "$(cat "$dir/pid")" 2>/dev/null || true
  for _ in $(seq 30); do kill -0 "$(cat "$dir/pid")" 2>/dev/null || { echo "$name stopped"; exit 0; }; sleep 1; done
  kill -9 "$(cat "$dir/pid")" 2>/dev/null || true; echo "$name killed"
fi
