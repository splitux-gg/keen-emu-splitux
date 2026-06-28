#!/usr/bin/env bash
# Attach splitux-together to the live Enshrouded gamescope-splitux node.
set -uo pipefail
cd "$HOME/Code/splitux-together"
NODE="${1:?need pipewire node id}"
TGT="$(cargo metadata --no-deps --format-version 1 | grep -o '"target_directory":"[^"]*"' | cut -d'"' -f4)/debug"
SC=/tmp/claude-1000/-mnt-games/2c634b19-bed6-44d7-8d63-bc6b7862b9cc/scratchpad
export LIBVA_DRIVER_NAME=radeonsi

# orchestrator (reuse if already on :8080)
if ! curl -sf http://127.0.0.1:8080/api/seats >/dev/null 2>&1; then
  "$TGT/orchestrator" --web web > "$SC/orch.log" 2>&1 &
  echo "ORCH=$!"; sleep 1
fi

# seat-streamer: stream the Enshrouded gamescope node as seat-1 (x264, robust)
RUST_LOG=info "$TGT/seat-streamer" \
  --seat seat-1 --name "Enshrouded" \
  --source pipewire --pw-node "$NODE" \
  --width 1920 --height 1080 --fps 60 --bitrate 20000 \
  --encoder x264 \
  --signalling ws://127.0.0.1:8080/ws/producer > "$SC/seat.log" 2>&1 &
echo "SEAT=$!"
echo "logs: orch=$SC/orch.log seat=$SC/seat.log"
