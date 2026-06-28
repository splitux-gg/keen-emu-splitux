#!/usr/bin/env bash
# Two Enshrouded instances over goldberg LAN, BOTH pointed at the keen-emu auth
# server (--keenonline-server-data-file).  instA hosts public (Keen auth -> Steam
# lobby via goldberg), instB joins over LAN.  Adapted from ensh-2inst.sh.
# Requires the emu running on 127.0.0.1:27503 with a matching keenonline-emu.json.
set -uo pipefail
GAME_ROOT=/mnt/games/Enshrouded.v0.9.1.2/Enshrouded
BASE_PFX=/mnt/games/Enshrouded.v0.9.1.2/wine
PROTON=/mnt/games/home/Steam/compatibilitytools.d/GE-Proton10-34
GSC="$HOME/.local/share/splitux/bin/gamescope-splitux"
EXP_API="$HOME/.local/share/splitux/goldberg/win/steam_api64.dll"
DATAFILE='Z:\home\alphasigmachad\Code\keen-emu-splitux\keenonline-emu.json'
SCRATCH=/tmp/splitux-together-bench/ensh-2inst-keen
W=1280; H=720; FPS=30
export LIBVA_DRIVER_NAME=radeonsi
mkdir -p "$SCRATCH"

build_overlay() {  # inst sid name lport pport
  local inst=$1 sid=$2 name=$3 lport=$4 pport=$5 d="$SCRATCH/$1"
  fusermount -uz "$d/game" 2>/dev/null || true
  rm -rf "$d/overlay" "$d/upper" "$d/work"
  mkdir -p "$d/overlay/steam_settings" "$d/upper" "$d/work" "$d/game"
  cp "$EXP_API" "$d/overlay/steam_api64.dll"
  local ss="$d/overlay/steam_settings"
  echo 1203620 > "$d/overlay/steam_appid.txt"
  printf '[user::general]\naccount_name=%s\naccount_steamid=%s\nlanguage=english\n' "$name" "$sid" > "$ss/configs.user.ini"
  cat > "$ss/configs.main.ini" <<INI
[main::general]
new_app_ticket=1
gc_token=1

[main::connectivity]
disable_lan_only=0
disable_networking=0
listen_port=$lport
offline=0
disable_lobby_creation=0
disable_source_query=0
INI
  printf '127.0.0.1:%s\n' "$pport" > "$ss/custom_broadcasts.txt"
  : > "$ss/auto_accept_invite.txt"
  : > "$ss/auto_send_invite.txt"
  printf '2' > "$ss/force_lobby_type.txt"
  : > "$ss/invite_all.txt"
  fuse-overlayfs -o "lowerdir=$d/overlay:$GAME_ROOT" -o "upperdir=$d/upper" -o "workdir=$d/work" "$d/game"
  echo "  $inst overlay mounted ($name $sid listen=$lport peer=$pport)"
}

prep_prefix() {  # inst
  local d="$SCRATCH/$1"
  if [ ! -d "$d/pfx/drive_c" ]; then echo "  cloning prefix -> $1"; cp -a "$BASE_PFX" "$d/pfx"; fi
}

launch() {  # inst
  local inst=$1 d="$SCRATCH/$1"
  ( exec env ENABLE_GAMESCOPE_WSI=0 SDL_VIDEO_WAYLAND_SCALE=1 SDL_JOYSTICK_DEVICE=/dev/null \
    "$GSC" -W $W -H $H -r $FPS --force-windows-fullscreen --hide-cursor-delay 3000 -- \
      env WINEPREFIX="$d/pfx" PROTONPATH="$PROTON" GAMEID=0 \
          SteamAppId=1203620 SteamGameId=1203620 \
          GSE_FORCE_LOG=1 "GSE_LOG_PATH=Z:$d/gse-$inst.log" \
          /usr/bin/umu-run "$d/game/enshrouded.exe" --keenonline-server-data-file "$DATAFILE" ) > "$d/gs.log" 2>&1 &
  echo $!
}

echo "==> emu check"; ss -tlnp 2>/dev/null | grep -q 27503 && echo "  emu listening" || echo "  WARNING: no emu on 27503"
echo "==> building overlays"
build_overlay instA 76561197990000001 EnshHost 47584 47585
build_overlay instB 76561197990000002 EnshJoin 47585 47584
echo "==> cloning prefixes"
prep_prefix instA
prep_prefix instB
echo "==> launching instA (host)"
A=$(launch instA); echo "instA GSPID=$A  log=$SCRATCH/instA/gs.log  gamelog=$SCRATCH/instA/game/enshrouded.log"
sleep 20
echo "==> launching instB (joiner)"
B=$(launch instB); echo "instB GSPID=$B  log=$SCRATCH/instB/gs.log  gamelog=$SCRATCH/instB/game/enshrouded.log"
echo "SCRATCH=$SCRATCH"
