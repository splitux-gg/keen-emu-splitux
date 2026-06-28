#!/usr/bin/env bash
set -uo pipefail
GSC="$HOME/.local/share/splitux/bin/gamescope-splitux"
GAME=/mnt/games/Enshrouded.v0.9.1.2/Enshrouded/enshrouded.exe
PFX=/mnt/games/Enshrouded.v0.9.1.2/wine
PROTON=/mnt/games/home/Steam/compatibilitytools.d/GE-Proton10-34
DATAFILE='Z:\home\alphasigmachad\Code\keen-emu-splitux\keenonline-emu.json'
LOG=/tmp/claude-1000/-mnt-games/3dff41c3-54df-4621-963c-ccfe83424d95/scratchpad/ensh-keen.log
export LIBVA_DRIVER_NAME=radeonsi
( exec env ENABLE_GAMESCOPE_WSI=0 SDL_VIDEO_WAYLAND_SCALE=1 SDL_JOYSTICK_DEVICE=/dev/null \
  "$GSC" -W 1280 -H 720 -r 30 --force-windows-fullscreen --hide-cursor-delay 3000 -- \
    env WINEPREFIX="$PFX" PROTONPATH="$PROTON" GAMEID=0 SteamAppId=1203620 SteamGameId=1203620 \
        /usr/bin/umu-run "$GAME" --keenonline-server-data-file "$DATAFILE" ) > "$LOG" 2>&1 &
echo "GSPID=$!  log=$LOG"
