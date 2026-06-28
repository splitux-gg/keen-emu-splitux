#!/usr/bin/env bash
# Launch Enshrouded under GE-Proton inside gamescope-splitux so it publishes a
# PipeWire capture node (the producer side of splitux-together). Goldberg is
# already swapped into the game dir (self-contained gbe_fork), so no overlay.
set -uo pipefail
GSC="$HOME/.local/share/splitux/bin/gamescope-splitux"
GAME=/mnt/games/Enshrouded.v0.9.1.2/Enshrouded/enshrouded.exe
PFX=/mnt/games/Enshrouded.v0.9.1.2/wine
PROTON=/mnt/games/home/Steam/compatibilitytools.d/GE-Proton10-34
GS_LOG=/tmp/claude-1000/-mnt-games/2c634b19-bed6-44d7-8d63-bc6b7862b9cc/scratchpad/ensh-gs.log
W=1920; H=1080; FPS=60

export LIBVA_DRIVER_NAME=radeonsi   # box exports stale nvidia; AMD card

# umu env so Proton runs the windows exe; gamescope-splitux wraps it + captures.
( exec env ENABLE_GAMESCOPE_WSI=0 SDL_VIDEO_WAYLAND_SCALE=1 SDL_JOYSTICK_DEVICE=/dev/null \
  "$GSC" -W "$W" -H "$H" -r "$FPS" --force-windows-fullscreen --hide-cursor-delay 3000 -- \
    env WINEPREFIX="$PFX" PROTONPATH="$PROTON" GAMEID=0 \
        SteamAppId=1203620 SteamGameId=1203620 \
        /usr/bin/umu-run "$GAME" ) > "$GS_LOG" 2>&1 &
echo "GSPID=$!"
echo "gs log: $GS_LOG"
