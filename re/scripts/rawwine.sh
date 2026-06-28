#!/bin/bash
GE=/mnt/games/home/Steam/compatibilitytools.d/GE-Proton10-34/files
export WINEPREFIX=/mnt/games/Enshrouded.v0.9.1.2/wine
export WINEFSYNC=1 WINEESYNC=1 WINEDEBUG=-all
export PATH="$GE/bin:$PATH"
export LD_LIBRARY_PATH="$GE/lib64:$GE/lib:$LD_LIBRARY_PATH"
export LIBVA_DRIVER_NAME=radeonsi
cd /mnt/games/Enshrouded.v0.9.1.2/Enshrouded
exec "$GE/bin/wine" enshrouded.exe --keenonline-server-data-file 'Z:\home\alphasigmachad\Code\keen-emu\keenonline-emu.json'
