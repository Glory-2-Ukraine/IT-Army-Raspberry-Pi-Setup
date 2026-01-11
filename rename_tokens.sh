#!/usr/bin/env bash
# rename_tokens.sh
#
# Usage:
#   ./rename_tokens.sh clean
#   ./rename_tokens.sh dirty
#   ./rename_tokens.sh run
#
# Operates ONLY on:
#   /run/media/pi/rootfs/home/pi/setup-pi.sh
#   /home/pi/setup-pi.sh
# whichever exists first.
#
# clean:
#   mhddos    -> FOOBAR
#   itarmy -> STATEONE
#   ITARMY -> GOLDENONE
#   ADSS   -> SSDA
#
# dirty/run (same):
#   FOOBAR    -> mhddos
#   STATEONE  -> itarmy
#   GOLDENONE -> ITARMY
#   SSDA      -> ADSS
#
# Creates a timestamped backup before modifying.

set -euo pipefail

MODE="${1:-}"

if [[ "$MODE" != "clean" && "$MODE" != "dirty" && "$MODE" != "run" ]]; then
  echo "ERROR: mode must be: clean | dirty | run" >&2
  exit 2
fi

TARGET=""
if [[ -f /run/media/pi/rootfs/home/pi/setup-pi.sh ]]; then
  TARGET="/run/media/pi/rootfs/home/pi/setup-pi.sh"
elif [[ -f /home/pi/setup-pi.sh ]]; then
  TARGET="/home/pi/setup-pi.sh"
else
  echo "ERROR: setup-pi.sh not found in allowed locations" >&2
  exit 1
fi

TS="$(date +%Y%m%d-%H%M%S)"
BACKUP="${TARGET}.bak.${TS}"

cp -a "$TARGET" "$BACKUP"

if [[ "$MODE" == "clean" ]]; then
  # use placeholders to avoid collision
  sed -i \
    -e 's/ITARMY/GOLDENONE/g' \
    -e 's/itarmy/STATEONE/g' \
    -e 's/mhddos/FOOBAR/g' \
    -e 's/ADSS/SSDA/g' \
    "$TARGET"
else
  sed -i \
    -e 's/GOLDENONE/ITARMY/g' \
    -e 's/STATEONE/itarmy/g' \
    -e 's/FOOBAR/mhddos/g' \
    -e 's/SSDA/ADSS/g' \
    "$TARGET"
fi

echo "mode=${MODE}"
echo "target=${TARGET}"
echo "backup=${BACKUP}"
