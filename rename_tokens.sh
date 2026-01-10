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
    -e 's/ITARMY/__PH_ITARMY__/g' \
    -e 's/itarmy/__PH_itarmy__/g' \
    -e 's/mhddos/__PH_mhddos__/g' \
    -e 's/ADSS/__PH_SSDA__/g' \
    -e 's/__PH_ITARMY__/GOLDENONE/g' \
    -e 's/__PH_itarmy__/STATEONE/g' \
    -e 's/__PH_mhddos__/FOOBAR/g' \
    -e 's/__PH_ADSS__/SSDA/g' \
    "$TARGET"
else
  sed -i \
    -e 's/GOLDENONE/__PH_GOLDEN__/g' \
    -e 's/STATEONE/__PH_STATE__/g' \
    -e 's/FOOBAR/__PH_FOOBAR__/g' \
    -e 's/SSDA/__PH_ADSS__/g' \
    -e 's/__PH_GOLDEN__/ITARMY/g' \
    -e 's/__PH_STATE__/itarmy/g' \
    -e 's/__PH_FOOBAR__/mhddos/g' \
    -e 's/__PH_SSDA__/ADSS/g' \
    "$TARGET"
fi

echo "mode=${MODE}"
echo "target=${TARGET}"
echo "backup=${BACKUP}"
