#!/bin/sh
set -e
# Only a system booted with systemd can reload units; containers and chroots skip it.
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    systemctl try-restart honk-core.service || true
fi
