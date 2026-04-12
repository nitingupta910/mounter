#!/bin/sh
# Runs inside the container. Checks sshfs mounts every 30s and remounts if stale.
# Mount configs are saved to /etc/mounter/<name>.conf by the CLI.

CONF_DIR="/etc/mounter"
CHECK_INTERVAL=30
STAT_TIMEOUT=10

while true; do
    sleep "$CHECK_INTERVAL"

    for conf in "$CONF_DIR"/*.conf 2>/dev/null; do
        [ -f "$conf" ] || continue

        name=$(basename "$conf" .conf)
        mp="/mnt/$name"

        # Skip if not currently mounted
        mountpoint -q "$mp" 2>/dev/null || continue

        # Health check: can we stat the mount within timeout?
        if timeout "$STAT_TIMEOUT" ls "$mp" >/dev/null 2>&1; then
            continue  # healthy
        fi

        echo "[monitor] $name: mount stale, remounting..."

        # Read saved config
        . "$conf"  # sets: SSHFS_CMD

        # Force unmount stale FUSE mount
        fusermount3 -u "$mp" 2>/dev/null || fusermount -u "$mp" 2>/dev/null || true
        sleep 1

        # Remount
        if eval "$SSHFS_CMD"; then
            echo "[monitor] $name: remounted successfully"
        else
            echo "[monitor] $name: remount failed, will retry in ${CHECK_INTERVAL}s"
        fi
    done
done
