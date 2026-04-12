#!/bin/bash
set -euo pipefail

IMAGE="mounter-sshfs"
CONTAINER="mounter"
MOUNT_BASE="$HOME/mnt"

# ---------- helpers ----------

die()  { echo "error: $*" >&2; exit 1; }
info() { echo ":: $*"; }

dexec() { docker exec "$CONTAINER" sh -c "$*"; }

resolve_host() {
    local ip
    ip=$(host "$1" 2>/dev/null | awk '/has address/{print $NF; exit}')
    echo "${ip:-$1}"
}

resolve_ssh() {
    local host=$1
    local home="$HOME"
    ssh -G "$host" 2>/dev/null | awk -v home="$home" '
        /^hostname /    { hostname=$2 }
        /^user /        { user=$2 }
        /^port /        { port=$2 }
        /^identityfile / {
            f=$2; gsub(/^~/, home, f)
            if (!idfile) { cmd="test -f " f; if (system(cmd)==0) idfile=f }
        }
        END { print hostname, user, port, idfile }
    '
}

container_ip() {
    docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CONTAINER" 2>/dev/null
}

ensure_image() {
    docker image inspect "$IMAGE" >/dev/null 2>&1 && return
    info "Building sshfs image (one-time, ~1 min)..."
    local dir
    dir=$(cd "$(dirname "$0")" && pwd)
    docker build -t "$IMAGE" "$dir" || die "Docker build failed"
    info "Image built."
}

ensure_container() {
    if docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -q true; then
        return
    fi
    ensure_image
    if docker inspect "$CONTAINER" >/dev/null 2>&1; then
        docker start "$CONTAINER" >/dev/null || die "Container start failed"
    else
        docker run -d --name "$CONTAINER" --privileged --restart unless-stopped \
            "$IMAGE" >/dev/null || die "Container create failed"
    fi
    # Wait for smbd
    for _ in $(seq 1 10); do
        dexec "pidof smbd" >/dev/null 2>&1 && return
        sleep 0.5
    done
}

# ---------- commands ----------

cmd_mount() {
    local remote="${1:?Usage: mounter mount [user@]host:[/path]}"
    shift
    local port=22 identity="" name=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -p|--port)     port="$2"; shift 2 ;;
            -i|--identity) identity="$2"; shift 2 ;;
            -n|--name)     name="$2"; shift 2 ;;
            *) die "Unknown option: $1" ;;
        esac
    done

    # Parse remote spec: [user@]host:[/path]
    local ruser="" rhost rpath
    if [[ "$remote" == *@* ]]; then
        ruser="${remote%%@*}"
        remote="${remote#*@}"
    fi
    if [[ "$remote" == *:* ]]; then
        rhost="${remote%%:*}"
        rpath="${remote#*:}"
    else
        rhost="$remote"
        rpath="/"
    fi
    [[ -z "$rpath" ]] && rpath="/"
    [[ -z "$rhost" ]] && die "Empty hostname"

    name="${name:-$rhost}"

    # Resolve SSH config
    local resolved
    resolved=$(resolve_ssh "$rhost")
    local ssh_hostname ssh_user ssh_port ssh_key
    ssh_hostname=$(echo "$resolved" | awk '{print $1}')
    ssh_user=$(echo "$resolved" | awk '{print $2}')
    ssh_port=$(echo "$resolved" | awk '{print $3}')
    ssh_key=$(echo "$resolved" | awk '{print $4}')

    [[ -n "$ruser" ]] && ssh_user="$ruser"
    [[ "$port" != "22" ]] && ssh_port="$port"
    [[ -n "$identity" ]] && ssh_key="$identity"

    # Resolve hostname on macOS (handles Tailscale, custom DNS)
    local target_ip
    target_ip=$(resolve_host "$ssh_hostname")

    [[ -z "$ssh_key" ]] && die "No SSH key found. Use --identity or set up ~/.ssh/id_*"

    info "Mounting ${ruser:+$ruser@}$rhost:$rpath"

    ensure_container

    # Copy SSH key to container
    local ckey="/root/.ssh/key-$name"
    docker cp "$ssh_key" "$CONTAINER:$ckey"
    dexec "chmod 600 $ckey"

    # sshfs mount inside container
    local vmount="/mnt/$name"
    if dexec "mountpoint -q $vmount 2>/dev/null"; then
        info "Already mounted in container."
    else
        dexec "mkdir -p $vmount"
        dexec "sshfs \
            -o StrictHostKeyChecking=accept-new \
            -o reconnect \
            -o ServerAliveInterval=15 \
            -o ServerAliveCountMax=3 \
            -o allow_other \
            -o IdentityFile=$ckey \
            ${ssh_port:+-o port=$ssh_port} \
            ${ssh_user}@${target_ip}:${rpath} $vmount" \
            || die "sshfs failed"
    fi

    # Save mount config for the in-container health monitor
    local sshfs_cmd="sshfs -o StrictHostKeyChecking=accept-new -o reconnect -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -o allow_other -o IdentityFile=$ckey"
    [[ "$ssh_port" != "22" ]] && sshfs_cmd="$sshfs_cmd -o port=$ssh_port"
    sshfs_cmd="$sshfs_cmd ${ssh_user}@${target_ip}:${rpath} $vmount"
    dexec "echo 'SSHFS_CMD=\"$sshfs_cmd\"' > /etc/mounter/${name}.conf"

    # Samba share
    if ! dexec "grep -q '\\[$name\\]' /etc/samba/smb.conf 2>/dev/null"; then
        dexec "printf '\n[$name]\npath = $vmount\nbrowseable = yes\nread only = no\nguest ok = yes\nforce user = root\ncreate mask = 0644\ndirectory mask = 0755\n' >> /etc/samba/smb.conf"
    fi
    dexec "kill -HUP \$(pidof smbd) 2>/dev/null || smbd --daemon --no-process-group"

    # SMB mount on macOS
    local macmount="$MOUNT_BASE/$name"
    mkdir -p "$macmount"
    mount | grep -q " on $macmount " && /sbin/umount "$macmount" 2>/dev/null
    local cip
    cip=$(container_ip)
    /sbin/mount_smbfs "//guest@${cip}/${name}" "$macmount" || die "SMB mount failed"

    info "Mounted at $macmount"
    echo "Open in Finder:  open $macmount"
}

cmd_unmount() {
    local target="${1:?Usage: mounter unmount <name>}"
    local name
    [[ "$target" == /* ]] && name=$(basename "$target") || name="$target"
    local macmount="$MOUNT_BASE/$name"

    if mount | grep -q " on $macmount "; then
        /sbin/umount "$macmount" 2>/dev/null || /usr/sbin/diskutil unmount force "$macmount" 2>/dev/null
        info "Unmounted $macmount"
    fi

    if docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -q true; then
        dexec "fusermount3 -u /mnt/$name 2>/dev/null || fusermount -u /mnt/$name 2>/dev/null" || true
        dexec "rm -f /etc/mounter/$name.conf" || true
        dexec "sed -i '/^\[$name\]$/,/^$/d' /etc/samba/smb.conf" || true
        dexec "kill -HUP \$(pidof smbd) 2>/dev/null" || true
    fi
    echo "Done."
}

cmd_list() {
    if ! docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -q true; then
        echo "No active mounts"; return
    fi

    local mounts
    mounts=$(dexec "mount -t fuse.sshfs 2>/dev/null" || true)
    [[ -z "$mounts" ]] && { echo "No active mounts"; return; }

    echo "$mounts" | while IFS= read -r line; do
        local remote name macpath status
        remote=$(echo "$line" | awk '{print $1}')
        name=$(basename "$(echo "$line" | awk '{print $3}')")
        macpath="$MOUNT_BASE/$name"
        mount | grep -q " on $macpath " && status="mounted" || status="stale — run: mounter mount $name"
        printf "  %s\n    Remote: %s\n    Finder: %s [%s]\n\n" "$name" "$remote" "$macpath" "$status"
    done
}

cmd_status() {
    if docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -q true; then
        echo "Container: running"
        echo "sshfs:     $(dexec 'sshfs --version 2>&1 | head -1')"
        local n
        n=$(dexec "mount -t fuse.sshfs 2>/dev/null | wc -l" || echo 0)
        echo "Mounts:    $n active"
        echo "Image:     $(docker image inspect "$IMAGE" --format '{{.Size}}' 2>/dev/null | awk '{printf "%.0f MB", $1/1024/1024}')"
    else
        echo "Container: stopped"
    fi
}

# ---------- main ----------

case "${1:-help}" in
    mount)   shift; cmd_mount "$@" ;;
    unmount) shift; cmd_unmount "$@" ;;
    list)    cmd_list ;;
    status)  cmd_status ;;
    help|-h|--help)
        cat <<'USAGE'
mounter — mount remote SSH directories in Finder

Usage:
  mounter mount [user@]host:[/path] [-n name] [-p port] [-i identity]
  mounter unmount <name>
  mounter list
  mounter status

No macFUSE, no sudo. Requires OrbStack with Docker.
USAGE
        ;;
    *) die "Unknown command: $1. Run 'mounter help'" ;;
esac
