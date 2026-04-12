#!/bin/sh
set -e

mkdir -p /etc/mounter /run/samba

cat > /etc/samba/smb.conf << 'EOF'
[global]
workgroup = WORKGROUP
security = user
map to guest = Bad User
server min protocol = SMB2
log level = 0
EOF

smbd --daemon --no-process-group

# Start the health monitor in the background
/monitor.sh &

exec sleep infinity
