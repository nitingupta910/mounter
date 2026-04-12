#!/bin/bash
set -e

# Base samba config (shares added dynamically by the CLI)
cat > /etc/samba/smb.conf << 'EOF'
[global]
workgroup = WORKGROUP
security = user
map to guest = Bad User
server min protocol = SMB2
log level = 0
EOF

smbd
exec sleep infinity
