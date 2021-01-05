#!/bin/bash

for x in riseupvpn.sh riseupvpn.config; do
install -o root -g root -m 755 -D "$(realpath $(dirname "${BASH_SOURCE[0]}"))"/$x -t /usr/share/riseupvpn.sh;
done
mkdir -p /etc/systemd/system
cat > /etc/systemd/system/riseupvpn.sh.service <<EOF
[Unit]
Description=RiseupVPN Bash implementation
After=network.target network-online.target

[Service]
ExecStart=/usr/share/riseupvpn.sh/riseupvpn.sh
Restart=always

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now riseupvpn.sh
