#!/bin/bash

install -o root -g root -m 0755 -D "$(realpath $(dirname "${BASH_SOURCE[0]}"))"/riseupvpn.sh -t /usr/share/riseupvpn.sh;
ln -sf /usr/share/riseupvpn.sh/riseupvpn.sh /usr/bin/riseupvpn.sh
if ! [ -f /usr/share/riseupvpn.sh/riseupvpn.conf ]
then
	install -o root -g root -m 0644 -D "$(realpath $(dirname "${BASH_SOURCE[0]}"))"/riseupvpn.conf -t /usr/share/riseupvpn.sh;
fi
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
