#!/bin/bash

cat > /etc/systemd/system/pyips-pro.service <<EOF
[Unit]
Description=PyIPS-Pro Intrusion Prevention System
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/pyips-pro
ExecStart=/usr/bin/docker-compose up
ExecStop=/usr/bin/docker-compose down
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable pyips-pro
systemctl start pyips-pro

echo "PyIPS-Pro installed and started"
