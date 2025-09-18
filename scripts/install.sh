#!/usr/bin/env bash

set -e

# Compile the program
make

BIN_NAME="bin/rootisnaked"
SERVICE_NAME="systemd/rootisnaked.service"

# Copy the bpf program
sudo mkdir -p /usr/local/share/rootisnaked
sudo cp build/rootisnaked.bpf.o /usr/local/share/rootisnaked/rootisnaked.bpf.o

# Copy the binary
sudo install -m 0755 "$BIN_NAME" /usr/local/bin/

# Copy systemd service
sudo install -m 0644 "$SERVICE_NAME" /etc/systemd/system/

# Create log directory and file
sudo mkdir -p /var/log/rootisnaked
sudo touch /var/log/rootisnaked/lastlog

# Reload systemd and enable service
sudo systemctl daemon-reload
sudo systemctl enable --now rootisnaked.service

printf "\nInstallation complete. Service 'rootisnaked' is installed and running.\n"