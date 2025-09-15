#! /usr/bin/env bash

set -e

# Compile the program
make

# Copy the bpf program into /usr/local/share/rootisnaked/rootisnaked.bpf.o
sudo mkdir -p /usr/local/share/rootisnaked
sudo cp build/rootisnaked.bpf.o /usr/local/share/rootisnaked/rootisnaked.bpf.o

# Copy the binary into /usr/local/bin/rootisnaked
sudo cp bin/rootisnaked /usr/local/bin/rootisnaked

printf "Installation complete. You can run the program using 'export TELEGRAM_TOKEN=\"xxxxx\"; export DEBUG=true; export CHAT_ID=\"xxxxx\" ; sudo -E ./bin/rootisnaked'\n"