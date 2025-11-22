#!/bin/bash

# CorvoScan DEVELOPMENT Launcher
# USAGE: ./dev.sh
#
# FEATURES:
# - Mounts local ./app source code into the container (Hot Reload)
# - Mounts ./output and ./rulesets for persistence
# - Configures X11/WSLg for GUI
# - Runs on Host Network for full tool access

APP_NAME="corvoscan:final"
CONTAINER_NAME="corvoscan_dev"
SOURCE_DIR="$(pwd)/app"
OUTPUT_DIR="$(pwd)/output"
RULES_DIR="$(pwd)/rulesets"

# Basic Checks
if [ ! -d "$SOURCE_DIR" ]; then
    echo "[!] Error: 'app' directory not found. Are you in the project root?"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"
mkdir -p "$RULES_DIR"

# Detect Environment (Linux vs WSL2)
KERNEL_RELEASE=$(uname -r)
DISPLAY_VAR="$DISPLAY"
MOUNT_ARGS=""

echo "[-] Starting CorvoScan in DEVELOPMENT MODE..."
echo "    > Source code mapped: $SOURCE_DIR"

if [[ "$KERNEL_RELEASE" == *"WSL2"* ]]; then
    echo "    > Environment: WSL2 (WSLg)"
    MOUNT_ARGS="-v /mnt/wslg:/mnt/wslg -v /tmp/.X11-unix:/tmp/.X11-unix"
    DISPLAY_VAR=":0"
else
    echo "    > Environment: Native Linux"
    MOUNT_ARGS="-v /tmp/.X11-unix:/tmp/.X11-unix"
    
    xhost +local:docker > /dev/null 2>&1
fi

# 3. Run Container with Bind Mounts
# -v "$SOURCE_DIR":/home/corvo/app
# Replaces the image's code with local code.

docker run -it --rm \
    --name "$CONTAINER_NAME" \
    --net=host \
    -e DISPLAY="$DISPLAY_VAR" \
    -e QT_DEBUG_PLUGINS=1 \
    $MOUNT_ARGS \
    -v "$SOURCE_DIR":/home/corvo/app \
    -v "$OUTPUT_DIR":/home/corvo/app/output \
    -v "$RULES_DIR":/home/corvo/app/rulesets \
    "$APP_NAME"

echo "[+] Dev session ended."