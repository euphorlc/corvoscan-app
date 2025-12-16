#!/bin/bash

# CorvoScan DEVELOPMENT Launcher
# USAGE: ./dev.sh
#
# FEATURES:
# - Mounts local ./app source code into the container (Hot Reload)
# - Mounts ./output and ./rulesets for persistence
# - Configures X11/WSLg for GUI
# - Runs on Host Network for full tool access

APP_NAME="corvoscan-app:dev"
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
OS_TYPE=$(uname -s)
KERNEL_RELEASE=$(uname -r)
MOUNT_ARGS=""
DISPLAY_VAR=""

echo "[-] Starting CorvoScan in DEVELOPMENT MODE..."
echo "    > Source code mapped: $SOURCE_DIR"

if [ "$OS_TYPE" == "Darwin" ]; then
    # --- MACOS CONFIGURATION ---
    echo "    > Environment: macOS (Apple Silicon/Intel)"

    # 1. Allow docker to connect to XQuartz
    xhost +localhost > /dev/null 2>&1

    # 2. Use the special Docker-for-Mac host DNS
    DISPLAY_VAR="host.docker.internal:0"

    # 3. macOS doesn't use the X11 socket mount, it uses Network
    MOUNT_ARGS=""

elif [[ "$KERNEL_RELEASE" == *"WSL2"* ]]; then
    # --- WSL2 CONFIGURATION ---
    echo "    > Environment: WSL2 (WSLg)"
    MOUNT_ARGS="-v /mnt/wslg:/mnt/wslg -v /tmp/.X11-unix:/tmp/.X11-unix"
    DISPLAY_VAR=":0"

else
    # --- NATIVE LINUX CONFIGURATION ---
    echo "    > Environment: Native Linux"
    MOUNT_ARGS="-v /tmp/.X11-unix:/tmp/.X11-unix"
    DISPLAY_VAR="$DISPLAY"
    xhost +local:docker > /dev/null 2>&1
fi

# 3. Run Container with Bind Mounts
# -v "$SOURCE_DIR":/home/corvo/app
# Replaces the image's code with local code.

docker run -it --rm \
    --name "$CONTAINER_NAME" \
    --net=host \
    --cap-add=NET_RAW \
    --cap-add=NET_ADMIN \
    -e DISPLAY="$DISPLAY_VAR" \
    -e QT_DEBUG_PLUGINS=1 \
    -e QT_XCB_GL_INTEGRATION=none \
    -e QT_QUICK_BACKEND=software \
    -e LIBGL_ALWAYS_SOFTWARE=1 \
    $MOUNT_ARGS \
    -v "$SOURCE_DIR":/home/corvo/app \
    -v "$OUTPUT_DIR":/home/corvo/app/output \
    -v "$RULES_DIR":/home/corvo/app/rulesets \
    "$APP_NAME"

echo "[+] Dev session ended."
