#!/bin/bash

# CorvoScan Universal Launcher
# Supports: WSL2 (Windows), Native Linux, and MacOS (Intel/M-Series)

APP_NAME="euphorlc/corvoscan-app:latest"
CONTAINER_NAME="corvoscan_instance"
OUTPUT_DIR="$(pwd)/output"
RULES_DIR="$(pwd)/rulesets"

# Create output directory for results persistence
mkdir -p "$OUTPUT_DIR"

# Detect Kernel Info
KERNEL_NAME=$(uname -s)
KERNEL_RELEASE=$(uname -r)

# Default Variables
DISPLAY_VAR="$DISPLAY"
X11_MOUNT=""
NET_FLAGS="--net=host"

echo "[-] Detecting environment..."

if [[ "$KERNEL_RELEASE" == *"WSL2"* ]]; then
    echo "    > WSL2 detected. Configuring WSLg..."
    X11_MOUNT="-v /mnt/wslg:/mnt/wslg -v /tmp/.X11-unix:/tmp/.X11-unix"
    DISPLAY_VAR=":0"

elif [[ "$KERNEL_NAME" == "Darwin" ]]; then
    echo "    > MacOS detected."

    # Check for XQuartz (Required for X11 Forwarding)
    if ! command -v xhost &> /dev/null; then
        echo "    [!] ERROR: XQuartz is not installed."
        echo "    [!] Please run: brew install --cask xquartz"
        echo "    [!] Then: Open XQuartz > Settings > Security > 'Allow connections from network clients'"
        echo "    [!] Restart XQuartz and run this script again."
        exit 1
    fi

    # Configure Security (Allow localhost to talk to XQuartz)
    echo "    > Configuring XQuartz permissions..."
    xhost + 127.0.0.1 > /dev/null 2>&1

    # Docker Magic Hostname for Mac
    DISPLAY_VAR="host.docker.internal:0"

    NET_FLAGS=""
    X11_MOUNT=""

elif [[ "$KERNEL_NAME" == "Linux" ]]; then
    echo "    > Standard Linux detected."
    X11_MOUNT="-v /tmp/.X11-unix:/tmp/.X11-unix"

    # Allow docker user to write to X server
    if command -v xhost &> /dev/null; then
        xhost +local:docker > /dev/null 2>&1
    fi
fi

echo "[-] Checking for image updates..."

if ! docker pull "$APP_NAME"; then
    echo "[!] Warning: Could not reach Docker Hub."

    if [[ "$(docker images -q $APP_NAME 2> /dev/null)" == "" ]]; then
        echo "[!] FATAL: No local image found and no internet connection."
        echo "[!] Cannot launch application."
        exit 1
    else
        echo "[-] Starting with existing local version (Offline Mode)."
    fi

else
    echo "[-] Application is up to date."
fi

echo "[-] Launching $APP_NAME..."

# Run the Container
docker run -it --rm \
    --name "$CONTAINER_NAME" \
    $NET_FLAGS \
    -e DISPLAY="$DISPLAY_VAR" \
    $X11_MOUNT \
    -v "$OUTPUT_DIR":/home/corvo/app/output \
    "$APP_NAME"

echo "[+] CorvoScan closed."
