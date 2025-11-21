#!/bin/bash

# Define where rules should live
RULES_DIR="/home/corvo/app/rulesets"
REPO_URL="https://github.com/euphorlc/corvoscan-rulesets.git"

echo "[-] Initializing CorvoScan Environment..."

# Handle Dynamic Rulesets
if [ -d "$RULES_DIR" ]; then
    echo "[-] Updating existing rulesets..."
    cd "$RULES_DIR"
    git pull origin main
else
    echo "[-] Cloning rulesets for the first time..."
    # Create dir if not exists
    git clone "$REPO_URL" "$RULES_DIR"
fi

# Return to app dir
cd /home/corvo/app

# Run the Application
echo "[+] Starting CorvoScan GUI..."
# Pass all arguments ($@) to the python script
python3 main.py "$@"