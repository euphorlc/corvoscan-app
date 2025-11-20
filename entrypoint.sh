#!/bin/bash

# 1. (Placeholder) Update Rulesets
# In the future, we will add: git pull origin main ...
echo "[-] Checking for CorvoScan ruleset updates..."

# 2. Run the Application
# We use "$@" to allow passing arguments to the container if needed
echo "[+] Starting CorvoScan..."
python3 main.py "$@"