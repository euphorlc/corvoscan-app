# CorvoScan (Dockerized)

**CorvoScan** is a GUI-based reconnaissance wrapper that consolidates tools like `nmap`, `theHarvester`, `whatweb`, and `ffuf` into a single interface.

This version is fully **containerized** to solve dependency fragmentation. It runs consistently on Kali Linux, Fedora, Arch, macOS, and Windows (WSL2).

#### Architecture

-   **Core**: Python 3 + PyQt6 (GUI)
-   **Engine**: Docker (Kali Linux Rolling Base)
-   **Display**: X11 Forwarding (Linux/WSL) & Network Bridge (macOS)
-   **Distribution**: Automated builds via Docker Hub

#### Prerequisites

1.  **Docker Desktop** (Windows/Mac) or **Docker Engine** (Linux).
2.  **Git**.
3.  **(macOS Only)**: [XQuartz](https://www.xquartz.org/) is required.

## Installation
You do **not** need to build the Docker image manually. The launcher script will automatically pull the latest stable version from Docker Hub.

#### 1. Clone the Repository

```bash
git clone https://github.com/euphorlc/corvoscan-app.git
cd corvoscan-app
```

#### 2. Run the Application

We provide a universal launcher that automatically detects your OS, configures X11 forwarding, and mounts the necessary volumes.

```bash
# Make executable (first time only)
chmod +x corvo.sh

# Launch
./corvo.sh
```

_Note: The first run will take a few minutes to download the image. Subsequent runs will be instant._

#### Special Note for macOS Users

1. Install XQuartz: brew install --cask xquartz
2. Open XQuartz > Settings > Security.
3. Check "Allow connections from network clients".
4. Enable IGLX (Required for Rendering): Run this command in your terminal to fix blank window issues:
```bash
defaults write org.xquartz.X11 enable_iglx -bool true
```
5. Restart XQuartz (Quit fully via Cmd+Q and reopen) before running the script.

## 🛠️ For Developers
If you want to contribute to CorvoScan, you can use our "Hot Reload" mode to see changes without rebuilding the image.

#### Dev Mode

1. Ensure you are on **Linux** or **WSL2**
2. Clone the CorvoScan GitHub repository:
```bash
git clone https://github.com/euphorlc/corvoscan-app.git
```
3. Build the development image:
```bash
docker build -t corvoscan-app:dev .
```
4. Run the dev script:
```bash
chmod +x dev.sh
./dev.sh
```
This mounts your local `app/` folder into the container. When changes are made, close the app GUI and restart the script.

#### 🛡️ Code Quality & Pre-Commit Hooks

We use **Pre-Commit** to ensure code quality and prevent CI failures. This runs the same checks locally that GitHub Actions runs in the cloud.

**Setup (Run once)**
After cloning the repo and installing dependencies, initialize the hooks:

1. Create a Python environment.
```bash
python3 -m venv venv
```

2. Install the pre-commit framework
```bash
pip install pre-commit
```

2. Activate the hooks in your .git directory
```bash
pre-commit install
```

When you run `git commit`, the hooks will automatically scan your code for syntax errors and style issues.

---

## 📂 Data & Persistence
- **Reports**: Scan reports are saved to the ./output folder on your host machine.
- **Rulesets**: The app automatically fetches the latest scanning rules from GitHub every time it launches.

## ❓ Troubleshooting
- **GUI not appearing?** Ensure your Docker Desktop has "Allow access to default file location" enabled.
- **Network errors?** The container runs in --net=host mode on Linux/WSL. On macOS, it uses the standard bridge; some SYN scans (nmap -sS) may require root privileges inside the container (not currently supported for security).
