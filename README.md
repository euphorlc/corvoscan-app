# CorvoScan (Dockerized)

**CorvoScan** is a GUI-based reconnaissance wrapper that consolidates tools like `nmap`, `theHarvester`, `whatweb`, and `ffuf` into a single interface.

This version is fully **containerized** to solve dependency fragmentation. It runs consistently on Kali Linux, Fedora, Arch, macOS, and Windows (WSL2).

#### Architecture

-   **Core**: Python 3 + PyQt6 (GUI)
-   **Engine**: Docker (Kali Linux Rolling Base)
-   **Display**: X11 Forwarding (Linux/WSL) & Network Bridge (macOS)

#### Prerequisites

1.  **Docker Desktop** (Windows/Mac) or **Docker Engine** (Linux).
2.  **Git**.
3.  **(macOS Only)**: [XQuartz](https://www.xquartz.org/) is required.

## Installation

#### 1. Clone the Repository

```bash
git clone https://github.com/euphorlc/corvoscan-app.git
cd corvo-app
```

#### 2. Build the Image

Compile the environment (this pulls Kali, installs Ruby/Python dependencies, and configures the scanner).

```bash
docker build -t corvoscan:final .
```

## Usage

#### Launching the App

We provide a universal launcher that handles X11 forwarding and volume mounting automatically.

```bash
# Make executable (first time only)
chmod +x corvo.sh

# Run
./corvo.sh
```

#### Special Note for macOS Users

1. Install XQuartz: brew install --cask xquartz
2. Open XQuartz > Settings > Security.
3. Check "Allow connections from network clients".
4. Restart XQuartz (or log out/in) before running the script.

## Data & Rules

-   Reports: Scan reports are saved to the ./output folder on your host machine.
-   Rulesets: The app automatically fetches the latest scanning rules from GitHub every time it launches.

## Troubleshooting

-   GUI not appearing? Ensure your Docker Desktop has "Allow access to default file location" enabled.
-   Network errors? The container runs in --net=host mode on Linux/WSL. On macOS, it uses the standard bridge; some SYN scans (nmap -sS) may require root privileges inside the container (not currently supported for security).
