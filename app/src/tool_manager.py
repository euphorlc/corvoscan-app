import platform
import shutil
import subprocess
import os
import sys

class ToolManager:
    # Define command templates at the class level
    PKG_MGR_TEMPLATES = {
        "install": {
            "apt": ["sudo", "apt-get", "install", "-y"],
            "yum": ["sudo", "yum", "install", "-y"],
            "dnf": ["sudo", "dnf", "install", "-y"],
            "pacman": ["sudo", "pacman", "-S", "--noconfirm"],
        },
        "update": {
            "apt": ["sudo", "apt-get", "install", "--only-upgrade", "-y"],
            "yum": ["sudo", "yum", "update", "-y"],
            "dnf": ["sudo", "dnf", "upgrade", "-y"],
            "pacman": ["sudo", "pacman", "-Syu", "--noconfirm"],
        }
    }
    
    # Define standard tool package names
    LINUX_TOOL_PKG_NAMES = {
        "Whois": "whois",
        "DNSEnum": "dnsenum",
        "NMAP": "nmap",
        "WhatWeb": "whatweb",
        "FFUF": "ffuf",
    }


    def __init__(self):
        self.project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.tools_dir = os.path.join(self.project_root, "tools")
        os.makedirs(self.tools_dir, exist_ok=True)

        self.os_type = self.detect_os()
        self.pkg_manager = self.detect_package_manager() if self.os_type == "linux" else None
        
        self.tool_definitions = self.get_tool_definitions()
        self.installed_tools = {tool: False for tool in self.tool_definitions}
        self.initialize_tools()

    def detect_os(self):
        os_name = platform.system().lower()
        if "linux" in os_name:
            return "linux"
        elif "darwin" in os_name:
            return "macos"
        else:
            raise RuntimeError("Unsupported OS: CorvoScan supports Linux and macOS only.")

    def detect_package_manager(self):
        """Detects the package manager on a Linux system."""
        if shutil.which("apt"):
            return "apt"
        elif shutil.which("yum"):
            return "yum"
        elif shutil.which("dnf"):
            return "dnf"
        elif shutil.which("pacman"):
            return "pacman"
        return None

    def get_tool_definitions(self):
        theharvester_executable = os.path.join(self.tools_dir, "theHarvester", "theHarvester.py")
        
        # --- NEW: Define wordlist paths ---
        wordlists_dir = os.path.join(self.project_root, "wordlists")
        wordlists_content_dir = os.path.join(wordlists_dir, "Discovery", "Web-Content")
        # --- END OF NEW SECTION ---

        linux_commands = {}

        if self.pkg_manager:
            # Programmatically build commands for standard tools
            for tool_name, pkg_name in self.LINUX_TOOL_PKG_NAMES.items():
                linux_commands[tool_name] = {"install": {}, "update": {}}
                for pkg_mgr, cmd_template in self.PKG_MGR_TEMPLATES["install"].items():
                    linux_commands[tool_name]["install"][pkg_mgr] = cmd_template + [pkg_name]
                
                for pkg_mgr, cmd_template in self.PKG_MGR_TEMPLATES["update"].items():
                    # Pacman updates all, so we don't specify a package
                    pkg = [] if pkg_mgr == "pacman" else [pkg_name]
                    linux_commands[tool_name]["update"][pkg_mgr] = cmd_template + pkg

            # --- Handle Special Cases ---
            
            # Nslookup (part of dnsutils or bind-utils)
            linux_commands["Nslookup"] = {
                "install": {
                    "apt": self.PKG_MGR_TEMPLATES["install"]["apt"] + ["dnsutils"],
                    "yum": self.PKG_MGR_TEMPLATES["install"]["yum"] + ["bind-utils"],
                    "dnf": self.PKG_MGR_TEMPLATES["install"]["dnf"] + ["bind-utils"],
                    "pacman": self.PKG_MGR_TEMPLATES["install"]["pacman"] + ["dnsutils"],
                },
                "update": {
                    "apt": self.PKG_MGR_TEMPLATES["update"]["apt"] + ["dnsutils"],
                    "yum": self.PKG_MGR_TEMPLATES["update"]["yum"] + ["bind-utils"],
                    "dnf": self.PKG_MGR_TEMPLATES["update"]["dnf"] + ["bind-utils"],
                    "pacman": self.PKG_MGR_TEMPLATES["update"]["pacman"],
                }
            }

            linux_commands["CorvoGUI"] = {
                "install": {
                    "apt": self.PKG_MGR_TEMPLATES["install"]["apt"] + ["libatomic1", "libnss3", "libasound2t64", "libxkbfile1"],
                    "yum": self.PKG_MGR_TEMPLATES["install"]["yum"] + ["libatomic", "nss", "alsa-lib", "libxkbfile"],
                    "dnf": self.PKG_MGR_TEMPLATES["install"]["dnf"] + ["libatomic", "nss", "alsa-lib", "libxkbfile"],
                    "pacman": self.PKG_MGR_TEMPLATES["install"]["pacman"] + ["libatomic", "nss", "alsa-lib", "libxkbfile"],
                },
                "update": {
                    "apt": self.PKG_MGR_TEMPLATES["update"]["apt"] + ["libatomic1", "libnss3", "libasound2t64", "libxkbfile1"],
                    "yum": self.PKG_MGR_TEMPLATES["update"]["yum"] + ["libatomic", "nss", "alsa-lib", "libxkbfile"],
                    "dnf": self.PKG_MGR_TEMPLATES["update"]["dnf"] + ["libatomic", "nss", "alsa-lib", "libxkbfile"],
                    "pacman": self.PKG_MGR_TEMPLATES["update"]["pacman"], # Just update all
                }
            }

        return {
            "CorvoGUI": {
                "check": {
                    "apt": ["dpkg", "-s", "libnss3"],
                    "yum": ["rpm", "-q", "nss"],
                    "dnf": ["rpm", "-q", "nss"],
                    "pacman": ["pacman", "-Q", "nss"],
                    "macos": ["echo", "GUI check not required"], # Auto-passes
                },
                "install": linux_commands.get("CorvoGUI", {}).get("install", {}) if self.os_type == "linux" else ["echo", "GUI dependencies are not required on macOS"],
                "update": linux_commands.get("CorvoGUI", {}).get("update", {}) if self.os_type == "linux" else ["echo", "GUI dependencies are not required on macOS"],
            },
            # --- NEW TOOL: Wordlists ---
            "Wordlists": {
                "check": ["test", "-d", wordlists_content_dir],
                "install_method": self.install_wordlists,
                "update": ["git", "-C", wordlists_dir, "pull"],
            },
            # --- END OF NEW TOOL ---
            "Whois": {
                "check": ["whois", "--version"],
                "install": linux_commands.get("Whois", {}).get("install", {}) if self.os_type == "linux" else ["brew", "install", "whois"],
                "update": linux_commands.get("Whois", {}).get("update", {}) if self.os_type == "linux" else ["brew", "upgrade", "whois"],
            },
            "theHarvester": {
                "check": ["test", "-f", theharvester_executable], # Use file check
                "install_method": self.install_theharvester,
                "update": ["git", "-C", os.path.join(self.tools_dir, "theHarvester"), "pull"],
            },
            "Nslookup": {
                "check": ["nslookup", "google.com"],
                "install": linux_commands.get("Nslookup", {}).get("install", {}) if self.os_type == "linux" else ["echo", "nslookup is pre-installed on macOS"],
                "update": linux_commands.get("Nslookup", {}).get("update", {}) if self.os_type == "linux" else ["echo", "nslookup is part of macOS; update with OS updates"],
            },
            "DNSEnum": {
                "check": ["which", "dnsenum"], # Use `which` check
                "install": linux_commands.get("DNSEnum", {}).get("install", {}) if self.os_type == "linux" else ["brew", "install", "dnsenum"],
                "update": linux_commands.get("DNSEnum", {}).get("update", {}) if self.os_type == "linux" else ["brew", "upgrade", "dnsenum"],
            },
            "NMAP": {
                "check": ["nmap", "--version"],
                "install": linux_commands.get("NMAP", {}).get("install", {}) if self.os_type == "linux" else ["brew", "install", "nmap"],
                "update": linux_commands.get("NMAP", {}).get("update", {}) if self.os_type == "linux" else ["brew", "upgrade", "nmap"],
            },
            "WhatWeb": {
                "check": ["whatweb", "--version"],
                "install": linux_commands.get("WhatWeb", {}).get("install", {}) if self.os_type == "linux" else ["brew", "install", "whatweb"],
                "update": linux_commands.get("WhatWeb", {}).get("update", {}) if self.os_type == "linux" else ["brew", "upgrade", "whatweb"],
            },
            "FFUF": {
                "check": ["ffuf", "-V"],
                "install": linux_commands.get("FFUF", {}).get("install", {}) if self.os_type == "linux" else ["brew", "install", "ffuf"],
                "update": linux_commands.get("FFUF", {}).get("update", {}) if self.os_type == "linux" else ["brew", "upgrade", "ffuf"],
            },
        }

    # --- NEW METHOD TO INSTALL WORDLISTS ---
    def install_wordlists(self):
        print("Installing SecLists (Web-Content) via sparse-checkout...")
        wordlists_dir = os.path.join(self.project_root, "wordlists")
        seclists_url = "https://github.com/danielmiessler/SecLists.git"
        target_dir = "Discovery/Web-Content"

        try:
            if os.path.exists(wordlists_dir):
                print(f"Wordlists directory already exists at {wordlists_dir}. Skipping install.")
                # We assume if it exists, it's functional or will be updated.
                return True

            # 1. Clone the repo skeleton
            print("Cloning repository skeleton (no files)...")
            clone_cmd = [
                "git", "clone", "--depth", "1", "--no-checkout",
                "--filter=blob:none", seclists_url, wordlists_dir
            ]
            subprocess.run(clone_cmd, check=True)

            # 2. Set the sparse-checkout directory
            print(f"Setting sparse-checkout to {target_dir}...")
            sparse_cmd = ["git", "sparse-checkout", "set", target_dir]
            subprocess.run(sparse_cmd, cwd=wordlists_dir, check=True)

            # 3. Download the files
            print("Checking out wordlists... This may take a moment.")
            # We use checkout (or pull) to get the files. Let's use pull to be safe.
            pull_cmd = ["git", "checkout", "master"]
            subprocess.run(pull_cmd, cwd=wordlists_dir, check=True)
            
            print("Successfully installed wordlists.")
            return True
        except Exception as e:
            print(f"Failed to install wordlists. Error: {e}")
            # Clean up failed attempt
            shutil.rmtree(wordlists_dir, ignore_errors=True)
            return False
    # --- END OF NEW METHOD ---


    def install_theharvester(self):
        harvester_path = os.path.join(self.tools_dir, "theHarvester")
        if os.path.exists(harvester_path):
            print("theHarvester directory already exists. Skipping clone.")
        else:
            print("Cloning theHarvester...")
            git_clone_cmd = ["git", "clone", "https://github.com/laramies/theHarvester.git", harvester_path]
            subprocess.run(git_clone_cmd, check=True)

        pyproject_path = os.path.join(harvester_path, "pyproject.toml")
        if os.path.exists(pyproject_path):
            print("Installing theHarvester dependencies from pyproject.toml...")
            pip_install_cmd = [sys.executable, "-m", "pip", "install", "."]
            subprocess.run(pip_install_cmd, cwd=harvester_path, check=True)
        else:
            print("Installing theHarvester dependencies from requirements.txt...")
            requirements_path = os.path.join(harvester_path, "requirements.txt")
            pip_install_cmd = [sys.executable, "-m", "pip", "install", "-r", requirements_path]
            subprocess.run(pip_install_cmd, check=True)
        return True

    def check_tool_installation(self, tool_name):
        definition = self.tool_definitions.get(tool_name)
        if not definition:
            return False
        
        check_cmd_def = definition["check"]
        check_cmd = [] # Default to empty list

        # NEW: Resolve dictionary-based checks
        if isinstance(check_cmd_def, dict):
            if self.os_type == 'linux' and self.pkg_manager in check_cmd_def:
                check_cmd = check_cmd_def[self.pkg_manager]
            elif self.os_type == 'macos' and 'macos' in check_cmd_def:
                check_cmd = check_cmd_def['macos']
            # If no key matches, check_cmd remains empty
        
        elif isinstance(check_cmd_def, list):
            check_cmd = check_cmd_def

        # If no check command was resolved (e.g., non-applicable platform)
        if not check_cmd:
            print(f"Skipping check for {tool_name} (not applicable to this platform).")
            self.installed_tools[tool_name] = True
            return True
        
        try:
            # NEW: Handle "echo" commands as automatic pass
            if check_cmd[0] == "echo":
                print(f"{tool_name} is considered installed by default on this OS.")
                self.installed_tools[tool_name] = True
                return True

            subprocess.run(check_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            self.installed_tools[tool_name] = True
            print(f"{tool_name} is installed.")
            return True
        except (FileNotFoundError, subprocess.CalledProcessError):
            self.installed_tools[tool_name] = False 
            print(f"{tool_name} is NOT installed.")
            return False

    def install_tool(self, tool_name):
        definition = self.tool_definitions.get(tool_name)
        if not definition:
            print(f"No definition for tool: {tool_name}")
            return False

        print(f"Attempting to install {tool_name}...")
        try:
            if "install_method" in definition:
                success = definition["install_method"]()
            else:
                install_cmds = definition["install"]
                if self.os_type == "linux":
                    if self.pkg_manager and self.pkg_manager in install_cmds:
                        command = install_cmds[self.pkg_manager]
                    else:
                        print(f"Unsupported package manager for {tool_name} on this Linux system.")
                        return False
                else: # macOS
                    command = install_cmds
                
                if not command: 
                    print(f"{tool_name} does not require manual installation on this OS.")
                    success = True
                elif command[0] == "echo": 
                    print(" ".join(command[1:]))
                    success = True
                else:
                    subprocess.run(command, check=True)
                    success = True
            
            if success:
                self.installed_tools[tool_name] = True
                print(f"Successfully installed {tool_name}.")
                return True
        except Exception as e:
            self.installed_tools[tool_name] = False
            print(f"Failed to install {tool_name}. Error: {e}")
            return False
        return False

    def update_tool(self, tool_name):
        definition = self.tool_definitions.get(tool_name)
        if not definition:
            return False
        
        print(f"Attempting to update {tool_name}...")
        try:
            update_cmds = definition["update"]
            if self.os_type == "linux":
                if self.pkg_manager and self.pkg_manager in update_cmds:
                    command = update_cmds[self.pkg_manager]
                else:
                    if isinstance(update_cmds, list):
                        command = update_cmds
                    else:
                        print(f"Unsupported package manager for updating {tool_name}.")
                        return False
            else: # macOS
                command = update_cmds

            if not command: 
                print(f"{tool_name} does not require manual update on this OS.")
                return True
            elif command[0] == "echo": 
                print(" ".join(command[1:]))
                return True
            else:
                subprocess.run(command, check=True)
                print(f"Successfully updated {tool_name}.")
                return True
        except Exception as e:
            print(f"Could not update {tool_name}. Error: {e}")
            return False

    def initialize_tools(self):
        print("Initializing tools...")
        # Re-order to install GUI dependencies first
        tool_list = sorted(self.tool_definitions.keys(), key=lambda x: (x != 'CorvoGUI', x))

        for tool in tool_list:
            if not self.check_tool_installation(tool):
                self.install_tool(tool)
            else:
                self.update_tool(tool)
        print("Tool initialization complete.")