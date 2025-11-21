from .tool_process_base import ToolProcessBase
import subprocess
import threading
import os

# Parameters that require a user-supplied value (must match main.py strings)
value_required = [
    "Timing template (-T0-5)",
    "Custom port range (-p)",
    "XML Output (-oX)"
]

# Standalone flags (exact strings must match main.py's tools_data)
standalone_flags = [
    "Fast scan (-F)",
    "Service detection (-sV)",       # unified label for service/version detection (-sV)
    "OS detection (-O)",
    "SYN (Stealth) scan (-sS)",      # single canonical label for -sS
    "UDP scan (-sU)",
    "Ping scan (-sn)",
    "Script scan (-sC)",
    "Traceroute (--traceroute)"
]

# Modifier flags (exact strings must match main.py's tools_data)
modifier_flags = [
    "Timing template (-T0-5)",
    "Custom port range (-p)"
]

# Basic param_map for building commands (map UI label -> nmap flag)
param_map = {
    "Fast scan (-F)": "-F",
    "Service detection (-sV)": "-sV",
    "OS detection (-O)": "-O",
    "SYN (Stealth) scan (-sS)": "-sS",
    "UDP scan (-sU)": "-sU",
    "Ping scan (-sn)": "-sn",
    "Script scan (-sC)": "-sC",
    "Traceroute (--traceroute)": "--traceroute",
    "Timing template (-T0-5)": "-T",
    "Custom port range (-p)": "-p",
    "XML Output (-oX)": "-oX"
}

class NmapToolProcess(ToolProcessBase):
    
# These scan types require root privileges
    root_required_flags = {"-sS", "-sU", "-O", "-sF", "-sX", "-sN", "--traceroute"}  # -A removed
    
    def __init__(self, target, params):
        super().__init__("nmap", target, params)
        self.process = None
        # ensure instance methods referencing self.param_map work
        self.param_map = param_map

    def needs_root(self):
        """Check if the current scan configuration requires root privileges"""
        flags = []
        for p in self.params:
            if isinstance(p, tuple):
                name, value = p
                flag = self.param_map.get(name)
                if flag:
                    flags.append(flag)
            else:
                flag = self.param_map.get(p)
                if flag:
                    flags.append(flag)
        
        # Check if any flag requires root privileges
        return any(flag in self.root_required_flags for flag in flags)

    def build_command(self):
        flags = []
        for p in self.params:
            if isinstance(p, tuple):
                name, value = p
                flag = self.param_map.get(name)
                if flag:
                    flags.extend([flag, value])
            else:
                flag = self.param_map.get(p)
                if flag:
                    flags.append(flag)
        
        base_command = ["nmap"] + flags + [self.target]
        
        # Add sudo if root privileges are needed and we're not already root
        if self.needs_root() and os.geteuid() != 0:
            # use -S to read password from stdin and -p "" to suppress prompt text
            return ["sudo", "-S", "-p", ""] + base_command
        else:
            return base_command

    def start(self, output_callback, sudo_password=None):
        def run():
            try:
                command = self.build_command()
                output_callback("nmap", f"Starting command: {' '.join(command)}\n")

                if command and command[0] == "sudo":
                    output_callback("nmap", "Executing with sudo (password via stdin)...\n")
                    self.process = subprocess.Popen(
                        command,
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        bufsize=1
                    )
                    if sudo_password and self.process.stdin:
                        try:
                            self.process.stdin.write(sudo_password + "\n")
                            self.process.stdin.flush()
                        except Exception:
                            pass
                        try:
                            self.process.stdin.close()
                        except Exception:
                            pass
                else:
                    output_callback("nmap", "Executing without sudo password...\n")
                    self.process = subprocess.Popen(
                        command,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        bufsize=1
                    )

                # Read output line by line
                for line in self.process.stdout:
                    output_callback("nmap", line)

                # Wait for completion
                return_code = self.process.wait()

                if return_code != 0:
                    if return_code == 1 and "sudo" in str(command):
                        output_callback("nmap", "Error: Sudo authentication failed.\n")
                    else:
                        output_callback("nmap", f"Command failed with exit code {return_code}\n")

            except Exception as e:
                output_callback("nmap", f"Error executing nmap: {str(e)}\n")

        # Start in daemon thread
        threading.Thread(target=run, daemon=True).start()

    def terminate(self):
        if self.process:
            self.process.terminate()
