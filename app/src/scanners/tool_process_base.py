import os
import pty
import fcntl
import struct
import subprocess
import threading


class ToolProcessBase:
    param_map = {}

    def __init__(self, tool_name, target, params):
        self.tool_name = tool_name
        self.target = target
        self.params = params
        self.process = None
        self.master_fd = None
        self.output_buffer = []
        self.status = "idle"
        self.command = []
        # set when user requests termination so finalizer can emit cancelled sentinel
        self._user_terminated = False

    def build_command(self):
        return []

    def _set_winsize_fd(self, fd, rows, cols, xpixels=0, ypixels=0):
        # TIOCSWINSZ: struct winsize { unsigned short ws_row, ws_col, ws_xpixel, ws_ypixel; }
        winsize = struct.pack("HHHH", rows, cols, xpixels, ypixels)
        fcntl.ioctl(fd, getattr(termios := __import__('termios'), 'TIOCSWINSZ'), winsize)

    def set_window_size(self, rows, cols):
        """If process started in PTY, update its window size (call from GUI on resize)."""
        try:
            if self.master_fd is not None:
                self._set_winsize_fd(self.master_fd, int(rows), int(cols))
        except Exception:
            pass

    def start(self, output_callback, sudo_password=None):
        def run():
            self.status = "running"
            self.command = self.build_command()

            # create a new pty for the child so tool thinks it's on a real terminal
            master_fd, slave_fd = pty.openpty()
            self.master_fd = master_fd
            # optional: set an initial window size (80x24)
            try:
                self._set_winsize_fd(master_fd, 24, 80)
            except Exception:
                pass

            # start process with slave as its stdio
            self.process = subprocess.Popen(
                self.command,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True
            )
            os.close(slave_fd)

            # read raw bytes from master and forward immediately
            try:
                while True:
                    chunk = os.read(master_fd, 4096)
                    if not chunk:
                        break
                    text = chunk.decode(errors='replace')
                    self.output_buffer.append(text)
                    output_callback(self.tool_name, text)
            except Exception:
                pass
            finally:
                try:
                    if self.master_fd:
                        os.close(self.master_fd)
                        self.master_fd = None
                except Exception:
                    pass
                self.process.wait()
                self.status = "completed"
                # Send completion signal to trigger parsing
                output_callback(self.tool_name, f"\n[SCAN COMPLETED] {self.tool_name} scan finished\n")

        t = threading.Thread(target=run, daemon=True)
        t.start()

    def terminate(self):
        try:
            # mark as user-terminated so finalizer knows this was a stop request
            self._user_terminated = True
            if self.process and self.process.poll() is None:
                self.process.terminate()
        except Exception:
            pass
