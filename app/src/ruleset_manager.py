import os
import subprocess
import shutil

class RulesetManager:
    def __init__(self):
        """
        Initializes the RulesetManager, calculates paths, and starts
        the initialization (check/install/update) process.
        """
        # Calculate project root, assuming this file is in /src
        self.project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        # Define the target directory for the rulesets
        self.rulesets_dir = os.path.join(self.project_root, "rulesets")
        
        # Define the remote repository URL
        self.repo_url = "https://github.com/Euphorlc/CorvoScan-rulesets"
        
        # Automatically run the initialization
        self.initialize_rulesets()

    def initialize_rulesets(self):
        """
        Main logic flow. Checks if rulesets are installed and either
        installs them or updates them.
        """
        if not self.check_installation():
            print("Ruleset repository not found. Attempting to install...")
            self.install_rulesets()
        else:
            print("Ruleset repository found. Attempting to update...")
            self.update_rulesets()

    def check_installation(self):
        """
        Checks if the rulesets directory exists and is a valid Git repository.
        Returns True if valid, False otherwise.
        """
        if not os.path.exists(self.rulesets_dir):
            return False
        
        # A simple and effective check is to run 'git status'.
        # If the directory doesn't exist or isn't a git repo, this will fail.
        check_cmd = ["git", "-C", self.rulesets_dir, "status"]
        try:
            subprocess.run(check_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            # The directory might exist but be corrupted or not a git repo.
            # We'll treat this as "not installed" and clean it up.
            print("Corrupted or invalid ruleset directory found. Cleaning up...")
            shutil.rmtree(self.rulesets_dir, ignore_errors=True)
            return False

    def install_rulesets(self):
        """
        Clones the rulesets from the remote repository.
        This is a simple 'git clone' as we want the entire repository.
        """
        print(f"Cloning rulesets from {self.repo_url}...")
        clone_cmd = ["git", "clone", self.repo_url, self.rulesets_dir]
        
        try:
            subprocess.run(clone_cmd, check=True)
            print("Successfully cloned rulesets.")
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"Failed to clone rulesets. Error: {e}")
            # Clean up the failed attempt
            shutil.rmtree(self.rulesets_dir, ignore_errors=True)

    def update_rulesets(self):
        """
        Pulls the latest changes from the remote ruleset repository.
        """
        print("Pulling latest ruleset updates...")
        pull_cmd = ["git", "-C", self.rulesets_dir, "pull"]
        
        try:
            subprocess.run(pull_cmd, check=True)
            print("Rulesets are up-to-date.")
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"Failed to update rulesets. Error: {e}")
            print("Proceeding with existing rulesets.")