"""
Config Manager for GIAM-SAT Agent
Auto-creates config with default server at YOUR_SERVER_IP:6666
Runs completely silent - no user prompts for installation
Uses %PROGRAMDATA% for writable data (safe when installed in Program Files)
"""

import json
import os
import sys
import uuid


def get_agent_data_dir():
    """
    Get the writable data directory for agent files.
    v2.5.11 FIX: Use %PROGRAMDATA% (NOT %APPDATA%) to match main.py.
    main.py saves config to %PROGRAMDATA%, so config_manager must read from SAME path.
    """
    if os.name == "nt":
        programdata = os.environ.get("PROGRAMDATA", "C:\\ProgramData")
        return os.path.join(programdata, "GIAM-SAT", "Agent")
    else:
        # Linux/Mac
        return os.path.join(os.path.expanduser("~"), ".giamsat", "agent")


def get_agent_install_dir():
    """
    Get the directory where agent binary/scripts are installed.
    """
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(os.path.abspath(__file__))


AGENT_DATA_DIR = get_agent_data_dir()
AGENT_INSTALL_DIR = get_agent_install_dir()
CONFIG_FILE = os.path.join(AGENT_DATA_DIR, "agent_config.json")

DEFAULT_SERVER_HOST = "YOUR_SERVER_IP"
DEFAULT_SERVER_PORT = 6666


class ConfigManager:
    def __init__(self):
        self.config = self._load_or_create()

    def _load_or_create(self):
        """Load config or create default silently (no prompts). Migrate old configs missing user info fields (v2.2.0)."""
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    config = json.load(f)
                # v2.2.0: Ensure user info fields exist (migrate old configs)
                updated = False
                for key in ["user_name", "employee_id", "email", "psk", "enrollment_token", "command_key"]:
                    if key not in config:
                        config[key] = ""
                        updated = True
                if updated:
                    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                        json.dump(config, f, indent=4)
                return config
            except Exception:
                pass
        return self._create_default()

    def _create_default(self):
        """Auto-create config with default server YOUR_SERVER_IP:6666, silent. Includes user info fields (v2.2.0)."""
        machine_id = str(uuid.uuid4())[:8]
        hostname = os.environ.get("COMPUTERNAME", os.environ.get("HOSTNAME", "UNKNOWN"))

        config = {
            "server_host": DEFAULT_SERVER_HOST,
            "server_port": DEFAULT_SERVER_PORT,
            "machine_id": machine_id,
            "hostname": hostname,
            "user_name": "",
            "employee_id": "",
            "email": "",
            "psk": "",
            "enrollment_token": "",
            "command_key": "",
            "configured": True
        }

        try:
            os.makedirs(AGENT_DATA_DIR, exist_ok=True)
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=4)
        except Exception:
            pass

        return config

    def get(self, key, default=None):
        return self.config.get(key, default)

    def update(self, key, value):
        self.config[key] = value
        try:
            os.makedirs(AGENT_DATA_DIR, exist_ok=True)
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(self.config, f, indent=4)
        except Exception:
            pass

    def get_config_path(self):
        """Return the full path to the config file."""
        return CONFIG_FILE

    def get_data_dir(self):
        """Return the writable data directory."""
        return AGENT_DATA_DIR