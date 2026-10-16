import json
import os
from dataclasses import asdict, dataclass, field
from typing import Any, Dict

from app.core.logger import get_logger

logger = get_logger()

def get_default_config_dir() -> str:
    local_app_data = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    path = os.path.join(local_app_data, "TinyAV")
    os.makedirs(path, exist_ok=True)
    return path

def get_default_config_path() -> str:
    return os.path.join(get_default_config_dir(), "config.json")

def get_default_quarantine_dir() -> str:
    path = os.path.join(get_default_config_dir(), "Quarantine")
    os.makedirs(path, exist_ok=True)
    return path

def get_default_watched_dirs() -> list[str]:
    dirs = []
    user_home = os.environ.get("USERPROFILE") or os.path.expanduser("~")
    dl = os.path.join(user_home, "Downloads")
    if os.path.isdir(dl):
        dirs.append(dl)
    return dirs

@dataclass
class AppConfig:
    clamav_bin_dir: str = ""
    clamd_host: str = "127.0.0.1"
    clamd_port: int = 3310
    prefer_clamd: bool = False
    quarantine_dir: str = field(default_factory=get_default_quarantine_dir)
    update_interval_hours: int = 4
    auto_update_enabled: bool = True
    remembered_drives: Dict[str, str] = field(default_factory=dict)  # serial -> 'auto_scan' | 'ignore'
    notify_on_clean: bool = True
    start_minimized: bool = False
    last_update_time: str = ""
    definition_version: str = "Unknown"
    # Real-time directory monitoring configuration
    realtime_watch_enabled: bool = True
    watched_directories: list[str] = field(default_factory=get_default_watched_dirs)
    realtime_auto_quarantine: bool = True
    # USB autorun immunization configuration
    usb_autorun_immunize: bool = True

class ConfigManager:
    def __init__(self, config_path: str = ""):
        self.config_path = config_path or get_default_config_path()
        self.config = AppConfig()
        self.load()

    def load(self) -> AppConfig:
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                
                # Update dataclass with loaded keys that exist
                for key, val in data.items():
                    if hasattr(self.config, key):
                        setattr(self.config, key, val)
                logger.info(f"Loaded config from {self.config_path}")
            except Exception as exc:
                logger.warning(f"Error reading config from {self.config_path}, using defaults: {exc}")
        else:
            self.save()
        return self.config

    def save(self) -> bool:
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(asdict(self.config), f, indent=2)
            logger.info(f"Saved config to {self.config_path}")
            return True
        except Exception as exc:
            logger.error(f"Failed to save config to {self.config_path}: {exc}")
            return False

    def update(self, **kwargs: Any) -> bool:
        changed = False
        for key, val in kwargs.items():
            if hasattr(self.config, key) and getattr(self.config, key) != val:
                setattr(self.config, key, val)
                changed = True
        if changed:
            return self.save()
        return True
