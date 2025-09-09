"""Configuration management for DFW."""

import os
import json
from pathlib import Path
from typing import Dict, Any


class Config:
    """Application configuration manager."""

    DEFAULT_CONFIG = {
        "case_directory": "~/DFW_Cases",
        "temp_directory": "/tmp/dfw",
        "export_directory": "~/DFW_Exports",
        "tools": {
            "volatility_path": "volatility3",
            "regripper_path": "rip.pl",
            "plaso_path": "log2timeline.py",
            "tshark_path": "tshark",
            "bulk_extractor_path": "bulk_extractor",
            "foremost_path": "foremost",
            "binwalk_path": "binwalk",
            "yara_path": "yara",
            "exiftool_path": "exiftool"
        },
        "ui": {
            "theme": "clam",
            "font_size": 10,
            "terminal_shell": "bash",
            "max_preview_size": 1048576,  # 1MB
            "auto_save_interval": 300  # 5 minutes
        },
        "analysis": {
            "hash_algorithms": ["md5", "sha1", "sha256"],
            "timeline_sources": ["filesystem", "registry", "logs", "browser"],
            "yara_rules_path": "~/.dfw/yara_rules",
            "volatility_plugins_path": "~/.dfw/volatility_plugins"
        },
        "reporting": {
            "template_path": "~/.dfw/templates",
            "logo_path": "~/.dfw/logo.png",
            "default_format": "html"
        }
    }

    def __init__(self, config_file: str = None):
        """Initialize configuration.

        Args:
            config_file: Path to configuration file
        """
        if config_file:
            self.config_file = Path(config_file)
        else:
            self.config_file = Path.home() / ".dfw" / "config.json"

        self.config = self.load()

    def load(self) -> Dict[str, Any]:
        """Load configuration from file."""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    user_config = json.load(f)
                # Merge with defaults
                config = self.DEFAULT_CONFIG.copy()
                config.update(user_config)
                return config
            except Exception as e:
                print(f"Error loading config: {e}")

        return self.DEFAULT_CONFIG.copy()

    def save(self) -> bool:
        """Save configuration to file."""
        try:
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
            return False

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value.

        Args:
            key: Configuration key (supports dot notation)
            default: Default value if key not found
        """
        keys = key.split('.')
        value = self.config

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default

        return value

    def set(self, key: str, value: Any) -> None:
        """Set configuration value.

        Args:
            key: Configuration key (supports dot notation)
            value: Value to set
        """
        keys = key.split('.')
        config = self.config

        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]

        config[keys[-1]] = value
        self.save()

