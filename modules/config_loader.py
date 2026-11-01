"""
config_loader.py — Load and validate the YAML configuration file.

Supports ``${ENV_VAR}`` expansion in string values via environment variables.
"""

import os
import re

import yaml


ENV_PATTERN = re.compile(r"\$\{([A-Z0-9_]+)\}")


def _expand_env(value):
    """Recursively expand ``${ENV_VAR}`` placeholders in strings."""
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    if not isinstance(value, str):
        return value

    def _replace(match):
        return os.getenv(match.group(1), "")

    return ENV_PATTERN.sub(_replace, value)


def load_env_file(env_path=".env"):
    """Read a simple ``KEY=VALUE`` file and populate ``os.environ``."""
    if not env_path or not os.path.exists(env_path):
        return
    with open(env_path, "r", encoding="utf-8") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip())


def load_config(config_path):
    """Load YAML config, expand env vars, and return the dict.

    Raises ``SystemExit`` if the file is missing or invalid.
    """
    if not os.path.isfile(config_path):
        raise SystemExit(f"Config file not found: {config_path}")

    with open(config_path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}

    cfg = _expand_env(raw)

    # Basic validation
    for section in ("zintel", "androai", "paths", "pipeline", "researchers"):
        if section not in cfg:
            raise SystemExit(f"Missing required config section: '{section}'")

    if not cfg["zintel"].get("api_key"):
        raise SystemExit("zintel.api_key is required")

    researchers = cfg.get("researchers") or []
    if not researchers:
        raise SystemExit("At least one researcher must be configured")

    return cfg
