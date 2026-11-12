"""The few `hermes_cli.config` functions the Wisp plugin calls in-process, over a fake Hermes home:
`config.yaml` holds JSON (valid YAML), `.env` holds KEY=VALUE lines."""

import json
import os
from pathlib import Path


def _home() -> Path:
    return Path(os.environ["HERMES_HOME"])


def get_config_path() -> Path:
    return _home() / "config.yaml"


def get_env_path() -> Path:
    return _home() / ".env"


def read_raw_config() -> dict:
    if os.environ.get("FAKE_HERMES_RAW_CONFIG_RAISES") == "1":
        raise ValueError("config.yaml: not YAML")
    try:
        return json.loads(get_config_path().read_text())
    except (OSError, ValueError):
        return {}


def _env_lines() -> list:
    try:
        return get_env_path().read_text().splitlines()
    except OSError:
        return []


def load_env() -> dict:
    return dict(line.partition("=")[::2] for line in _env_lines() if "=" in line)


def get_env_value(key: str):
    if os.environ.get("FAKE_HERMES_ENV_VALUE_RAISES") == "1":
        raise ValueError(".env: unreadable")
    # As Hermes's with multiplexing on and no profile scope: raised before the key is looked up, set or not.
    if os.environ.get("FAKE_HERMES_ENV_VALUE_UNSCOPED") == "1":
        from agent.secret_scope import UnscopedSecretError
        raise UnscopedSecretError(key)
    return load_env().get(key)


def _locked(key: str):
    """Hermes's `.env` write lock (a managed install or an administrator-pinned key), played by
    `FAKE_HERMES_ENV_LOCKED=1`."""
    if os.environ.get("FAKE_HERMES_ENV_LOCKED") == "1":
        return f"Cannot set {key}: it is managed by your administrator and cannot be changed."
    return None


def require_env_writable(key: str, action: str) -> None:
    refusal = _locked(key)
    if refusal:
        raise ValueError(refusal)


def save_env_value(key: str, value: str) -> None:
    # As Hermes's: a refused write returns without raising.
    if _locked(key):
        return
    # Hermes's writer can still raise past `require_env_writable` (a bad name, its write lock).
    if os.environ.get("FAKE_HERMES_ENV_SAVE_RAISES") == "1":
        raise OSError(f"Cannot write {key}")
    lines = [line for line in _env_lines() if not line.startswith(f"{key}=")] + [f"{key}={value}"]
    get_env_path().write_text("\n".join(lines) + "\n")


def remove_env_value(key: str) -> bool:
    lines = _env_lines()
    kept = [line for line in lines if not line.startswith(f"{key}=")]
    get_env_path().write_text("".join(f"{line}\n" for line in kept))
    return len(kept) < len(lines)
