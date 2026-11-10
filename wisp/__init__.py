"""Wisp's Hermes plugin: at Hermes's start, the sandbox, the routing rule from Wisp's zone and the
`pre_tool_call` hook that refuses reaching into it; `hermes wisp connect`; `/wisp` and `/wisp_model`."""

import json
import logging
import sys
from pathlib import Path

from . import commands, connect
from .hook import make_hook
from .sandbox import UNPROTECTED, protect
from .zone import PIN, ZONE_CACHE, load_pin, load_zone, pinned_zone, routing_rule

logger = logging.getLogger(__name__)
# The Hermes MCP servers `wisp integrate hermes` switched off because Wisp holds them now: written from
# outside Hermes, beside the plugin, where the sandbox denies Hermes writes.
MOVED = Path(__file__).resolve().parent / "moved.json"


def _warn(line):
    """In the log, and on stderr when the zone is unprotected where a sandbox should hold it (Windows has none, and
    integrate says so): a log no one reads does not say Hermes runs without it. Through `sys.stderr` as it stands now: the CLI's prompt keeps its screen through `patch_stdout`, and
    the TUI takes its backend's stderr for its log, so neither is drawn over."""
    logger.warning("%s", line)
    if line.startswith(UNPROTECTED) and sys.platform != "win32":
        try:
            print(line, file=sys.stderr, flush=True)
        except (OSError, ValueError):
            pass  # A closed stderr costs Hermes nothing.


def register(ctx):
    from hermes_cli.config import get_config_path, get_env_value, read_raw_config

    # First, so no zone can take `hermes wisp connect` (the way to repair one) down with it.
    ctx.register_cli_command(
        "wisp", "Connect Hermes to a Wisp Runtime", connect.setup, connect.handle,
        description="hermes wisp connect <url> registers the Runtime's MCP endpoint; --remove undoes it.")
    ctx.register_command("wisp", lambda raw_args: commands.wisp(ctx, raw_args),
                         description="Hand a task to Wisp directly", args_hint="<task>")
    # An underscore, not a hyphen: Telegram's command menu takes only [a-z0-9_].
    ctx.register_command("wisp_model", commands.wisp_model,
                         description="Show or set the model Wisp uses for Hermes's tasks",
                         args_hint="[advanced|balanced|<model id>|thinking on|off|reset]")
    zone = None
    protected = False
    try:
        pin = load_pin(PIN)
        if pin is not None:
            # Pinned, the URL is integrate's (Hermes's model can repoint `config.yaml`'s at its own endpoint), and the pin
            # alone is a zone: whatever fails in reading more, the sandbox, the hook and the rule have it.
            zone = pinned_zone(pin, lambda: get_env_value(connect.CREDENTIAL_ENV), ZONE_CACHE)
        else:
            url = ((read_raw_config().get("mcp_servers") or {}).get("wisp") or {}).get("url")
            zone = load_zone(url, get_env_value(connect.CREDENTIAL_ENV), ZONE_CACHE)
            if zone is None and url:
                _warn(f"{UNPROTECTED}: Wisp's zone could not be read, so Hermes is not sandboxed")
        if zone is not None:
            # After the zone is cached: the sandbox denies writes beside the plugin.
            # On Linux, sandboxed, the process is re-exec'd under bubblewrap here, through the pinned `wisp`.
            for warning in protect(zone, Path(__file__).resolve().parent, get_config_path().parent,
                                   pinned=pin, wisp=(pin or {}).get("wisp")):
                _warn(warning)
            protected = True
            ctx.register_system_prompt_section("wisp-routing", routing_rule(zone))
    except Exception as exc:  # noqa: BLE001 — a zone of any wrong shape leaves no rule, never a failed load
        logger.warning("Wisp: no routing rule, the zone is malformed: %r", exc)
        if not protected and PIN.exists():
            _warn(f"{UNPROTECTED}: the pin or the zone is malformed, so Hermes is not sandboxed")
    # Built here, not per call: a hook that raises blocks every tool call (Hermes fails closed).
    config_path = get_config_path()
    try:
        moved = json.loads(MOVED.read_text())
    except (OSError, ValueError):
        moved = []
    try:
        hook = make_hook(zone, config_path, moved if isinstance(moved, list) else [])
    except Exception as exc:  # noqa: BLE001 — a malformed zone still leaves the switch-off attempts refused
        logger.warning("Wisp: the hook guards no zone, it is malformed: %r", exc)
        hook = make_hook(None, config_path)
    ctx.register_hook("pre_tool_call", hook)
