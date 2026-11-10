"""Wisp's Hermes plugin: at Hermes's start, the sandbox, the routing rule from Wisp's zone and the
`pre_tool_call` hook that refuses reaching into it; `hermes wisp connect`; `/wisp` and `/wisp-model` (`/wisp_model` in Telegram)."""

import json
import logging
import sys
from pathlib import Path

from . import commands, connect
from .hook import make_hook
from .sandbox import UNPROTECTED, protect
from .zone import (PIN, ZONE_CACHE, load_pin, load_zone, not_connected, not_connected_rule, pinned_zone,
                   routing_rule, session_rule)

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
    # A hyphen, not an underscore: a gateway looks a typed name up with `_` made `-`, so Telegram's menu (which
    # shows it as `/wisp_model`) and the CLI (`/wisp-model`) both find it; `wisp_model` no gateway could reach.
    ctx.register_command("wisp-model", commands.wisp_model,
                         description="Show or set the model Wisp uses for Hermes's tasks",
                         args_hint="[advanced|balanced|<model id>|thinking on|off|reset]")
    pinned = PIN.exists()

    def unconnected():
        """The not-connected refusal while this profile names no Wisp endpoint or holds no credential, else None.
        Read again each time: `wisp integrate hermes` or `hermes wisp connect` can mend it while Hermes runs."""
        connected = (((read_raw_config().get("mcp_servers") or {}).get("wisp")) and
                     get_env_value(connect.CREDENTIAL_ENV))
        return None if connected else not_connected(pinned)

    zone = pin = None
    rule = ""
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
            rule = routing_rule(zone)
    except Exception as exc:  # noqa: BLE001 — a zone of any wrong shape leaves no rule, never a failed load
        logger.warning("Wisp: no routing rule, the zone is malformed: %r", exc)
        if not protected and pinned:
            _warn(f"{UNPROTECTED}: the pin or the zone is malformed, so Hermes is not sandboxed")

    def section(_session):
        """Rendered into each new session's prompt, so it says the state Wisp is in then; blank, Hermes leaves it out."""
        try:
            if unconnected():
                return not_connected_rule(pinned)
            if not rule:
                return rule
            # The Connectors as of now: `wisp connectors auth` while Hermes runs needs no restart.
            url = pin["url"] if pin else ((read_raw_config().get("mcp_servers") or {}).get("wisp") or {}).get("url")
            return session_rule(zone, url, get_env_value(connect.CREDENTIAL_ENV), ZONE_CACHE)
        except Exception as exc:  # noqa: BLE001 — one that raises Hermes skips, and the rule with it
            logger.warning("Wisp: could not tell whether Wisp is connected: %r", exc)
            return rule

    ctx.register_system_prompt_section("wisp-routing", section)
    # Built here, not per call: a hook that raises blocks every tool call (Hermes fails closed).
    config_path = get_config_path()
    try:
        moved = json.loads(MOVED.read_text())
    except (OSError, ValueError):
        moved = []
    try:
        hook = make_hook(zone, config_path, moved if isinstance(moved, list) else [], unconnected)
    except Exception as exc:  # noqa: BLE001 — a malformed zone still leaves the switch-off attempts refused
        logger.warning("Wisp: the hook guards no zone, it is malformed: %r", exc)
        hook = make_hook(None, config_path, unconnected=unconnected)
    ctx.register_hook("pre_tool_call", hook)
