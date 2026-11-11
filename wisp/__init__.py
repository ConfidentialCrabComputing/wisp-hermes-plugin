"""Wisp's Hermes plugin: at Hermes's start, the sandbox, the routing rule from Wisp's zone and the
`pre_tool_call` hook that refuses reaching into it; `hermes wisp connect`; `/wisp` and `/wisp-model` (`/wisp_model` in Telegram)."""

import json
import logging
import sys
import threading
import time
from pathlib import Path

from . import commands, connect
from .hook import make_hook
from .mcp_client import refuses
from .sandbox import UNPROTECTED, protect
from .zone import (PIN, ZONE_CACHE, down_rule, load_pin, load_zone, not_answering, not_connected, not_connected_rule,
                   pinned_zone, rejected, routing_rule, session_rule)

logger = logging.getLogger(__name__)
# The Hermes MCP servers `wisp integrate hermes` switched off because Wisp holds them now: written from
# outside Hermes, beside the plugin, where the sandbox denies Hermes writes.
MOVED = Path(__file__).resolve().parent / "moved.json"
# How often a parked `wisp` is looked at: Wisp is back within this of its Runtime, then a turn for the tools to reach
# an open session (Hermes refreshes its tool list between turns).
REVIVE_EVERY = 10


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
    from hermes_cli.config import get_config_path, get_env_value, load_env, read_raw_config

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
    from agent.secret_scope import UnscopedSecretError

    pinned = PIN.exists()

    def credential():
        """The profile's Wisp credential, or None. Hermes raises for any key, set or not, read with multiplexing on
        and no profile scope; the profile's own `.env`, where `hermes wisp connect` saves it, answers then."""
        try:
            return get_env_value(connect.CREDENTIAL_ENV)
        except UnscopedSecretError:
            return load_env().get(connect.CREDENTIAL_ENV)

    def unconnected():
        """The not-connected refusal while this profile names no Wisp endpoint or holds no credential, else None.
        Read again each time: `wisp integrate hermes` or `hermes wisp connect` can mend it while Hermes runs.
        Connected only when read so: a check that raises says not connected, never `ask_wisp`."""
        try:
            connected = (((read_raw_config().get("mcp_servers") or {}).get("wisp")) and credential())
        except Exception as exc:  # noqa: BLE001 — unsure is not connected
            logger.warning("Wisp: could not tell whether Wisp is connected: %r", exc)
            connected = False
        return None if connected else not_connected(pinned)

    # Whether this process saw `wisp`'s loopback endpoint refuse since `wisp` last connected or was reconnected: a
    # `wisp` Hermes failed meanwhile failed for a Runtime that was down, so it heals once the endpoint listens, though
    # Hermes, when it never connected it, does not call it reconnecting.
    saw_refuse = [False]

    def hermes_wisp():
        """Hermes's MCP client's view of `wisp`: None while it answers (or with no client loaded: only a Hermes that
        connects its MCP servers, a chat or a gateway, has one), else what is wrong and whether a reconnect would
        mend it now: `(down, revive)`. Down while nothing listens on its loopback endpoint (Hermes notices a stopped
        Runtime only some seconds later) or while Hermes has parked it (or failed to connect it); a park heals only
        while Hermes says so (`mcp_server_reconnecting`: false on a permanent error, a refused credential, a wrong
        path) or after the endpoint was seen refusing."""
        discovery = sys.modules.get("tools.mcp_tool_discovery")
        if discovery is None:
            return None
        entry = (read_raw_config().get("mcp_servers") or {}).get("wisp") or {}
        if refuses(entry.get("url")):
            saw_refuse[0] = True
            return not_answering(), False
        if not any(status.get("name") == "wisp" and status.get("status") == "failed"
                   for status in discovery.get_mcp_status({"wisp": entry})):
            saw_refuse[0] = False
            return None
        if saw_refuse[0] or discovery.mcp_server_reconnecting("wisp"):
            return not_answering(), True
        return rejected(pinned), False

    def down():
        """None while the connected Wisp answers, else why it does not. A Hermes that connects no MCP server has no
        `ask_wisp` to route to anyway. Unsure is answering: a rule saying Wisp is down would turn away tasks it can do."""
        try:
            known = hermes_wisp()
            return known and known[0]
        except Exception as exc:  # noqa: BLE001 — unsure is answering
            logger.warning("Wisp: could not tell whether Wisp answers: %r", exc)
            return None

    def revive():
        """Asks Hermes to reconnect a parked `wisp` that heals once its endpoint takes connections again, at Hermes's
        start and every `REVIVE_EVERY` s after: Hermes's own retry of a parked server comes every 300 s, and each
        restart of the Runtime (every `wisp update`) can park it. A remote endpoint is never probed here, so one
        Hermes calls reconnecting is reconnected at each look: Hermes's connect is then the probe. Never a park that
        does not heal: an explicit reconnect skips the gate Hermes holds a permanent error behind.
        ponytail: the default profile's `wisp` only; under a gateway serving several profiles the others wait for
        Hermes's own retry or a new session's discovery."""
        refused = False
        while True:
            try:
                known = None if unconnected() else hermes_wisp()
                if known and known[1]:
                    from tools.mcp_tool_loop import reconnect_mcp_server
                    logger.debug("Wisp: asking Hermes to reconnect wisp")
                    saw_refuse[0] = False
                    accepted = reconnect_mcp_server("wisp")
                    if not accepted and not refused:
                        logger.warning("Wisp: Hermes refused to reconnect wisp")
                    refused = not accepted
            except Exception as exc:  # noqa: BLE001 — the next turn tries again
                logger.debug("Wisp: could not revive wisp: %r", exc)
            time.sleep(REVIVE_EVERY)

    def unavailable():
        """What the hook refuses with instead of `ask_wisp` while there is no Wisp to ask, else None."""
        return unconnected() or down()

    zone = pin = None
    rule = ""
    protected = False
    try:
        pin = load_pin(PIN)
        if pin is not None:
            # Pinned, the URL is integrate's (Hermes's model can repoint `config.yaml`'s at its own endpoint), and the pin
            # alone is a zone: whatever fails in reading more, the sandbox, the hook and the rule have it.
            zone = pinned_zone(pin, credential, ZONE_CACHE)
        else:
            url = ((read_raw_config().get("mcp_servers") or {}).get("wisp") or {}).get("url")
            zone = load_zone(url, credential(), ZONE_CACHE)
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
        if unconnected():
            return not_connected_rule(pinned)
        why = down()
        if not rule:
            return down_rule(None, why) if why else rule
        try:
            # The Connectors as of now: `wisp connectors auth` while Hermes runs needs no restart.
            url = pin["url"] if pin else ((read_raw_config().get("mcp_servers") or {}).get("wisp") or {}).get("url")
            return session_rule(zone, url, credential(), ZONE_CACHE, why)
        except Exception as exc:  # noqa: BLE001 — the start's rule then, one that raises Hermes skips
            logger.warning("Wisp: could not read the Connectors as of now: %r", exc)
            return down_rule(zone, why) if why else rule

    ctx.register_system_prompt_section("wisp-routing", section)
    # Built here, not per call: a hook that raises blocks every tool call (Hermes fails closed).
    config_path = get_config_path()
    try:
        moved = json.loads(MOVED.read_text())
    except (OSError, ValueError):
        moved = []
    try:
        hook = make_hook(zone, config_path, moved if isinstance(moved, list) else [], unavailable)
    except Exception as exc:  # noqa: BLE001 — a malformed zone still leaves the switch-off attempts refused
        logger.warning("Wisp: the hook guards no zone, it is malformed: %r", exc)
        hook = make_hook(None, config_path, unavailable=unavailable)
    ctx.register_hook("pre_tool_call", hook)
    # Once per process: a forced rediscovery loads every plugin again, a fresh module each time, in the same process.
    if not any(thread.name == "wisp-revive" for thread in threading.enumerate()):
        threading.Thread(target=revive, name="wisp-revive", daemon=True).start()
