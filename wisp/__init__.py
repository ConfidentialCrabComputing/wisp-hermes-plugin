"""Wisp's Hermes plugin: at Hermes's start, the sandbox, the routing rule from Wisp's zone and the
`pre_tool_call` hook that refuses reaching into it; `hermes wisp connect`; `/wisp` and `/wisp-model` (`/wisp_model` in Telegram)."""

import json
import logging
import sys
import threading
import time
import urllib.error
from pathlib import Path

from . import commands, connect
from .hook import make_hook
from .mcp_client import call_tool, loopback, refuses
from .sandbox import SERVICE_COMMAND, UNPROTECTED, protect
from .zone import (PIN, ZONE_CACHE, down_rule, load_pin, load_zone, not_answering, not_connected, not_connected_rule,
                   pinned_zone, rejected, routing_rule, SESSION_TIMEOUT, session_rule)

logger = logging.getLogger(__name__)
# The Hermes MCP servers `wisp integrate hermes` switched off because Wisp holds them now: written from
# outside Hermes, beside the plugin, where the sandbox denies Hermes writes.
MOVED = Path(__file__).resolve().parent / "moved.json"
# How often a parked `wisp` is looked at: Wisp is back within this of its Runtime, then a turn for the tools to reach
# an open session (Hermes refreshes its tool list between turns).
REVIVE_EVERY = 10
# What the revive thread does about a `wisp` Hermes has failed: ask Hermes to reconnect it, or first ask Wisp.
RECONNECT, ASK = "reconnect", "ask"


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
    # `unavailable` is bound below, before any command can run: what the hook refuses with, `/wisp` answers.
    ctx.register_command("wisp", lambda raw_args: commands.wisp(ctx, raw_args, unavailable),
                         description="Hand a task to Wisp directly", args_hint="[task]")
    # `[task]`, not `<task>`: Hermes leaves a plugin command whose hint starts with `<` out of Telegram's menu. Bare,
    # `/wisp` answers how to use it.
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

    # The URL and credential Wisp itself refused (a 401 or 403 to `wisp_zone`) while Hermes had failed `wisp`, or None.
    # Hermes's word alone cannot tell a refusal: it calls no server reconnecting that never connected in this process,
    # a Runtime down at Hermes's start as much as a revoked credential. Cleared once Hermes connects `wisp`.
    # Kept on the revive thread, one per process: a forced rediscovery loads every plugin again, a fresh module each
    # time, in the same process, and its load reads and clears the verdict the process's one revive thread writes.
    revival = next((thread for thread in threading.enumerate() if thread.name == "wisp-revive"), None)
    refusal = getattr(revival, "refusal", None) or [None]
    # Whether this process had the Runtime replace its agent token, kept on the same thread for the same reason.
    sealed = getattr(revival, "sealed", False)
    # The ids of the sessions this process gave a connected rule, at their start or a turn, kept on the same thread so a
    # reload does not give them it again.
    routed = getattr(revival, "routed", None)
    if routed is None:
        routed = set()

    def hermes_wisp():
        """Hermes's MCP client's view of `wisp`: None while it answers (or with no client loaded: only a Hermes that
        connects its MCP servers, a chat or a gateway, has one), else what is wrong and what the revive thread should
        do now: `(down, mend)`, `mend` one of `RECONNECT`, `ASK` (Wisp, whether it refuses Hermes's credential) or
        None. Down while nothing listens on its loopback endpoint (Hermes notices a stopped Runtime only some seconds
        later) or while Hermes has parked it (or failed to connect it); refused only once Wisp said so."""
        discovery = sys.modules.get("tools.mcp_tool_discovery")
        if discovery is None:
            return None
        entry = (read_raw_config().get("mcp_servers") or {}).get("wisp") or {}
        if refuses(entry.get("url")):
            return not_answering(), None
        statuses = {status.get("status") for status in discovery.get_mcp_status({"wisp": entry})
                    if status.get("name") == "wisp"}
        if "connected" in statuses:
            refusal[0] = None
        if "failed" not in statuses:
            return None
        if discovery.mcp_server_reconnecting("wisp"):
            return not_answering(), RECONNECT
        if refusal[0] == (entry.get("url"), credential()):
            return rejected(pinned), None
        return not_answering(), ASK

    def ask():
        """Asks the configured endpoint, as Hermes would connect it, whether it takes Hermes's credential: `RECONNECT`
        when it answers, else None, keeping a 401 or 403 as the refusal."""
        url = ((read_raw_config().get("mcp_servers") or {}).get("wisp") or {}).get("url")
        token = credential()
        try:
            call_tool(url, token, "wisp_zone", timeout=SESSION_TIMEOUT)
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                refusal[0] = (url, token)
            return None
        except Exception as exc:  # noqa: BLE001 — not answering, asked again at the next look
            logger.debug("Wisp: not answering at %s: %r", url, exc)
            return None
        return RECONNECT

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
        restart of the Runtime (every `wisp update`) can park it. A remote endpoint is never probed for listening, so
        one Hermes calls reconnecting is reconnected at each look: Hermes's connect is then the probe. One Hermes does not
        call reconnecting is reconnected only once Wisp answers, and never once Wisp refused its credential: an
        explicit reconnect skips the gate Hermes holds a permanent error behind.
        ponytail: the default profile's `wisp` only; under a gateway serving several profiles the others wait for
        Hermes's own retry or a new session's discovery."""
        refused = False
        while True:
            try:
                known = None if unconnected() else hermes_wisp()
                mend = known and known[1]
                if mend == ASK:
                    mend = ask()
                if mend == RECONNECT:
                    from tools.mcp_tool_loop import reconnect_mcp_server
                    logger.debug("Wisp: asking Hermes to reconnect wisp")
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
    live = False  # the pinned endpoint answered `wisp_zone` at this start, not the cache
    rule = ""
    protected = False
    sandboxed = False  # `protect` sandboxed this start, saying nothing "unprotected"; no running process changes it
    start_closed = False  # what the start's rule says of Wisp's files; with no rule, nothing closed them

    def closed(url):
        """Whether this process is closed off from Wisp's files: sandboxed at its start, or Wisp at `url` on another
        machine."""
        return sandboxed or not loopback(url)

    try:
        pin = load_pin(PIN)
        if pin is not None:
            # Pinned, the URL is integrate's (Hermes's model can repoint `config.yaml`'s at its own endpoint), and the pin
            # alone is a zone: whatever fails in reading more, the sandbox, the hook and the rule have it.
            pinned = pin.get("wisp") or True  # the not-connected text names the pinned `wisp`
            zone, live = pinned_zone(pin, credential, ZONE_CACHE)
        else:
            url = ((read_raw_config().get("mcp_servers") or {}).get("wisp") or {}).get("url")
            zone = load_zone(url, credential(), ZONE_CACHE)
            if zone is None and url:
                # Wisp on another machine is never sandboxed from here, so a zone it cannot read is only Wisp down.
                if loopback(url):
                    _warn(f"{UNPROTECTED}: Wisp's zone could not be read, so Hermes is not sandboxed")
                else:
                    logger.warning("Wisp is not answering at %s", url)
        if zone is not None:
            # After the zone is cached: the sandbox denies writes beside the plugin.
            # On Linux, sandboxed, the process is re-exec'd under bubblewrap here, through the pinned `wisp`.
            warnings = protect(zone, Path(__file__).resolve().parent, get_config_path().parent,
                               pinned=pin, wisp=(pin or {}).get("wisp"))
            for warning in warnings:
                _warn(warning)
            protected = True
            sandboxed = not any(warning.startswith((UNPROTECTED, SERVICE_COMMAND)) for warning in warnings)
            start_closed = closed(pin["url"] if pin else url)
            rule = routing_rule(zone, closed=start_closed)
            if live and not sealed and sandboxed:
                # Sandboxed now, beside the Runtime that just answered: the agent token read before this start could
                # reach the model, so the Runtime replaces it. Every such start asks, so the last replacement is one
                # asked from inside a sandbox. A load again in a process whose replacement succeeded asks no more: a
                # client holding the token it was just given keeps it. One that never had it replaced (its loads ran
                # on the cache, unsandboxed, or the ask failed) asks. Bubblewrap's child is a new process, so it asks.
                try:
                    call_tool(pin["url"], credential(), "wisp_sealed")
                    sealed = True
                except Exception as exc:  # noqa: BLE001 — the token stays as it was; the start goes on
                    logger.warning("Wisp: could not have the Runtime replace its agent token: %r", exc)
    except Exception as exc:  # noqa: BLE001 — a zone of any wrong shape leaves no rule, never a failed load
        logger.warning("Wisp: no routing rule, the zone is malformed: %r", exc)
        if not protected and pinned:
            _warn(f"{UNPROTECTED}: the pin or the zone is malformed, so Hermes is not sandboxed")

    def section(session):
        """Rendered into each new session's prompt, so it says the state Wisp is in then; blank, Hermes leaves it out."""
        text = rule_now()
        if text and not unavailable():
            routed.add(session.get("session_id"))
        return text

    def turn(session_id=None, **_):
        """At each turn: the rule as of now for a session whose prompt has no connected rule (it started before this
        load, or while Wisp was not connected or not answering) once Wisp answers; once per session, as the context
        stays in its history. Hermes fixes a session's prompt section at its start, so only a turn can tell it.
        ponytail: a session id Hermes rotates on compression, or a process restarted under an open session, gets the
        rule once more."""
        if session_id in routed or unavailable():
            return None
        text = rule_now()
        if not text:
            return None
        routed.add(session_id)
        return {"context": f"Wisp is connected and answering now; this rule replaces any earlier one about Wisp:\n{text}"}

    def rule_now():
        if unconnected():
            return not_connected_rule(pinned)
        why = down()
        if zone is None and not pinned:
            # No zone at the load (connected since, or Wisp down then): asked again for each session, at the URL as of
            # now, so a Wisp connected or back since is routed to with no restart. The sandbox and the hook stay the
            # start's; on this machine its "unprotected" warning said so.
            try:
                url = ((read_raw_config().get("mcp_servers") or {}).get("wisp") or {}).get("url")
                # With Wisp down, the cache alone: the endpoint is not asked.
                now = load_zone(None if why else url, credential(), ZONE_CACHE, SESSION_TIMEOUT)
                if now is None:
                    return down_rule(None, why or not_answering(), closed(url)) if url else ""
                return down_rule(now, why, closed(url)) if why else routing_rule(now, closed=closed(url))
            except Exception as exc:  # noqa: BLE001 — a zone of any wrong shape leaves no rule, as at a load
                logger.warning("Wisp: no routing rule, the zone is malformed: %r", exc)
                return ""
        if not rule:
            return down_rule(None, why, start_closed) if why else rule
        try:
            # The Connectors as of now: `wisp connectors auth` while Hermes runs needs no restart.
            url = pin["url"] if pin else ((read_raw_config().get("mcp_servers") or {}).get("wisp") or {}).get("url")
            return session_rule(zone, url, credential(), ZONE_CACHE, why, start_closed)
        except Exception as exc:  # noqa: BLE001 — the start's rule then, one that raises Hermes skips
            logger.warning("Wisp: could not read the Connectors as of now: %r", exc)
            return down_rule(zone, why, start_closed) if why else rule

    ctx.register_system_prompt_section("wisp-routing", section)
    ctx.register_hook("pre_llm_call", turn)
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
    if revival is None:
        revival = threading.Thread(target=revive, name="wisp-revive", daemon=True)
        revival.refusal = refusal
        revival.routed = routed
        revival.start()
    revival.sealed = sealed
