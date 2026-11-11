"""Wisp's zone and services, as `wisp_zone` answers them at Hermes's start (the services again at each
session's), and the routing rule built from them."""

import json
import logging
import os
import re
from pathlib import Path

from .mcp_client import McpError, call_tool

logger = logging.getLogger(__name__)

# Beside the plugin. Hermes's model can write it (`plugins/` is not among Hermes's protected paths), so
# everything read from it is data: shape-checked by its use, and made inert before it enters the rule.
ZONE_CACHE = Path(__file__).resolve().parent / "zone.json"
# Beside the plugin too, written only by `wisp integrate hermes` from outside Hermes: the Runtime's loopback
# URL and Wisp's zone as they were then. Write-denied under the sandbox, unlike `config.yaml`'s URL.
PIN = Path(__file__).resolve().parent / "pin.json"
# Hermes drops a longer system prompt section whole (`plugins_dispatch.MAX_SYSTEM_PROMPT_SECTION_CHARS`).
SECTION_CAP = 4000
# A session's prompt waits on this read of the Connectors; past it, the cache answers.
SESSION_TIMEOUT = 2.0
# Two limits on an answer's folders, for time only, as no real zone nears them: a list that fails costs a probe per
# folder, at about 57 ms each, and past 2 MB of paths (Linux's usual `ARG_MAX`) every probe of it fails with `E2BIG`. What
# keeps the pinned folders closed is `pinned_zone` and `protect`'s fallback, not these. `ZONE_BYTES`, Linux's limit on one
# argument, says nothing of how many folders fit: `ZONE_FOLDERS` does.
ZONE_FOLDERS = 500
ZONE_BYTES = 128 * 1024
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]+")


def _cache(zone, cache):
    try:
        cache.write_text(json.dumps(zone))
    except OSError as exc:
        logger.warning("Wisp: could not cache the zone at %s: %s", cache, exc)


def load_zone(url, credential, cache, timeout=5.0):
    """With no pin: the zone from the endpoint at `url`, written to `cache` as it came, as it may name another
    machine's folders; the cached one when the endpoint cannot answer; None when there is neither."""
    if url and credential:
        try:
            zone = call_tool(url, credential, "wisp_zone", timeout=timeout)["structuredContent"]
            _cache(zone, cache)
            return zone
        except (OSError, McpError, ValueError, KeyError) as exc:
            logger.warning("Wisp: wisp_zone failed (%s); using the cached zone", exc)
    try:
        return json.loads(cache.read_text())
    except (OSError, ValueError):
        return None


def load_pin(path):
    """What `wisp integrate hermes` pinned, the zone's shape plus `url`; None without a pin (a second
    machine's `hermes wisp connect` writes none)."""
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return None


def _folders(zone):
    return [zone["dataDir"], zone["deskRoot"], *(folder["path"] for folder in zone.get("privateFolders") or [])]


def _secret_files(zone):
    """The files outside its data directory the Runtime reads its secrets from; none from a Runtime older than them."""
    return list(zone.get("secretFiles") or [])


def _well_formed(path):
    """An absolute string the kernel can take as a path: a NUL byte or a lone surrogate raises where it is used (strictly
    encoded, as macOS's profile needs and Linux's nested re-exec, through a Node that must decode it the same)."""
    try:
        return isinstance(path, str) and os.path.isabs(path) and b"\0" not in path.encode()
    except ValueError:
        return False


def _answered_folders(answer):
    """The folders and secret files of `answer`, the whole of it checked; raises when it cannot widen a pinned zone."""
    folders = [*_folders(answer), *_secret_files(answer)]
    if len(folders) > ZONE_FOLDERS:
        raise ValueError(f"past {ZONE_FOLDERS} folders")
    if bad := [path for path in folders if not _well_formed(path)]:
        raise ValueError(f"not a folder: {bad[0]!r}"[:200])
    if sum(map(len, map(os.fsencode, folders))) > ZONE_BYTES:
        raise ValueError(f"its folders are past {ZONE_BYTES} bytes")
    return folders


def widen(pin, answer):
    """The pinned zone with whatever `answer`, if any, adds to it: an answer widens the zone, never narrows it."""
    pinned = [*_folders(pin), *_secret_files(pin)]
    answered = [] if answer is None else _answered_folders(answer)
    added = [path for path in dict.fromkeys(answered) if path not in pinned]
    given = answer or {}
    files = _secret_files(given)
    return {"dataDir": pin["dataDir"], "deskRoot": pin["deskRoot"],
            "privateFolders": [*pin["privateFolders"], *({"path": path} for path in added if path not in files)],
            "secretFiles": [*_secret_files(pin), *(path for path in added if path in files)],
            "services": given.get("services") or [],
            **({"connectors": given["connectors"]} if "connectors" in given else {})}


def pinned_zone(pin, credential, cache):
    """The pinned zone, widened by the endpoint's answer, or else by the cached one. Everything read beyond the pin is
    data: a failure of any kind means no answer, and only a well-formed answer is cached. Only a pin of the wrong shape raises."""
    def answered():
        token = credential()
        if not token:
            raise ValueError("no credential")
        answer = call_tool(pin["url"], token, "wisp_zone")["structuredContent"]
        if answer is None:
            raise ValueError("it answered null")
        zone = widen(pin, answer)
        _cache(answer, cache)
        return zone

    def cached():
        return widen(pin, json.loads(cache.read_text()))

    for read in (answered, cached):
        try:
            return read()
        except Exception as exc:  # noqa: BLE001 — a process on the pinned port, or in the cache, can make any of them
            logger.warning("Wisp: no zone %s (%r)", read.__name__, exc)
    return widen(pin, None)


def _inert(text):
    """One line: a newline or other control character in a path or a name could open a rule of its own."""
    return _CONTROL.sub(" ", str(text))


def _plainly(connector):
    """`Display (name): description`, with whatever of it the Connector has."""
    name = connector["name"]
    shown = f"{connector['displayName']} ({name})" if connector.get("displayName") else str(name)
    return f"{shown}: {connector['description']}" if connector.get("description") else shown


def not_connected(pinned):
    """What the hook refuses with, and the rule says, while this profile names no Wisp endpoint or holds no
    credential: there is no `ask_wisp`, so nothing may route to it. `pinned`: `wisp integrate hermes` put Wisp on
    this machine, and it is the repair; else Wisp is on another machine, and `hermes wisp connect` is."""
    run = ("`wisp integrate hermes`" if pinned else
           "`hermes wisp connect https://<host>/mcp` (with the credential `wisp tokens create --name <name> --host-agent` printed)")
    return f"Wisp is not connected to Hermes: tell the user to run {run} in a terminal, then restart Hermes."


def not_connected_rule(pinned):
    """The routing rule while Wisp is not connected."""
    return f"""# Wisp
Wisp is the user's private agent: it holds the keys to the user's sensitive accounts and reads their private
files, and you cannot reach them. {not_connected(pinned)}
Say so whenever the user asks for Wisp or for anything Wisp does, and do not do the task another way."""


def not_answering():
    """What the hook refuses with, and the rule says, while Wisp is connected but does not answer: its Runtime is
    stopped or restarting, or its endpoint cannot be reached. `ask_wisp` comes back by itself once it answers."""
    return ("Wisp is not answering right now (its Runtime is stopped or restarting, or its endpoint cannot be "
            "reached): tell the user so, and that Wisp is usually back within a minute; do not do the task another way.")


def not_answering_rule(zone):
    """The routing rule while Wisp does not answer: what is Wisp's, from `zone` when there is one, and that it waits."""
    if zone:
        return routing_rule(zone, answering=False)
    return f"""# Wisp
Wisp is the user's private agent: it holds the keys to the user's sensitive accounts and reads their private
files, and you cannot reach them. {not_answering()}
Say so whenever the user asks for Wisp or for anything Wisp does."""


def session_rule(zone, url, credential, cache, answering=True):
    """The routing rule for a session starting now: `zone`'s folders as of Hermes's start (the sandbox closes a folder
    only at a start, so a rule naming one added since would call closed a folder Hermes can still open) with the
    Connectors the endpoint names now, or the cache's when it does not answer, or the start's. Not `answering`, the
    endpoint is not asked."""
    def answered():
        if not (url and credential):
            raise ValueError("no endpoint or credential")
        return call_tool(url, credential, "wisp_zone", timeout=SESSION_TIMEOUT)["structuredContent"]

    def cached():
        return json.loads(cache.read_text())

    folders = {key: value for key, value in zone.items() if key not in ("services", "connectors")}
    for read in (answered, cached) if answering else (cached,):
        try:
            answer = read()
            return routing_rule({**folders, "services": answer.get("services") or [],
                                 **({"connectors": answer["connectors"]} if "connectors" in answer else {})}, answering)
        except Exception as exc:  # noqa: BLE001 — anything read here is data; the start's rule stands in
            logger.warning("Wisp: no Connectors %s (%r)", read.__name__, exc)
    return routing_rule(zone, answering)


def routing_rule(zone, answering=True):
    """The system prompt section that sends Wisp's tasks to `ask_wisp` (not `answering`: that names them as Wisp's
    and says Wisp does not answer), within Hermes's section cap: what does not fit is counted, not listed."""
    send = ("""Hand these tasks to the `ask_wisp` tool instead of doing them
yourself, and relay Wisp's answer; continue a Wisp conversation by passing its `conversation` id back to
`ask_wisp`:""" if answering else f"""{not_answering()}
These tasks are Wisp's:""")
    head = f"""# Wisp
Wisp is the user's private agent. It holds the keys to the user's sensitive accounts and reads their
private files; you cannot reach them. {send}
- anything that reads or changes a file in Wisp's data directory {_inert(zone["dataDir"])} or under its
Desk root {_inert(zone["deskRoot"])};"""
    if "connectors" in zone:
        services = [_inert(_plainly(connector)) for connector in zone["connectors"] or []
                    if connector.get("status") == "connected"]
    else:  # an older Runtime or `zone.json`: names only
        services = [_inert(service) for service in zone.get("services") or []]
    folders = [f"- {_inert(folder['path'])}" for folder in zone.get("privateFolders") or []]
    # ponytail: rebuilds the rule per dropped item, O(n²) in the zone's size; fine for hundreds of entries.
    for shown in range(len(services) + len(folders), -1, -1):
        listed_services = services[:shown]
        listed_folders = folders[:max(0, shown - len(services))]
        rule = "\n".join([
            head,
            f"- anything that needs Wisp's services: {', '.join(listed_services) or ('none yet' if not services else '…')};",
            "- anything that reads or changes a file in Wisp's Private Folders:",
            *(listed_folders or ["- none yet" if not folders else "- …"]),
        ])
        hidden = len(services) + len(folders) - shown
        if hidden:
            rule += f"\nand {hidden} more; ask Wisp."
        if len(rule) <= SECTION_CAP:
            return rule
    # Only a data directory or Desk root past the cap on its own gets here.
    return rule[:SECTION_CAP]
