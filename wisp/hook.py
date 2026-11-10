"""The `pre_tool_call` hook: a call that reaches into Wisp's zone, or switches this plugin off, is refused
with a pointer to `ask_wisp`. A guide for Hermes's model, not the boundary: text it does not recognise
passes."""

import logging
import os
import re
from urllib.parse import unquote

logger = logging.getLogger(__name__)

REFUSAL = {"action": "block", "message": "This goes through Wisp — use ask_wisp."}
FILE_TOOLS = {"read_file", "write_file", "patch", "search_files"}
WRITE_TOOLS = {"write_file", "patch"}
# The argument that holds what a code tool runs.
CODE_TOOLS = {"terminal": "command", "execute_code": "code"}
# Between the words of a command, as a shell or a Python argv list (`["hermes", "plugins", ...]`) spells it.
_SEP = r"[\s'\",]+"
# Bounded, so a long line repeating "hermes" stays linear: Hermes abandons a slow hook but cannot stop it.
# ponytail: "hermes" anywhere on the line, so `git log --grep="hermes gateway install"` is refused too.
# A restart passes: this plugin sandboxes Hermes at every start, and a plugin installed with new
# dependencies loads only after one.
_SWITCH_OFF = re.compile(
    rf"\bhermes[^\n;|&]{{0,200}}?\b(plugins{_SEP}(disable|remove|rm|uninstall){_SEP}wisp"
    rf"|config{_SEP}(set|unset){_SEP}plugins|gateway{_SEP}install)\b")
# What `wisp integrate hermes` switches off: a name `hermes config set mcp_servers.<n>` addresses whole.
_SERVER_NAME = re.compile(r"[A-Za-z0-9_-]{1,64}")
_FILE_URL = re.compile(r"file://[^\s'\"<>]+")


def _real(path):
    return os.path.realpath(os.path.expanduser(path))


def _texts(value):
    """Every string in a tool's arguments, however nested."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _texts(item)
    elif isinstance(value, list):
        for item in value:
            yield from _texts(item)


def _naming(paths):
    """A pattern for free text naming any of `paths`, as given, by its real path (`/home` is a link on
    macOS) or with `~`; a path, not part of a longer one (`/home/u/bank` is not `/home/u/bank2` nor
    `/mnt/home/u/bank`). None for no paths."""
    home = os.path.expanduser("~")
    spellings = {spelling for path in {*paths, *map(_real, paths)} for spelling in
                 (path, *(["~" + path[len(home):]] if path.startswith(home + os.sep) else []))}
    return re.compile("|".join(rf"(?<![\w.~/-]){re.escape(s)}(?![\w.-])" for s in spellings)) if spellings else None


def _moved_names(moved):
    """The servers' names as `hermes config set mcp_servers.<n>` takes them; anything else is dropped."""
    return [name for name in moved if isinstance(name, str) and _SERVER_NAME.fullmatch(name)]


def make_hook(zone, config_path, moved=(), unconnected=lambda: None):
    """The hook for `zone` (None: only the switch-off attempts are refused); `config_path` is Hermes's
    `config.yaml`, whose `plugins` section enables this plugin; `moved` names Hermes's MCP servers
    switched off because Wisp holds them now; `unconnected()`, asked at each refusal, what to refuse with
    instead of `ask_wisp` while there is none (None while Wisp is connected)."""
    given = ([zone["dataDir"], zone["deskRoot"], *(f["path"] for f in zone.get("privateFolders") or []),
              *(zone.get("secretFiles") or [])] if zone else [])
    home = os.path.expanduser("~")
    # A sandboxed Hermes's model cannot write zone.json (macOS and Linux both deny it), but an unsandboxed one can
    # (Windows, or a start the sandbox failed): an empty, relative, root or home folder would refuse nearly every
    # call, on every start the cache stands in for the Runtime.
    kept = [folder for folder in given
            if os.path.isabs(os.path.expanduser(folder)) and _real(folder) not in (os.sep, _real(home))]
    if len(kept) < len(given):
        logger.warning("Wisp: the hook skips %d zone folders that are empty, relative, / or home",
                       len(given) - len(kept))
    folders = [_real(folder) for folder in kept]
    named = _naming(kept)
    config = str(config_path)
    config_named = _naming([config])
    servers = _moved_names(moved)
    either = "|".join(map(re.escape, servers))
    # Switching a moved server back on, or replacing it, through Hermes's own CLI.
    switch_on = re.compile(
        rf"\bhermes[^\n;|&]{{0,200}}?\b(config{_SEP}(set|unset){_SEP}mcp_servers\.({either})"
        rf"|mcp{_SEP}\w+{_SEP}({either}))(?![\w-])") if servers else None
    config_edit = re.compile(rf"plugins|wisp|(?<![\w-])({either})(?![\w-])" if servers else r"plugins|wisp")

    def inside(path, among):
        # ponytail: a relative path is not judged; Hermes resolves it against the task's workspace,
        # which the hook does not know.
        try:
            if not os.path.isabs(os.path.expanduser(path)):
                return False
            real = _real(path)
        except ValueError:  # a NUL byte: the tool refuses it itself
            return False
        return any(real == folder or real.startswith(folder + os.sep) for folder in among)

    def pre_tool_call(tool_name, args, **_):
        if refused(tool_name, args) is None:
            return None
        try:
            message = unconnected()
        except Exception as exc:  # noqa: BLE001 — a refusal that raises would still block, naming nothing
            logger.warning("Wisp: could not tell whether Wisp is connected: %r", exc)
            message = None
        return {"action": "block", "message": message} if message else REFUSAL

    def refused(tool_name, args):
        if tool_name in FILE_TOOLS:
            path = args.get("path")
            if isinstance(path, str) and (inside(path, folders) or (
                    tool_name in WRITE_TOOLS and inside(path, [_real(config)]))):
                return REFUSAL
            # `patch` in V4A mode names its files inside the patch text.
            if tool_name == "patch" and any(
                    (named and named.search(text)) or config_named.search(text) for text in _texts(args.get("patch"))):
                return REFUSAL
        if tool_name in CODE_TOOLS:
            text = args.get(CODE_TOOLS[tool_name])
            if isinstance(text, str) and (
                    _SWITCH_OFF.search(text) or (named and named.search(text))
                    or (switch_on and switch_on.search(text))
                    or (config_named.search(text) and config_edit.search(text))):
                return REFUSAL
            workdir = args.get("workdir")
            if isinstance(workdir, str) and inside(workdir, folders):
                return REFUSAL
        if "browser" in tool_name:
            for text in _texts(args):
                for url in _FILE_URL.findall(text):
                    if inside(unquote(url[len("file://"):]), folders):
                        return REFUSAL
        return None

    return pre_tool_call
