"""`hermes wisp connect <url>`: registers Wisp's MCP endpoint in this Hermes profile.

Every change to `config.yaml` goes through `hermes config set|unset`; the credential goes into the
profile's `.env` through Hermes's own writer (`save_env_value`, as `hermes mcp add` keeps its keys),
never through an argument, so it lands in no argv and no shell history."""

import getpass
import ipaddress
import json
import subprocess
import sys
import urllib.parse

from .zone import ZONE_CACHE

# Hermes's terminal tool hands this to its subprocesses, so Hermes's model can `printenv` it: Hermes strips
# only provider keys, its own optional vars, platform-plugin secrets and a backend's `strip_env_keys`
# (`tools/environments/local.py` `_filter_secret_env`). The `_TOKEN` suffix keeps it from `execute_code`
# (stripped by substring), and `cat ~/.hermes/.env` in the terminal asks for approval. Its holder can do
# what `ask_wisp` does plus `wisp_zone`/`wisp_model`: `tools.include` hides those only from the model.
# An earlier version named it WISP_CREDENTIAL.
CREDENTIAL_ENV = "WISP_CREDENTIAL_TOKEN"
OLD_CREDENTIAL_ENV = "WISP_CREDENTIAL"
# Past Wisp's wait limit (1800 s) a call answers `running`; Hermes must not cut it before.
CALL_TIMEOUT = 1900
TIMEOUT_KEYS = ("timeouts.tools.sequential_call", "timeouts.tools.concurrent_batch")
SERVER_KEY = "mcp_servers.wisp"
# Hermes's own commands fill Telegram's 60-slot menu first; the names this lists come before them, the user's after.
MENU_KEY = "platforms.telegram.extra.command_menu.priority"
MENU = ["wisp", "wisp_model"]
# `hermes wisp` exists only once Hermes loads the plugin, and Hermes loads only an enabled one.
ENABLE_HINT = ("The plugin is enabled by `hermes plugins install <repo> --enable` (or `hermes plugins enable wisp`); "
               "connect leaves plugins.enabled alone.")

LIMITS = """Known limits:
- Hermes itself could answer Wisp's confirmation prompts: a prompt in Hermes is only as trustworthy as Hermes.
- Everyone Hermes lets in (its allowlist, its groups) uses Wisp as its owner.
- Hermes's model can read the credential (its terminal can `printenv` it) and with it call Wisp's endpoint
  directly: everything `ask_wisp` does, plus `wisp_zone` and `wisp_model`, which only the tool list hides.
- With Wisp on this machine, the sandbox stops Hermes reading Wisp's files itself,
  not a model set on escaping it: an app it opens or scripts, a startup file or a tool it rewrites,
  runs outside the sandbox. Wisp on another machine is the boundary that holds."""


def setup(parser):
    sub = parser.add_subparsers(dest="wisp_command", required=True)
    connect = sub.add_parser("connect", help="Register a Wisp Runtime's MCP endpoint; the credential is read from stdin")
    connect.add_argument("url", nargs="?", help="The endpoint, https://…/mcp or a loopback http URL")
    connect.add_argument("--remove", action="store_true", help="Undo what connect changed")
    # For `wisp integrate hermes`, which has no YAML reader of its own: Hermes's parse, changing nothing.
    sub.add_parser("servers", help="Print this profile's mcp_servers as JSON")


def handle(args):
    if args.wisp_command == "servers":
        from hermes_cli.config import read_raw_config

        print(json.dumps(read_raw_config().get("mcp_servers") or {}, default=str))
    elif args.remove:
        remove()
    else:
        connect(args.url)


def _get(config, dotted):
    node = config
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _hermes(*argv):
    # A child with the root's HERMES_HOME and no `-p` moves to `active_profile` (Hermes trusts HERMES_HOME
    # only when its parent is `profiles`): name the profile this one runs in.
    from hermes_cli.config import get_config_path

    home = get_config_path().parent
    profile = home.name if home.parent.name == "profiles" else "default"
    subprocess.run(["hermes", "-p", profile, *argv], check=True)


def _read_credential():
    # getpass reads the terminal when there is one; a pipe (`wisp integrate hermes`) is read as is.
    prompt = "Wisp Host Agent Credential (printed by `wisp tokens create --name hermes --host-agent`): "
    credential = getpass.getpass(prompt) if sys.stdin.isatty() else sys.stdin.readline()
    credential = credential.strip()
    if not credential:
        sys.exit("No Host Agent Credential given: paste the one `wisp tokens create --name <name> --host-agent` printed.")
    return credential


def _check_url(url):
    try:
        parsed = urllib.parse.urlsplit(url)
        host = parsed.hostname or ""
    except ValueError:
        sys.exit(f"Not a URL: {url}")
    if parsed.scheme == "https" and host:
        return
    if parsed.scheme == "http" and (host == "localhost" or _is_loopback(host)):
        return
    sys.exit(f"""Refusing {url}: the credential would cross the network in the clear.
Wisp's Runtime listens on 127.0.0.1 only. Either put https in front of it on its machine
(Tailscale Serve: `tailscale serve --bg <port>`, or Caddy as a reverse proxy) and connect to the https URL;
the Runtime refuses that https name until it is told it:
`wisp tokens create --name hermes --host-agent --public-url https://<name>`.
Or keep an ssh tunnel up as a service (`ssh -L <port>:127.0.0.1:<port> <runtime host>`, e.g. autossh
under systemd or launchd) and connect to http://127.0.0.1:<port>/mcp.""")


def _is_loopback(host):
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def connect(url):
    from hermes_cli.config import (get_env_path, read_raw_config, remove_env_value, require_env_writable,
                                   save_env_value)

    if not url:
        sys.exit("Usage: hermes wisp connect <url>, the credential on stdin")
    _check_url(url)
    credential = _read_credential()
    # A refused write returns from `save_env_value` without raising: ask first. The credential is saved
    # before any config change, so a failed save leaves no config naming a credential that is not there.
    try:
        require_env_writable(CREDENTIAL_ENV, "set")
        save_env_value(CREDENTIAL_ENV, credential)
    except (OSError, ValueError) as refusal:
        sys.exit(f"Could not save {CREDENTIAL_ENV}: {refusal}")
    remove_env_value(OLD_CREDENTIAL_ENV)
    config = read_raw_config()
    server = {
        "url": url,
        "headers": {"Authorization": f"Bearer ${{{CREDENTIAL_ENV}}}"},
        "timeout": CALL_TIMEOUT,
        "tools": {"include": ["ask_wisp", "wisp_result"]},
        "elicitation": {"timeout": 1800},
    }
    changes = [(SERVER_KEY, server)]
    for key in TIMEOUT_KEYS:
        current = _get(config, key)
        if not isinstance(current, (int, float)) or current < CALL_TIMEOUT:
            changes.append((key, CALL_TIMEOUT))
    changes.append((MENU_KEY, MENU + _users_menu(config)))

    # What the timeouts held before the first connect, for --remove; a later connect keeps it.
    prior = _prior_path()
    if not prior.exists():
        prior.write_text(json.dumps({key: _get(config, key) for key in TIMEOUT_KEYS}))
    for key, value in changes:
        if _get(config, key) != value:
            _hermes("config", "set", key, json.dumps(value))
    print(f"Set {CREDENTIAL_ENV} in {get_env_path()}")
    print(ENABLE_HINT)
    print(LIMITS)


def _users_menu(config):
    """The menu priority's names other than the plugin's (Hermes takes a single name for a list of one)."""
    current = _get(config, MENU_KEY)
    names = [current] if isinstance(current, str) else current if isinstance(current, list) else []
    return [name for name in names if str(name).lower().replace("-", "_") not in MENU]


def _prior_path():
    from hermes_cli.config import get_config_path

    return get_config_path().parent / "wisp-connect.json"


def remove():
    from hermes_cli.config import read_raw_config, remove_env_value

    config = read_raw_config()
    prior_path = _prior_path()
    try:
        prior = json.loads(prior_path.read_text())
    except (OSError, ValueError):
        prior = {}
    if not isinstance(prior, dict):
        prior = {}
    # The server is Wisp's alone and never comes from the record: it sits in Hermes's home, writable by
    # Hermes's model, which could plant a server there for --remove to install.
    if _get(config, SERVER_KEY) is not None:
        _hermes("config", "unset", SERVER_KEY)
    if _get(config, MENU_KEY) is not None:
        users = _users_menu(config)
        if not users:
            _hermes("config", "unset", MENU_KEY)
        elif users != _get(config, MENU_KEY):
            _hermes("config", "set", MENU_KEY, json.dumps(users))
    # Only the timeouts connect touches, and only numbers.
    for key in TIMEOUT_KEYS:
        if key not in prior:
            continue
        value = prior[key]
        if not _restorable(value):
            print(f"Not restoring {key}: wisp-connect.json holds a value connect never saved; unsetting it")
            value = None
        if _get(config, key) == value:
            continue
        if value is None:
            _hermes("config", "unset", key)
        else:
            _hermes("config", "set", key, json.dumps(value))
    for name in (CREDENTIAL_ENV, OLD_CREDENTIAL_ENV):
        if remove_env_value(name):
            print(f"Removed {name} from the profile's .env")
    prior_path.unlink(missing_ok=True)
    try:
        ZONE_CACHE.unlink(missing_ok=True)
    except OSError:
        # Wisp's sandbox denies Hermes writes beside the plugin; the file goes with the plugin's directory,
        # which `wisp integrate hermes --remove` deletes from outside, so there is nothing to tell the user.
        pass


def _restorable(value):
    return value is None or (isinstance(value, (int, float)) and not isinstance(value, bool))
