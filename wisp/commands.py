"""`/wisp <task>` and `/wisp-model [args]` (`/wisp_model` in Telegram), the plugin's slash commands in every Hermes surface."""

import contextvars
import json
import re
import ssl
import urllib.error
import urllib.parse

from .mcp_client import McpError, call_tool
from .zone import not_answering

NOT_CONNECTED = "Wisp is not connected: run `hermes wisp connect <url>`."
# Wisp holds a call up to 1800 s before it hands back the Run to follow with `wisp_result`.
WAIT = 1800.0 + 120.0
# After one accept, Wisp answers that tool's later Confirmations of the same Run itself.
CHOICES = [{"value": "accept", "label": "Allow for this task"}, {"value": "decline", "label": "Deny"}]
# Invisible Unicode tag characters, a way to hide text in what the user approves (Hermes strips them from its panel too).
_TAGS = re.compile("[\U000E0000-\U000E007F]")


def wisp(ctx, raw_args, unavailable=lambda: None):
    """The task to `ask_wisp`, without Hermes's model; while the Run goes on, `wisp_result` until it ends.
    `unavailable()` says, as for the hook, why there is no Wisp to ask (None while there is): answered instead of
    calling, since Hermes would answer a parked server's tool with "Unknown tool"."""
    task = (raw_args or "").strip()
    if not task:
        return "Usage: /wisp <task>"
    why = unavailable()
    if why:
        return why
    # ponytail: a Hermes without `ask_choice` keeps its own client everywhere, as before it could ask.
    if not hasattr(ctx, "ask_choice") or not hasattr(ctx, "session_surface") or ctx.session_surface() == "cli":
        # Hermes's client, whose panel asks the CLI's Confirmations. Its names for the tools: `mcp__<server>__<tool>`.
        def call(tool, args):
            return json.loads(ctx.dispatch_tool(f"mcp__wisp__{tool}", args))
    else:
        # Elsewhere a command runs outside an agent turn, where Hermes's client has no one to ask a Confirmation of
        # and declines it: the plugin's client asks it in the chat the command came from.
        endpoint = _endpoint()
        if endpoint is None:
            return NOT_CONNECTED
        # Hermes binds who `ask_choice` asks to the context it calls this handler in, and the client asks on a thread
        # of its own, whose context is empty. A copy per question: an earlier call's may still wait on the user, and
        # a context cannot be entered twice.
        handler = contextvars.copy_context()

        def call(tool, args):
            try:
                result = call_tool(*endpoint, tool, args, timeout=WAIT,
                                   elicit=lambda message: handler.copy().run(_ask, ctx, message))
            except urllib.error.HTTPError as exc:
                # Only `ask_wisp`'s 4xx is Wisp's refusal, before any Run; a 5xx may come from a hop between after
                # Wisp took the request, and a `wisp_result` follows a Run that exists.
                running = "" if tool == "ask_wisp" and exc.code < 500 else "; the task may still be running in Wisp"
                return {"error": f"Wisp's {tool} failed: {exc}{running}"}
            except urllib.error.URLError as exc:
                if isinstance(exc.reason, ssl.SSLCertVerificationError):  # reached something, but not provably Wisp
                    host = urllib.parse.urlsplit(endpoint[0]).hostname
                    # A `wisp_result` follows a Run that exists.
                    running = "" if tool == "ask_wisp" else "; the task may still be running in Wisp"
                    return {"error": f"Wisp's endpoint {host} failed its certificate check ({exc.reason}): "
                                     f"the connection was not made{running}"}
                # urllib wraps in a URLError only what fails in the connect or the send: the request never reached Wisp.
                # Only before `ask_wisp` reached it can no Run exist; a `wisp_result` follows one that does.
                if tool == "ask_wisp":
                    return {"error": not_answering()}
                return {"error": f"Wisp could not be reached for {tool} ({exc.reason}); the task may still be running "
                                 "in Wisp"}
            # Raw, after the request was sent (an answer that never came whole, or an answer to Wisp's own request
            # that could not be sent): Wisp may have started a Run, and "not answering, try again" would start it twice.
            except TimeoutError as exc:
                return {"error": f"Wisp's {tool} failed: it timed out ({exc}); the task may still be running in Wisp"}
            except OSError as exc:
                return {"error": f"Wisp's {tool} failed: {exc}; the task may still be running in Wisp"}
            except (McpError, ValueError) as exc:  # Wisp's own refusal, or a malformed endpoint URL before any send
                return {"error": f"Wisp's {tool} failed: {exc}"}
            structured = result.get("structuredContent")
            return {"result": "\n".join(c.get("text", "") for c in result.get("content", [])),
                    "structuredContent": structured if isinstance(structured, dict) else None}
    out = call("ask_wisp", {"task": task})
    while "run" in (out.get("structuredContent") or {}):
        out = call("wisp_result", {"run": out["structuredContent"]["run"]})
    return out.get("error") or out.get("result")


def _ask(ctx, message):
    """A Confirmation's answer from the user's tap: "cancel" when nobody answered, which is no one's decline."""
    return ctx.ask_choice(_TAGS.sub("", message) or "Wisp asks to go on.", CHOICES) or "cancel"


def _endpoint():
    """(url, credential) of the profile's Wisp endpoint, or None while it names none."""
    from hermes_cli.config import get_env_value, read_raw_config

    from .connect import CREDENTIAL_ENV

    url = ((read_raw_config().get("mcp_servers") or {}).get("wisp") or {}).get("url")
    credential = get_env_value(CREDENTIAL_ENV)
    return (url, credential) if url and credential else None


def wisp_model(raw_args):
    """The endpoint's `wisp_model` with `raw_args`, through the plugin's own MCP client: no `wisp` binary,
    so it works with a Runtime on another machine too."""
    endpoint = _endpoint()
    if endpoint is None:
        return NOT_CONNECTED
    args = (raw_args or "").strip()
    try:
        result = call_tool(*endpoint, "wisp_model", {"args": args} if args else {}, timeout=30.0)
    except (OSError, McpError, ValueError) as exc:
        return f"Wisp's wisp_model failed: {exc}"
    return "\n".join(c.get("text", "") for c in result.get("content", []))
