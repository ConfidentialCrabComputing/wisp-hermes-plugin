"""`/wisp <task>` and `/wisp_model [args]`, the plugin's slash commands in every Hermes surface."""

import json

from .mcp_client import McpError, call_tool

# Hermes's names for the `wisp` MCP server's tools (`tools/mcp_tool_schema.py`: `mcp__<server>__<tool>`).
ASK_WISP = "mcp__wisp__ask_wisp"
WISP_RESULT = "mcp__wisp__wisp_result"


def wisp(ctx, raw_args):
    """The task to `ask_wisp`, without Hermes's model; while the Run goes on, `wisp_result` until it ends."""
    task = (raw_args or "").strip()
    if not task:
        return "Usage: /wisp <task>"
    out = json.loads(ctx.dispatch_tool(ASK_WISP, {"task": task}))
    while "run" in (out.get("structuredContent") or {}):
        out = json.loads(ctx.dispatch_tool(WISP_RESULT, {"run": out["structuredContent"]["run"]}))
    return out.get("error") or out.get("result")


def wisp_model(raw_args):
    """The endpoint's `wisp_model` with `raw_args`, through the plugin's own MCP client: no `wisp` binary,
    so it works with a Runtime on another machine too."""
    from hermes_cli.config import get_env_value, read_raw_config

    from .connect import CREDENTIAL_ENV

    url = ((read_raw_config().get("mcp_servers") or {}).get("wisp") or {}).get("url")
    credential = get_env_value(CREDENTIAL_ENV)
    if not url or not credential:
        return "Wisp is not connected: run `hermes wisp connect <url>`."
    args = (raw_args or "").strip()
    try:
        result = call_tool(url, credential, "wisp_model", {"args": args} if args else {}, timeout=30.0)
    except (OSError, McpError, ValueError) as exc:
        return f"Wisp's wisp_model failed: {exc}"
    return "\n".join(c.get("text", "") for c in result.get("content", []))
