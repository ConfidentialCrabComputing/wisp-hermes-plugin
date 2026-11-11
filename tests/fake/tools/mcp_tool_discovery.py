"""Hermes's `tools.mcp_tool_discovery`, as far as the Wisp plugin reads it: each configured server's status is
`$FAKE_HERMES_WISP_STATUS` (Hermes's `connected`, `connecting`, `failed` for a parked or failed one, ...), and a
server is reconnecting (connected once, parked on a failure that heals) only with `$FAKE_HERMES_WISP_RECONNECTING`."""

import os


def get_mcp_status(configured=None, *, include_runtime=True):
    return [{"name": name, "status": os.environ["FAKE_HERMES_WISP_STATUS"]} for name in configured or {}]


def mcp_server_reconnecting(name):
    return bool(os.environ.get("FAKE_HERMES_WISP_RECONNECTING"))
