"""Hermes's `tools.mcp_tool_discovery`, as far as the Wisp plugin reads it: each configured server's status is
`$FAKE_HERMES_WISP_STATUS` (Hermes's `connected`, `connecting`, `failed` for a parked or failed one, ...)."""

import os


def get_mcp_status(configured=None, *, include_runtime=True):
    return [{"name": name, "status": os.environ["FAKE_HERMES_WISP_STATUS"]} for name in configured or {}]
