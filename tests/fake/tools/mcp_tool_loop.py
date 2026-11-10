"""Hermes's `tools.mcp_tool_loop`, as far as the Wisp plugin calls it: each reconnect asked for is logged to
`$HERMES_HOME/reconnect.log`, one server name per line."""

import os
from pathlib import Path


def reconnect_mcp_server(server_name):
    with open(Path(os.environ["HERMES_HOME"]) / "reconnect.log", "a") as log:
        log.write(server_name + "\n")
    return True
