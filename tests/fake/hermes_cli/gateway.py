"""Hermes's `hermes_cli.gateway`, as far as the plugin is concerned: `run_gateway`, the gateway in this process, which
`gateway run` starts and a service command's manual fallback starts too (`_restart_all_as_host` with no service)."""

import os
import signal


def probe():
    """Whether this process reads `FAKE_HERMES_PROBE`: "read" or "refused"."""
    try:
        open(os.environ["FAKE_HERMES_PROBE"]).read()
        return "read"
    except OSError:
        return "refused"


def run_gateway(verbose=0, quiet=False, replace=False, force=False, idle_exit=False):
    """With `FAKE_HERMES_PROBE`, says whether the gateway reads it, and stops; else waits for its signals."""
    if os.environ.get("FAKE_HERMES_PROBE"):
        print(f"gateway: {probe()}")
        return
    signal.pause()
