"""Hermes's `tools.browser_launcher`, as far as the Wisp plugin reads it: on this host Chromium keeps its own sandbox."""


def needs_chromium_sandbox_bypass():
    return False
