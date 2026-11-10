"""Hermes's `agent.secret_scope`, as far as the Wisp plugin reads it."""


class UnscopedSecretError(RuntimeError):
    """A secret read with multiplexing on and no profile scope: Hermes raises it whether the key is set or not."""
