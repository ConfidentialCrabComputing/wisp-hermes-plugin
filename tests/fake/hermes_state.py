"""As Hermes's `hermes_state.py`, as far as the plugin uses it: `SessionDB` on `$HERMES_HOME/state.db`, its write
helper, and the namespace check Hermes imports from `hermes_state_pidns` (here as on a platform without PID
namespaces: a `pid=` is evidence on its own)."""

import os
import sqlite3
from pathlib import Path


def holder_pid_checkable(holder):
    return True


class SessionDB:
    def __init__(self, db_path=None, read_only=False):
        self.db_path = db_path or Path(os.environ["HERMES_HOME"]) / "state.db"
        self._conn = sqlite3.connect(self.db_path, isolation_level=None)

    def _execute_write(self, fn, patience_s=None):
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            result = fn(self._conn)
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        self._conn.execute("COMMIT")
        return result

    def close(self):
        self._conn.close()
