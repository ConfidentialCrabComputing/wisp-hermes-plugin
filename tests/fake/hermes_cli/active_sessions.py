"""As Hermes's registry of open chats (`hermes_cli/active_sessions.py`), as far as the plugin uses it: entries in
`$HERMES_HOME/runtime/active_sessions.json`, each naming the PID that holds a chat."""

import json
import os
import time
from pathlib import Path

# As Hermes: a lease this process started this recently is kept, its session maybe not attached yet.
_SELF_ORPHAN_GRACE_SECONDS = 30.0


def release_orphaned_leases(live_lease_ids):
    """Drops this process's entries that no live session in `live_lease_ids` owns, past the grace; the count dropped."""
    path = Path(os.environ["HERMES_HOME"]) / "runtime" / "active_sessions.json"
    if not path.exists():
        return 0
    entries = json.loads(path.read_text())["entries"]
    cutoff = time.time() - _SELF_ORPHAN_GRACE_SECONDS
    kept = [e for e in entries if e.get("pid") != os.getpid() or e.get("lease_id") in live_lease_ids
            or e.get("started_at", 0.0) > cutoff]
    path.write_text(json.dumps({"entries": kept}))
    return len(entries) - len(kept)
