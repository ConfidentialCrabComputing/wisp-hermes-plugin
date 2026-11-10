"""The sandbox around the Hermes process the plugin loads into: read and write denied under Wisp's zone,
write denied under the plugin's own directory. Applied in-process, so every launch path (the CLI, a
profile's gateway service, its cron, the dashboard) is covered and every child inherits it."""

import ctypes
import importlib.util
import json
import os
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys

UNPROTECTED = "Wisp's zone is unprotected"
LEGACY_TIOCSTI = "/proc/sys/dev/tty/legacy_tiocsti"
BWRAP = "/usr/bin/bwrap"
EXTERNAL_SUPERVISOR = "--external-supervisor"
PROBE_TRIES = 3
# Where `systemctl` is looked for, never through `PATH`, which `.env` sets. The third is NixOS's.
SYSTEMCTL_DIRS = ["/usr/bin", "/bin", "/run/current-system/sw/bin", "/usr/sbin", "/sbin"]


def _literal(path):
    """`path` as an SBPL string literal: a `"` or `\\` in a folder name (both legal) cannot end it early."""
    return '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _ancestors(path):
    parent = os.path.dirname(path)
    return [] if parent == path else [parent, *_ancestors(parent)]


def profile(denied, plugin_dir):
    """The Seatbelt profile: everything allowed but the zone and writes to the plugin. A rule names a path,
    so renaming a folder's parent would carry it out from under its rule: each parent is write-denied
    itself (`literal`), which leaves creating files inside it alone."""
    parents = sorted({parent for path in [*denied, plugin_dir] for parent in _ancestors(path)})
    return "\n".join([
        "(version 1)",
        "(allow default)",
        *(f"(deny file-read* file-write* (subpath {_literal(path)}))" for path in denied),
        f"(deny file-write* (subpath {_literal(plugin_dir)}))",
        *(f"(deny file-write* (literal {_literal(parent)}))" for parent in parents),
        "",
    ])


def _mounts():
    """Each mount point of this process's mount namespace: (filesystem type, read-only), the topmost mount's."""
    mounts = {}
    with open("/proc/self/mountinfo", "rb") as info:
        for line in info:
            fields = line.split()
            # `\040` and the like: the kernel's octal escapes in a mount point's name.
            point = re.sub(rb"\\([0-7]{3})", lambda m: bytes([int(m[1], 8)]), fields[4])
            mounts[os.fsdecode(point)] = (fields[fields.index(b"-") + 1], b"ro" in fields[5].split(b","))
    return mounts


def _sandboxed(denied, plugin_dir):
    """Whether this process already runs in the sandbox, as the kernel says. Not an environment variable:
    Hermes loads `.env` into its environment before plugins load, and its model can write that file."""
    try:
        mounts = _mounts()
    except OSError:
        return False
    # A folder is under a tmpfs, a secret file under a read-only bind of `/dev/null`; a missing path has neither.
    return (mounts.get(plugin_dir, (None, False))[1]
            and all(mounts.get(path, (None,))[0] == b"tmpfs" if os.path.isdir(path) else mounts.get(path, (None, False))[1]
                    for path in denied if os.path.exists(path)))


def _loads_code(name):
    """Whether the dynamic loader (or glibc's `iconv`) runs code a variable `name` points at: Hermes loads `.env`
    into its environment before plugins load, and its model can write that file."""
    return name.startswith("LD_") or name == "GCONV_PATH"


def _outside(env):
    """`env` for a process started outside the sandbox: without what would run the model's code in it."""
    return {name: value for name, value in env.items() if not _loads_code(name)}


def _notify_socket(env):
    """With systemd watching: a datagram socket of its own for the sandboxed Hermes, named in `env`, its bound
    fd handed to the supervisor. Bound before Hermes starts, so no datagram finds it missing. Abstract, as
    bubblewrap does not unshare the network; the supervisor takes only the sandboxed Hermes's own datagrams."""
    if not env.get("NOTIFY_SOCKET"):
        return None
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    name = f"wisp-notify-{secrets.token_hex(16)}"
    sock.bind("\0" + name)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    env["NOTIFY_SOCKET"] = "@" + name
    # Its PID is not the one systemd started, and a Hermes checking this one would not ping.
    env.pop("WATCHDOG_PID", None)
    return sock


def _child_pid(info):
    """The sandboxed command's host PID, from bubblewrap's info on the fd `info`; None once it closed without
    one, or said anything malformed: a failed start, never an exception out of the plugin."""
    said = b""
    try:
        while chunk := os.read(info, 4096):
            said += chunk
            try:
                pid = json.loads(said)["child-pid"]
            except ValueError:
                continue  # Not all of it yet.
            return pid if type(pid) is int and pid > 0 else None
    except (OSError, KeyError, TypeError):
        pass
    return None


def _answers_to_systemd(argv, environ, cgroup):
    """Whether this command could be a gateway a systemd service restarts when it exits, as far as it costs nothing
    to tell (`_a_unit_respawns_this_process` asks systemd). `INVOCATION_ID` alone proves nothing: a terminal tab's
    shell carries one too, and nothing respawns what runs in its scope."""
    runs = any(argv[i:i + 2] == ["gateway", "run"] for i in range(len(argv)))
    return runs and bool(environ.get("INVOCATION_ID")) and cgroup.strip().endswith(".service")


def _a_unit_respawns_this_process(cgroup):
    """Whether this process is the main one of its unit, and that unit's `Restart` brings it back after a drained
    exit. Stricter than Hermes's own `_respawning_service`, which decides what to pause: here a false yes leaves no
    gateway, as the update hands it back to a unit that does not restart it (a tmux server that exits 0, `on-abnormal`
    and the like), and a false no only a running one the update restarts itself (a `sudo -u x hermes` wrapper). So in doubt, no.
    One `systemctl show` of up to 10 seconds, on a start of `gateway run` in a service only."""
    path = cgroup.strip().splitlines()[-1].split(":", 2)[-1]  # A unit's name may hold a colon.
    systemctl = next((at for at in (os.path.join(folder, "systemctl") for folder in SYSTEMCTL_DIRS) if os.access(at, os.X_OK)), None)
    if systemctl is None:
        return False
    scope = [systemctl, "--user"] if "/user@" in path else [systemctl]
    try:
        shown = subprocess.run([*scope, "show", path.rsplit("/", 1)[-1], "--property=MainPID,Restart"],
                               capture_output=True, text=True, timeout=10, env=_outside(os.environ)).stdout
    except (OSError, subprocess.SubprocessError, ValueError):  # ValueError: output it cannot decode.
        return False
    said = dict(line.split("=", 1) for line in shown.splitlines() if "=" in line)
    return said.get("MainPID") == str(os.getpid()) and said.get("Restart") in ("always", "on-failure")


def _knows_external_supervisor():
    """Whether this Hermes's `gateway run` takes the flag; one that does not would refuse the argv, and leave no
    gateway. Every Hermes `wisp integrate hermes` accepts does (since v0.21.6): this is for one downgraded since.
    Not by asking `gateway run --help`, which would load this plugin again."""
    try:
        with open(importlib.util.find_spec("hermes_cli.subcommands.gateway").origin) as source:
            return EXTERNAL_SUPERVISOR in source.read()
    except (ImportError, AttributeError, OSError, ValueError):
        return False


def _command():
    """What runs under bubblewrap: this very command. A gateway its systemd service respawns also declares its
    manager, as its command line is all `hermes update` goes by: the supervisor is the unit's main PID, so the update
    takes the real gateway for a manual one, and without the flag starts its successor outside the unit. With it,
    the gateway exits back to the unit. No other gateway may say so: nothing would bring it back."""
    argv = sys.orig_argv[1:]
    try:
        with open("/proc/self/cgroup") as own:
            cgroup = own.read()
    except (OSError, ValueError):  # ValueError: a cgroup name it cannot decode.
        cgroup = ""
    # `sys.argv`: Hermes's relaunch sets it in `-c` code, so its command line has no `gateway run`. The flag is for
    # `hermes update`, which reads that command line: code that sets `sys.argv` ignores it, and has `INVOCATION_ID`.
    if _answers_to_systemd(sys.argv, os.environ, cgroup) and _knows_external_supervisor() and _a_unit_respawns_this_process(cgroup):
        argv = [*argv, EXTERNAL_SUPERVISOR]
    return [sys.executable, *argv]


def _inherited_fds():
    """The fds this process was handed beyond stdio, which the sandboxed Hermes is to have as this one does:
    `hermes update` passes its checkout lock to its children this way, and one without it takes the lock for
    another update's. bubblewrap keeps them open without a PID namespace. Never a directory: `/proc/self/fd/N/...`
    from one walks past a Private Folder's tmpfs. A file is the launcher's own grant."""
    def passes(fd):
        try:
            return os.get_inheritable(fd) and not stat.S_ISDIR(os.fstat(fd).st_mode)
        except OSError:  # The listing's own fd, closed by now.
            return False
    return [fd for fd in map(int, os.listdir("/proc/self/fd")) if fd > 2 and passes(fd)]


def _folders(denied, plugin_dir):
    return [*(arg for path in denied for arg in ("--deny", path)), "--read-only", plugin_dir]


def _check(denied, plugin_dir, wisp):
    """What keeps bubblewrap from sandboxing with these folders, or None. Probing them with `/bin/true`, so nothing the
    user can write decides it: bubblewrap says `child-pid` before it mounts, so a mount that fails after the takeover
    would end in no Hermes. What a folder would take from Hermes's start is `_start_root`'s, by path."""
    try:
        check = subprocess.run([wisp, "sandbox-exec", "--check", *_folders(denied, plugin_dir)], capture_output=True, text=True,
                               timeout=60, env=_outside(os.environ))
    except (OSError, subprocess.SubprocessError) as exc:
        return f"wisp sandbox-exec --check failed: {exc}"
    if check.returncode == 0:
        return None
    return check.stdout.strip() or check.stderr.strip() or f"wisp sandbox-exec --check failed: it exited {check.returncode}"


def _check_repeated(denied, plugin_dir, wisp):
    """`_check`, believed only after `PROBE_TRIES` failures in a row: one can be a passing thing (a process toggling a
    lock on a folder's parent, a load past the probe's timeout), and it would cost a real folder or the sandbox.
    ponytail: a process that keeps a folder failing still gets it left out, with the warning; this narrows that, no more."""
    for _ in range(PROBE_TRIES):
        if (problem := _check(denied, plugin_dir, wisp)) is None:
            return None
    return problem


def _reexec(denied, plugin_dir, wisp):
    """Linux: this Hermes started again under bubblewrap, with the arguments `wisp sandbox-exec` prints, and this
    process, keeping its PID, turned into the supervisor (`supervise.py`); the reason it could not or a folder was
    left out, or None when it already runs there with all of them. The fresh process has no unconfined thread, as an in-process sandbox (Landlock) would
    leave. bubblewrap's info comes through an anonymous pipe: nothing outside the sandbox opens a path a process
    left inside could swap. Inside a sandbox, a list that fails costs no more probes: the start before this one made them."""
    if _sandboxed(denied, plugin_dir):
        return None
    # Cheap first: Hermes starts with no Node child where bubblewrap is not even there.
    if not os.path.exists(BWRAP):
        return "bubblewrap is not installed: sudo apt install bubblewrap"
    wisp = wisp or shutil.which("wisp")
    if not wisp:
        return "wisp is not on PATH, so Hermes cannot be re-run under bubblewrap"
    problem = _check(denied, plugin_dir, wisp)
    if problem is not None:
        # Inside, bubblewrap may make no namespace (Ubuntu 25.04+'s AppArmor), so its reason would be that, not the
        # folder's: the kernel names what the start before this one left out.
        if _sandboxed([], plugin_dir):
            return f"bubblewrap could not mount {', '.join(f for f in denied if not _sandboxed([f], plugin_dir))}"
        # A link a model left at an absent folder's path can resolve to what no tmpfs can cover (a folder `/bin/true` lives
        # in, or a path too long to mount): that folder goes, not the sandbox around the others.
        if _check_repeated([], plugin_dir, wisp) is not None:
            return problem
        denied = [folder for folder in denied if _check_repeated([folder], plugin_dir, wisp) is None]
        if (left := _check_repeated(denied, plugin_dir, wisp)) is not None:
            return left
    folders = _folders(denied, plugin_dir)
    command = _command()
    for _ in range(PROBE_TRIES):
        try:
            printed = subprocess.run([wisp, "sandbox-exec", "--print-args", *folders, "--", *command], capture_output=True,
                                     timeout=60, env=_outside(os.environ))
        except (OSError, subprocess.SubprocessError) as exc:
            why = str(exc)
            continue
        if printed.returncode == 0:
            break
        why = printed.stderr.decode(errors="replace").strip() or f"it exited {printed.returncode}"
    else:
        return f"wisp sandbox-exec failed: {why}"
    env = dict(os.environ)
    notify = _notify_socket(env)
    # bubblewrap passes its own environment on: the sandboxed Hermes gets the rest back as it was (CUDA, conda).
    # Options, so before the printed `--` and the command.
    kept = [arg for name, value in env.items() if _loads_code(name) for arg in ("--setenv", name, value)]
    sys.stdout.flush()
    sys.stderr.flush()
    info, written = os.pipe()
    try:
        started = subprocess.Popen([BWRAP, "--info-fd", str(written), *kept, *printed.stdout.split(b"\0")], env=_outside(env),
                                   pass_fds=[written, *_inherited_fds()])
    finally:
        os.close(written)
    child = _child_pid(info)
    os.close(info)
    if child is None:
        started.kill()
        return f"wisp sandbox-exec failed: bubblewrap exited {started.wait()}"
    if notify is not None:
        os.set_inheritable(notify.fileno(), True)
    try:
        # `-I` drops `PYTHON*`, not the loader's variables. Its `NOTIFY_SOCKET` stays systemd's own.
        os.execve(sys.executable, [sys.executable, "-I", "-S", os.path.join(plugin_dir, "supervise.py"),
                                   str(started.pid), str(child), str(notify.fileno()) if notify is not None else "-"], _outside(os.environ))
    except OSError as exc:
        # The sandboxed Hermes runs and no supervisor would forward to it: it goes, and this one carries on.
        os.kill(child, signal.SIGKILL)
        started.wait()
        return f"wisp sandbox-exec failed: {exc}"


def _without_chromes_sandbox():
    """Chrome's own sandbox cannot start inside ours, so Hermes's browser goes without it: `--no-sandbox` after the
    user's own Chromium args, which Hermes reads comma-separated. Only once this process runs in Wisp's sandbox:
    outside it, Chrome's is all that stands between a page that takes the renderer and the user's account."""
    args = os.environ.get("AGENT_BROWSER_ARGS", "")
    if "--no-sandbox" not in (arg.strip() for arg in args.split(",")):
        os.environ["AGENT_BROWSER_ARGS"] = f"{args},--no-sandbox" if args.strip() else "--no-sandbox"


def apply(denied, plugin_dir, wisp):
    """Sandboxes this process; the reason it could not or left a folder out, or None, never an exception. A second
    `sandbox_init` in one process fails, so a profile cannot be tightened once applied. On Linux `wisp` (the pinned binary,
    else the one on PATH) re-execs it under bubblewrap."""
    if sys.platform not in ("darwin", "linux"):
        return f"no sandbox on {sys.platform}"
    try:
        if sys.platform == "linux":
            # A working start returns here only inside bubblewrap; so can a folder left out of a running sandbox.
            problem = _reexec(denied, plugin_dir, wisp)
            if _sandboxed([], plugin_dir):
                _without_chromes_sandbox()
            return problem
        sandbox_init = ctypes.CDLL(None).sandbox_init
        sandbox_init.argtypes = [ctypes.c_char_p, ctypes.c_uint64, ctypes.POINTER(ctypes.c_char_p)]
        error = ctypes.c_char_p()
        if sandbox_init(profile(denied, plugin_dir).encode(), 0, ctypes.byref(error)) != 0:
            return f"sandbox_init failed: {(error.value or b'').decode(errors='replace')}"
    except Exception as exc:  # noqa: BLE001 — whatever stops the start, Hermes carries on, and says so
        return f"the sandbox could not start: {exc!r}"
    _without_chromes_sandbox()
    return None


def _zone_folders(zone):
    """The zone's folders, then the Runtime's secret files: each denied as a path, which on macOS covers a file as it
    does a folder, and on Linux `wisp sandbox-exec` covers by what it finds there."""
    return [zone["dataDir"], zone["deskRoot"], *(folder["path"] for folder in zone["privateFolders"]),
            *(zone.get("secretFiles") or [])]


def _within(path, folder):
    return path == folder or path.startswith(folder.rstrip(os.sep) + os.sep)


def _on_the_way(path):
    """What the kernel passes through to reach absolute `path`: each link, where it really lies, then the real path it ends at (as
    `realpath`, a link past 40 stopping there). Denying any of them, `path` no longer opens, however it was named."""
    here, parts, links = os.sep, os.path.join(os.sep, path).split(os.sep), []
    while parts and len(links) < 40:
        part = parts.pop(0)
        if part == "..":
            here = os.path.dirname(here)
        elif part not in ("", "."):
            at = os.path.join(here, part)
            try:
                target = os.readlink(at)
            except OSError:
                here = at
                continue
            links.append(at)
            parts[:0] = target.split(os.sep)
            if os.path.isabs(target):
                here = os.sep
    return [*links, here]


def _start_root(folder, linked):
    """What Hermes starts from that denying `folder` would take from it, decided once with no probe to time: `sys.prefix`,
    `sys.base_prefix` or the source tree of `hermes_cli` when `folder` holds one or, for a zone path that does not name
    `folder` itself (`linked`: a model can plant a link), lies inside one; `sys.executable` or the entry script when it
    holds one. Each by every link on its way as well as by `realpath`; a real folder inside a root stays closed, even one
    Hermes needs. Else None. What cannot be found is not looked for: that alone never fails a start."""
    roots = [_on_the_way(root) for root in filter(None, (sys.prefix, sys.base_prefix))]
    package = getattr(sys.modules.get("hermes_cli"), "__file__", None)
    if package:
        *links, real = _on_the_way(package)
        roots.append([*links, os.path.dirname(os.path.dirname(real))])
    files = [_on_the_way(path) for path in filter(None, (sys.executable, getattr(sys.modules.get("__main__"), "__file__", None)))]
    for way in (*roots, *files):
        for stop in way:
            if _within(stop, folder):
                return stop
    for way in roots:
        if linked and _within(folder, way[-1]):
            return way[-1]
    return None


def _reads(folder, denied):
    """Whether this process sees what is in `folder`: it opens and has an entry that is not itself denied (a
    tmpfs over `folder` holds the mount point of each denied folder inside it). ponytail: an empty folder
    reads as unseen, there being nothing in it to read yet."""
    try:
        with os.scandir(folder) as entries:
            return any(entry.path not in denied for entry in entries)
    except OSError:
        return False


def _here(path):
    try:
        os.stat(path)
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError:
        pass  # Only nothing there says Wisp is elsewhere: a sandbox inherited from a parent denies even a stat.
    return True


def _has_terminal():
    """Whether this process has a controlling terminal, stdin or not: `hermes </dev/null` on a terminal can still
    type into it."""
    try:
        os.close(os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY))
    except OSError:
        return False
    return True


def tiocsti_warning(sysctl=LEGACY_TIOCSTI):
    """Linux, on a terminal: bubblewrap without `--new-session` (which would break job control) leaves the
    sandboxed Hermes the terminal's `TIOCSTI`, if the kernel still allows it; kernels before 6.2 have no such
    switch and always do."""
    typing = "on this kernel the sandboxed Hermes can type commands into this terminal"
    try:
        with open(sysctl) as switch:
            allowed = switch.read().strip() == "1"
    except FileNotFoundError:
        return f"{typing}; upgrade to kernel 6.2+"
    except OSError:
        return None
    return f"{typing}; set `sysctl dev.tty.legacy_tiocsti=0` (kernel 6.2+)" if allowed else None


def protect(zone, plugin_dir, hermes_home, pinned=None, wisp=None):
    """Sandboxes this Hermes process away from `zone` when Wisp is local (its data directory is on this
    machine; for a zone `wisp integrate hermes` pinned, any of its folders), then checks from inside that
    the zone is out of reach. `pinned` is that pin. When the whole list fails with a pin, the pinned folders alone get one
    more try. The warnings to show in Hermes: a pinned zone left unsandboxed always warns."""
    zone_folders = _zone_folders(zone)
    if not (any(map(_here, zone_folders)) if pinned else _here(zone["dataDir"])):
        return [f"{UNPROTECTED}: none of the folders wisp integrate hermes pinned is on this machine"] if pinned else []
    hermes_home = os.path.realpath(hermes_home)
    plugin = os.path.realpath(plugin_dir)
    warnings = []
    denied = []
    for path in zone_folders:
        folder = os.path.realpath(path)
        # Denied, it would take Hermes's own config from it; `wisp private add` refuses such a folder.
        if _within(hermes_home, folder):
            warnings.append(f"{UNPROTECTED}: {folder} holds Hermes's home {hermes_home}, so it is not sandboxed; "
                            "remove it (wisp private remove) and add the folders inside it instead")
        # A link can resolve here. The plugin's read-only bind goes over any tmpfs, which would never read as sandboxed.
        elif _within(folder, plugin):
            warnings.append(f"{UNPROTECTED}: {folder} is inside Wisp's plugin, so it is not sandboxed")
        # A link can resolve here too. `/proc/self/...` names another path in each process, so a start would never read
        # as sandboxed: under bubblewrap it would re-exec again and again, until the kernel refused a mount.
        elif _within(folder, "/proc"):
            warnings.append(f"{UNPROTECTED}: {folder} is under /proc, so it is not sandboxed")
        # A link can resolve here too. Denied, Hermes would not start, or would fail inside on every start, naming no folder.
        elif root := _start_root(folder, folder != path):
            warnings.append(f"{UNPROTECTED}: {folder} would take {root} from Hermes's start, so it is not sandboxed")
        else:
            denied.append(folder)
    kept = set(map(os.path.realpath, _zone_folders(pinned or zone)))
    held = [folder for folder in denied if folder in kept]
    failed = apply(denied, plugin, wisp)
    # On Linux a start that works never returns here: the Hermes it starts comes through this with the sandbox up, and goes no deeper.
    left = []
    if failed and held != denied:
        again = None if _sandboxed(held, plugin) else apply(held, plugin, wisp)
        if again is None:
            # The kernel says which: on Linux an added folder can be in the sandbox with another left out, on macOS none is.
            left = [folder for folder in denied if folder not in held and not _sandboxed([folder], plugin)]
            if left:
                warnings.append(f"{UNPROTECTED}: of the folders added since wisp integrate hermes, these are not sandboxed: "
                                f"{', '.join(left)} ({failed})")
                failed = None
        else:
            failed = again
    open_folders = [folder for folder in denied if folder not in left and _reads(folder, denied)]
    if open_folders:
        warnings.append(f"{UNPROTECTED}: Hermes can read {', '.join(open_folders)}"
                        + (f" ({failed})" if failed else ""))
    elif failed:
        warnings.append(f"{UNPROTECTED}: {failed}")
    # `failed` under a running sandbox: a folder was left out of it, and all this still holds for the rest.
    if sys.platform == "linux" and (not failed or _sandboxed([], plugin)):
        # A folder's tmpfs goes up at the start; macOS denies by path, so a missing one is denied too.
        if pinned:
            warnings.extend(f"{folder} is not there yet, so Hermes is not kept out of it once it appears; "
                            "restart Hermes after it exists" for folder in denied if not os.path.exists(folder))
        if _has_terminal() and (typing := tiocsti_warning()):
            warnings.append(typing)
    return warnings

