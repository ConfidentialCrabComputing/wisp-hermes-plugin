"""What the process Hermes was started as becomes on Linux once its sandboxed Hermes runs (`sandbox.py`): it
keeps that PID, so it stays systemd's main PID and the parent the CLI's shell waits on, without the memory of a
loaded Hermes. Run outside the sandbox with `-I -S`, from the plugin's directory, which the sandboxed Hermes
cannot write.

    supervise.py <the started command's pid> <the sandboxed Hermes's host pid> <notify socket's fd, or ->"""

import ctypes
import os
import signal
import socket
import struct
import sys
import threading
import time

PR_SET_CHILD_SUBREAPER = 36
FORWARDED = (signal.SIGTERM, signal.SIGHUP, signal.SIGUSR1, signal.SIGUSR2)
# What systemd may hear from Hermes. Never `MAINPID=` (the main PID is this one) or the fd store.
RELAYED = ("READY=", "RELOADING=", "STOPPING=", "WATCHDOG=", "STATUS=", "EXTEND_TIMEOUT_USEC=", "MONOTONIC_USEC=")
UCRED = struct.Struct("3i")


def _forward(child, signum):
    try:
        os.kill(child, signum)
    except ProcessLookupError:
        pass


def _relay(sock, child, target):
    """Each datagram of the sandboxed Hermes itself, as `NotifyAccess=main` would take only the main PID's:
    its allowed lines, to the real socket. A process it started sends in vain."""
    out = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    address = "\0" + target[1:] if target.startswith("@") else target
    while True:
        data, ancillary, _flags, _from = sock.recvmsg(4096, socket.CMSG_SPACE(UCRED.size))
        senders = [UCRED.unpack(cdata[:UCRED.size])[0] for level, kind, cdata in ancillary
                   if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS]
        if senders != [child]:
            continue
        lines = [line for line in data.split(b"\n") if line.decode(errors="replace").startswith(RELAYED)]
        if lines:
            try:
                out.sendto(b"\n".join(lines), address)
            except OSError:
                pass  # As `sd_notify`: a manager gone or busy costs Hermes nothing.


def _alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        pass
    return True


def _cmdline(pid):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as cmdline:
            return cmdline.read()
    except OSError:
        return None


def _retire_bubblewrap(started, child):
    """bubblewrap goes, once it has started Hermes, and this process inherits Hermes. Without a PID namespace it
    only waits on it, and its command line ends in Hermes's: `hermes update` and `hermes gateway status`, which go by
    command lines, would take it for a second gateway, and `hermes update` would stop it and say to restart it by
    hand. Not sooner: until bubblewrap has told its child to go on, the child waits on it (a fork carries its
    parent's command line up to the exec, so a command line of its own says it is past that; so does an empty one, a
    child in the middle of its exec or dead, and nothing would reap two dead children while this waits). It was
    never reaped, so `started` cannot be another process by now."""
    while (now := _cmdline(child)) and now == _cmdline(started):
        time.sleep(0.01)
    os.kill(started, signal.SIGKILL)


def _wait(started, child):
    """The wait status to exit with: the sandboxed Hermes's own, as this process's child, else what bubblewrap
    said of a Hermes that never came to be."""
    status = 0
    while True:
        try:
            pid, status_of = os.waitpid(-1, 0)
        except ChildProcessError:
            return status
        if pid == child:
            return status_of
        if pid == started:
            status = status_of
            if not _alive(child):
                return status


def main(started, child, notify):
    ctypes.CDLL(None).prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
    for signum in FORWARDED:
        signal.signal(signum, lambda received, _frame: _forward(child, received))
    # The terminal sends these to the whole process group: Hermes already has them. SIGTSTP keeps its default:
    # this process stops with Hermes, and the shell sees the job stopped.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGQUIT, signal.SIG_IGN)
    _retire_bubblewrap(started, child)
    if notify != "-":
        sock = socket.socket(fileno=int(notify))
        threading.Thread(target=_relay, args=(sock, child, os.environ["NOTIFY_SOCKET"]), daemon=True).start()
    code = os.waitstatus_to_exitcode(_wait(started, child))
    sys.exit(128 - code if code < 0 else code)


if __name__ == "__main__":
    main(int(sys.argv[1]), int(sys.argv[2]), sys.argv[3])
