"""The plugin's self-sandbox at Hermes's start, in a real Python process: the fake `hermes` loads the plugin
as Hermes does, with Wisp's zone from its cache. On Linux it re-execs itself under
bubblewrap through the real `wisp`, from a wisp-agent checkout (`wisp-from-source/wisp` says which; without
one those tests skip): run as root there (wisp-agent CI's sandbox e2e), as Ubuntu's AppArmor blocks bubblewrap's
user namespaces for anyone else.
Run: python3 -m unittest discover -s tests"""

import http.server
import importlib.util
import json
import os
import random
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

FAKE = Path(__file__).resolve().parent / "fake"
WISP = Path(__file__).resolve().parent / "wisp-from-source"
PLUGIN = Path(__file__).resolve().parents[1] / "wisp"
UNPROTECTED = "Wisp's zone is unprotected"
macos = unittest.skipUnless(sys.platform == "darwin", "the macOS sandbox")
linux = unittest.skipUnless(sys.platform == "linux", "the Linux sandbox")
posix = unittest.skipIf(sys.platform == "win32", "needs POSIX: a terminal, a script's shebang, or a sandbox to warn of")


def _bwrap_sandboxes():
    """Whether `wisp sandbox-exec` runs under bubblewrap here; asked once, and only on Linux."""
    if sys.platform != "linux" or not os.path.exists("/usr/bin/bwrap"):
        return False
    return subprocess.run([str(WISP / "wisp"), "sandbox-exec", "--check"], capture_output=True).returncode == 0


# Where the plugin sandboxes Hermes: macOS always, Linux where bubblewrap can.
sandboxed = unittest.skipUnless(sys.platform == "darwin" or _bwrap_sandboxes(), "no sandbox here")


# What a model inside can leave at an absent Private Folder's path, for `stat` to fail on: (what, the folder, the code).
_PLANTS = [
    ("a link to itself", "self", lambda at: f"os.symlink({str(at)!r}, {str(at)!r})"),
    ("a link with a target's name too long", "long", lambda at: f"os.symlink({'x' * 300!r}, {str(at)!r})"),
    ("a loop at its parent", "loop/taxes", lambda at: f"os.symlink({str(at.parent)!r}, {str(at.parent)!r})"),
]


READ_THE_SECRETS = """
load_plugin()
for path in {paths!r}:
    try:
        open(path).read()
        print("read")
    except OSError:
        print("refused")"""


class HermesHome(unittest.TestCase):
    """A temp Hermes home with the plugin laid out and a zone on disk."""

    def setUp(self):
        # realpath: macOS's temp directory sits behind the /var -> /private/var link.
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp(prefix="wisp-hermes-sandbox-")))
        self.addCleanup(shutil.rmtree, self.tmp)
        self.home = self.tmp / "hermes"
        self.plugin = self.home / "plugins" / "wisp"
        shutil.copytree(PLUGIN, self.plugin, ignore=shutil.ignore_patterns("__pycache__", "zone.json"))
        (self.home / "config.yaml").write_text(json.dumps({"plugins": {"enabled": ["wisp"]}}))
        self.data_dir = self.tmp / "wisp"
        self.bank = self.tmp / "bank"
        for folder in (self.data_dir, self.data_dir / "desks", self.bank):
            folder.mkdir()
            (folder / "secret.txt").write_text("secret")
        self.zone = {"dataDir": str(self.data_dir), "deskRoot": str(self.data_dir / "desks"),
                     "privateFolders": [{"path": str(self.bank)}], "services": []}

    def python(self, code, wrap=()):
        """Runs `code` in a fake Hermes process that loads the plugin when `code` calls `load_plugin()`."""
        return self.hermes("python", code, wrap=wrap)

    def env(self):
        if self.zone is not None:
            (self.plugin / "zone.json").write_text(json.dumps(self.zone))
        return {**os.environ, "HERMES_HOME": str(self.home),
                "PATH": os.pathsep.join([str(FAKE), str(WISP), os.environ["PATH"]])}

    def hermes(self, *argv, wrap=(), stdin=None):
        done = subprocess.run([*wrap, sys.executable, str(FAKE / "hermes"), *argv],
                              env=self.env(), capture_output=True, text=True, input=stdin)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done

    def hermes_as_it_lives(self):
        """A source of its own, run by a venv's interpreter: (the venv, the source)."""
        venv = self.tmp / "venv"
        subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(venv)], check=True)
        source = self.tmp / "source"
        shutil.copytree(FAKE, source, ignore=shutil.ignore_patterns("__pycache__"))
        (source / "tools").mkdir(exist_ok=True)
        return venv, source

    def start_as(self, python, hermes, code):
        return subprocess.run([str(python), str(hermes), "python", code], env=self.env(), capture_output=True, text=True)

    def readable(self, path):
        """Whether the sandboxed Hermes reads `path` from its main thread."""
        done = self.python(f"""
load_plugin()
try:
    open({str(path)!r}).read()
    print("read")
except OSError:
    print("refused")""")
        return done.stdout.strip() == "read"


class Sandbox(HermesHome):
    @sandboxed
    def test_a_read_inside_the_zone_is_refused_from_the_main_thread(self):
        self.assertFalse(self.readable(self.bank / "secret.txt"))

    @sandboxed
    def test_a_read_inside_the_zone_is_refused_from_a_thread_started_before_the_sandbox(self):
        done = self.python(f"""
import queue, threading
asks, answers = queue.Queue(), queue.Queue()
def worker():
    asks.get()
    try:
        open({str(self.bank / "secret.txt")!r}).read()
        answers.put("read")
    except OSError:
        answers.put("refused")
threading.Thread(target=worker, daemon=True).start()
load_plugin()
asks.put(None)
print(answers.get(timeout=10))""")
        self.assertEqual(done.stdout.strip(), "refused")

    @sandboxed
    def test_a_read_inside_the_zone_is_refused_from_a_child_process(self):
        done = self.python(f"""
import subprocess
load_plugin()
print(subprocess.run(["cat", {str(self.bank / "secret.txt")!r}], capture_output=True).returncode)""")
        self.assertNotEqual(done.stdout.strip(), "0")

    @sandboxed
    def test_wisps_secret_files_cannot_be_read_or_replaced_and_their_folder_stays_usable(self):
        config = self.tmp / "config" / "wisp"
        config.mkdir(parents=True)
        key = config / "master.key"
        key.write_text("root key")
        serve = self.tmp / "serve.json"
        serve.write_text("agent token")
        self.zone["secretFiles"] = [str(key), str(serve)]

        # On Linux the file reads as the empty `/dev/null` over it, and a write goes there; on macOS both are refused.
        done = self.python(f"""
import os
load_plugin()
for path in {[str(key), str(serve)]!r}:
    for attempt in ("read", "write", "replace", "remove", "link"):
        try:
            if attempt == "read":
                print("read", repr(open(path).read()))
                continue
            elif attempt == "write":
                open(path, "w").write("x")
            elif attempt == "replace":
                open(path + ".new", "w").write("x")
                os.replace(path + ".new", path)
            elif attempt == "remove":
                os.remove(path)
            else:
                os.link(path, path + ".link")
                print("link", repr(open(path + ".link").read()))
                continue
            print(attempt, "done")
        except OSError:
            print(attempt, "refused")
open({str(self.tmp / "beside.txt")!r}, "w").write("beside")
print("beside", open({str(self.tmp / "beside.txt")!r}).read())""")

        seen = done.stdout.splitlines()
        self.assertEqual(seen[-1], "beside beside", done.stderr)
        for line in seen[:-1]:
            self.assertIn(line, ["read refused", "read ''", "write refused", "write done", "replace refused",
                                 "remove refused", "link refused", "link ''"])
        self.assertEqual(len(seen), 11)
        self.assertEqual(key.read_text(), "root key")
        self.assertEqual(serve.read_text(), "agent token")
        self.assertNotIn(UNPROTECTED, done.stderr)

    @macos
    def test_a_zone_folder_cannot_be_moved_out_from_under_the_sandbox_by_renaming_its_parent(self):
        parent = self.tmp / "docs"
        parent.mkdir()
        self.bank.rename(parent / "bank")
        self.zone["privateFolders"] = [{"path": str(parent / "bank")}]
        self.addCleanup(shutil.rmtree, f"{self.tmp}2", ignore_errors=True)

        done = self.python(f"""
import os
load_plugin()
for old, new in (({str(parent)!r}, {str(self.tmp / "docs2")!r}), ({str(self.tmp)!r}, {str(self.tmp) + "2"!r})):
    try:
        os.rename(old, new)
        print("moved")
    except OSError:
        print("refused")""")

        self.assertEqual(done.stdout.split(), ["refused", "refused"])

    @macos
    def test_a_zone_folder_cannot_be_read_through_a_clone_of_its_parent_or_grandparent(self):
        parent = self.tmp / "docs"
        parent.mkdir()
        self.bank.rename(parent / "bank")
        self.zone["privateFolders"] = [{"path": str(parent / "bank")}]
        elsewhere = Path(os.path.realpath(tempfile.mkdtemp(prefix="wisp-hermes-clone-")))
        self.addCleanup(shutil.rmtree, elsewhere)

        # APFS's `clonefile` copies a whole tree in the kernel, without a read of what is inside.
        done = self.python(f"""
import ctypes, os
load_plugin()
libc = ctypes.CDLL(None, use_errno=True)
for source, clone in (({str(parent)!r}, {str(elsewhere / "docs")!r}), ({str(self.tmp)!r}, {str(elsewhere / "tmp")!r})):
    print("cloned" if libc.clonefile(source.encode(), clone.encode(), 0) == 0 else "refused")""")

        self.assertEqual(done.stdout.split(), ["refused", "refused"], done.stderr)
        self.assertEqual(list(elsewhere.rglob("secret.txt")), [])

    @macos
    def test_a_missing_ancestor_of_a_zone_folder_cannot_be_made_by_the_sandboxed_hermes(self):
        self.zone["privateFolders"].append({"path": str(self.tmp / "m" / "n" / "taxes")})
        elsewhere = Path(os.path.realpath(tempfile.mkdtemp(prefix="wisp-hermes-plant-")))
        self.addCleanup(shutil.rmtree, elsewhere)

        # One Hermes each: what the first made would stand in the second's way, and nothing inside can remove it.
        for make in (f"os.mkdir({str(self.tmp / 'm')!r})", f"os.symlink({str(elsewhere)!r}, {str(self.tmp / 'm')!r})"):
            done = self.python(f"""
import os
load_plugin()
try:
    {make}
    print("made")
except OSError:
    print("refused")""")

            self.assertEqual(done.stdout.split(), ["refused"], make + done.stderr)
            self.assertFalse(os.path.lexists(self.tmp / "m"))

    @macos
    def test_a_parent_the_sandbox_keeps_in_place_answers_access_chmod_and_new_files_as_without_it(self):
        # Empty, as an absent Private Folder's parent can be: only the sandbox stands between it and an `rmdir`.
        empty = self.tmp / "empty"
        empty.mkdir()
        self.zone["privateFolders"].append({"path": str(empty / "taxes")})
        parents = [self.plugin.parent, self.home, self.tmp, empty]

        done = self.python(f"""
import os
load_plugin()
for parent in {[str(p) for p in parents]!r}:
    said = [os.access(parent, os.W_OK)]
    try:
        os.chmod(parent, 0o700)
        open(os.path.join(parent, "new.txt"), "w").write("new")
        said.append("changed")
    except OSError as exc:
        said.append(repr(exc))
    for move in (lambda: os.rename(parent, parent + ".moved"), lambda: os.rmdir(parent)):
        try:
            move()
            said.append("moved")
        except OSError:
            said.append("refused")
    print(*said)""")

        self.assertEqual(done.stdout.splitlines(), ["True changed refused refused"] * len(parents), done.stderr)

    @sandboxed
    def test_wisps_data_directory_and_desk_root_are_refused(self):
        self.assertFalse(self.readable(self.data_dir / "secret.txt"))
        self.assertFalse(self.readable(self.data_dir / "desks" / "secret.txt"))

    @sandboxed
    def test_reads_elsewhere_new_files_beside_the_zone_and_the_network_work(self):
        elsewhere = self.tmp / "notes.txt"
        elsewhere.write_text("notes")
        done = self.python(f"""
import http.server, threading, urllib.request
server = http.server.HTTPServer(("127.0.0.1", 0), http.server.SimpleHTTPRequestHandler)
threading.Thread(target=server.serve_forever, daemon=True).start()
load_plugin()
print(open({str(elsewhere)!r}).read())
open({str(self.tmp / "new.txt")!r}, "w").write("new")
print(urllib.request.urlopen(f"http://127.0.0.1:{{server.server_address[1]}}/").status)""")
        self.assertEqual(done.stdout.split(), ["notes", "200"])
        self.assertEqual((self.tmp / "new.txt").read_text(), "new")

    @sandboxed
    def test_writes_to_the_plugins_directory_are_refused(self):
        done = self.python(f"""
load_plugin()
for path in ({str(self.plugin / "__init__.py")!r}, {str(self.plugin / "zone.json")!r}, {str(self.plugin / "new.py")!r}):
    try:
        open(path, "a").write("x")
        print("written")
    except OSError:
        print("refused")""")
        self.assertEqual(done.stdout.split(), ["refused"] * 3)

    @macos
    def test_connect_remove_inside_the_sandbox_finishes_and_says_nothing_of_the_cache_it_keeps(self):
        done = self.hermes("wisp", "connect", "--remove")

        self.assertNotIn("zone.json", done.stdout + done.stderr)

    @sandboxed
    def test_the_browser_runs_without_chromes_own_sandbox_after_the_users_own_args(self):
        for before, after in ((None, "--no-sandbox"), ("", "--no-sandbox"), ("--lang=de", "--lang=de,--no-sandbox"),
                              ("--no-sandbox,--lang=de", "--no-sandbox,--lang=de")):
            with self.subTest(before=before):
                done = self.python("""
import os
load_plugin()
print(os.environ.get("AGENT_BROWSER_ARGS"))""", ("env", "-u", "AGENT_BROWSER_ARGS", *([] if before is None else [f"AGENT_BROWSER_ARGS={before}"])))

                self.assertEqual(done.stdout.strip(), after)

    def test_wisp_on_another_machine_applies_no_sandbox_and_warns_nothing(self):
        shutil.rmtree(self.data_dir)
        self.zone["deskRoot"] = str(self.tmp / "elsewhere" / "desks")

        self.assertTrue(self.readable(self.bank / "secret.txt"))
        self.assertNotIn(UNPROTECTED, self.python("load_plugin()").stderr)

    @macos
    def test_loaded_unsandboxed_with_wisp_local_it_warns(self):
        # An outer sandbox makes the plugin's own `sandbox_init` fail.
        stderr = self.python("load_plugin()", ("sandbox-exec", "-p", "(version 1)(allow default)")).stderr

        self.assertIn(UNPROTECTED, stderr)
        self.assertIn(str(self.data_dir), stderr)

    @macos
    def test_a_failed_sandbox_start_leaves_chromes_own_sandbox_on(self):
        for before in ([], ["AGENT_BROWSER_ARGS=--lang=de"]):
            with self.subTest(before=before):
                done = self.python("""
import os
load_plugin()
print(os.environ.get("AGENT_BROWSER_ARGS"))""", ("env", "-u", "AGENT_BROWSER_ARGS", *before,
                 "sandbox-exec", "-p", "(version 1)(allow default)"))

                self.assertIn(UNPROTECTED, done.stderr)
                self.assertEqual(done.stdout.strip(), "--lang=de" if before else "None")

    @linux
    @sandboxed
    def test_the_mark_a_model_could_leave_in_hermess_env_file_does_not_stop_the_sandbox(self):
        done = self.python(f"""
load_plugin()
try:
    open({str(self.bank / "secret.txt")!r}).read()
    print("read")
except OSError:
    print("refused")""", ("env", "WISP_HERMES_SANDBOXED=1"))

        self.assertEqual(done.stdout.strip(), "refused")

    @sandboxed
    def test_with_no_terminal_it_says_nothing_of_typing_into_one(self):
        self.assertNotIn("type commands", self.hermes("python", "load_plugin()", stdin="").stderr)

    @posix
    def test_a_zone_it_cannot_read_warns(self):
        # Connected to a loopback port nothing listens on, with no zone cached.
        closed = socket.create_server(("127.0.0.1", 0))
        port = closed.getsockname()[1]
        closed.close()
        (self.home / "config.yaml").write_text(json.dumps(
            {"plugins": {"enabled": ["wisp"]}, "mcp_servers": {"wisp": {"url": f"http://127.0.0.1:{port}/mcp"}}}))
        (self.home / ".env").write_text("WISP_CREDENTIAL_TOKEN=wisp_hermes_s3cr3t\n")
        self.zone = None

        self.assertIn(UNPROTECTED, self.python("load_plugin()").stderr)

    @sandboxed
    def test_sandboxed_it_does_not_warn(self):
        self.assertNotIn(UNPROTECTED, self.python("load_plugin()").stderr)

    @sandboxed
    def test_a_hermes_started_inside_a_sandboxed_one_keeps_its_sandbox_and_does_not_warn(self):
        done = self.python(f"""
import subprocess, sys
load_plugin()
child = subprocess.run([sys.executable, {str(FAKE / "hermes")!r}, "python",
                        "load_plugin(); print(open({str(self.bank / "secret.txt")!r}).read())"],
                       capture_output=True, text=True)
print(child.returncode)
sys.stderr.write(child.stderr)""")
        self.assertNotEqual(done.stdout.strip(), "0")
        self.assertNotIn(UNPROTECTED, done.stderr)

    @sandboxed
    def test_a_secret_file_named_with_a_quote_a_backslash_or_a_control_character_is_still_denied_and_nothing_beside_it(self):
        for name in ('x") (allow file-read* (subpath "', 'a\\b"c', "a\nb\x01c"):
            with self.subTest(name=name):
                secret = self.tmp / name
                secret.write_text("secret")
                beside = self.tmp / "beside.txt"
                beside.write_text("beside")
                self.zone["secretFiles"] = [str(secret)]

                # On Linux the file reads as the empty `/dev/null` over it.
                done = self.python(f"""
load_plugin()
try:
    print(repr(open({str(secret)!r}).read()))
except OSError:
    print("refused")""")

                self.assertIn(done.stdout.strip(), ("refused", "''"), done.stderr)
                self.assertTrue(self.readable(beside))

    @sandboxed
    def test_a_private_folder_named_with_a_quote_and_a_backslash_is_still_denied_and_nothing_beside_it(self):
        for name in ('x") (allow file-read* (subpath "', 'a\\b"c'):
            with self.subTest(name=name):
                folder = self.tmp / name
                folder.mkdir()
                (folder / "secret.txt").write_text("secret")
                beside = self.tmp / "beside.txt"
                beside.write_text("beside")
                self.zone["privateFolders"] = [{"path": str(folder)}]

                self.assertFalse(self.readable(folder / "secret.txt"))
                self.assertTrue(self.readable(beside))

    @linux
    @sandboxed
    @unittest.skipIf(hasattr(os, "getuid") and os.getuid() == 0, "root reads through a 0o000 folder")
    def test_a_private_folder_under_a_locked_parent_stays_out_of_reach_after_an_unlock_and_it_does_not_warn(self):
        docs = self.tmp / "docs"
        taxes = docs / "taxes"
        taxes.mkdir(parents=True)
        (taxes / "secret.txt").write_text("secret")
        self.zone["privateFolders"] = [{"path": str(taxes)}]
        docs.chmod(0o000)
        self.addCleanup(docs.chmod, 0o755)

        done = self.python(f"""
import os
load_plugin()
os.chmod({str(docs)!r}, 0o755)
try:
    open({str(taxes / "secret.txt")!r}).read()
    print("read")
except OSError:
    print("refused")""")

        self.assertEqual(done.stdout.strip(), "refused")
        self.assertNotIn(UNPROTECTED, done.stderr)

    @linux
    @sandboxed
    def test_what_a_model_plants_at_an_absent_private_folder_leaves_the_next_start_sandboxed(self):
        for name, folder, plant in _PLANTS:
            with self.subTest(name):
                at = self.tmp / folder
                self.zone["privateFolders"] = [{"path": str(self.bank)}, {"path": str(at)}]
                self.python(f"import os\nload_plugin()\n{plant(at)}")

                done = self.python(f"""
load_plugin()
for path in {[str(self.bank / "secret.txt"), str(self.data_dir / "secret.txt")]!r}:
    try:
        open(path).read()
        print("read")
    except OSError:
        print("refused")""")

                self.assertEqual(done.stdout.split(), ["refused", "refused"])
                self.assertNotIn(UNPROTECTED, done.stderr)

    @linux
    @sandboxed
    def test_a_link_to_the_plugins_own_folder_starts_one_sandbox_not_one_inside_another(self):
        taxes = self.tmp / "taxes"
        taxes.symlink_to(self.plugin)
        self.zone["privateFolders"] = [{"path": str(self.bank)}, {"path": str(taxes)}]

        done = self.python(f"""
load_plugin()
print(sum(line.split()[4] == {str(self.plugin)!r} for line in open("/proc/self/mountinfo")))""")

        self.assertEqual(done.stdout.strip(), "1")
        self.assertFalse(self.readable(self.bank / "secret.txt"))

    @sandboxed
    def test_a_link_into_proc_is_left_out_saying_so_and_starts_one_sandbox(self):
        taxes = self.tmp / "taxes"
        taxes.symlink_to("/proc/self/task")
        self.zone["privateFolders"] = [{"path": str(self.bank)}, {"path": str(taxes)}]

        done = self.python(f"""
import sys
load_plugin()
if sys.platform == "linux":
    print(sum(line.split()[4] == {str(self.plugin)!r} for line in open("/proc/self/mountinfo")))""")

        self.assertIn(f"{UNPROTECTED}: /proc/", done.stderr)
        self.assertIn("is under /proc", done.stderr)
        if sys.platform == "linux":
            self.assertEqual(done.stdout.strip(), "1")
        self.assertFalse(self.readable(self.bank / "secret.txt"))

    @sandboxed
    def test_a_link_to_what_hermes_starts_from_leaves_hermes_started_around_the_other_folders(self):
        venv, source = self.hermes_as_it_lives()
        python = venv / "bin" / "python"
        hermes = source / "hermes"
        real_python = os.path.realpath(sys.executable)
        (source / "bank").mkdir()
        (venv / "bank").mkdir()
        # As pipx and uv tools leave them, and a directory reached through a link of its own.
        entry, interpreter, middle, through = (self.tmp / name for name in ("localbin", "interpreter", "middle", "through"))
        for folder in (entry, interpreter, middle):
            folder.mkdir()
        (entry / "hermes").symlink_to(hermes)
        (entry / "chained").symlink_to(middle / "hermes")
        (middle / "hermes").symlink_to(hermes)
        (entry / "upward").symlink_to("../middle/hermes")
        (interpreter / "python").symlink_to(real_python)
        through.symlink_to(entry)
        taxes = self.tmp / "taxes"
        for name, target, run in (
                ("the interpreter's directory", venv / "bin", (python, hermes)), ("the venv", venv, (python, hermes)),
                ("the venv's lib", venv / "lib", (python, hermes)), ("a folder inside the venv", venv / "bank", (python, hermes)),
                ("Hermes's source", source, (python, hermes)), ("the package", source / "hermes_cli", (python, hermes)),
                ("the source's tools", source / "tools", (python, hermes)), ("a folder inside the source", source / "bank", (python, hermes)),
                ("a linked entry script's directory", entry, (python, entry / "hermes")),
                ("the directory between two links", middle, (python, entry / "chained")),
                ("the directory a relative link climbs to", middle, (python, entry / "upward")),
                ("an entry script's directory, reached through a link", entry, (python, through / "hermes")),
                # A framework build on macOS re-execs its real binary, so `sys.executable` does not keep the link.
                *([("a linked interpreter's directory", interpreter, (interpreter / "python", hermes))] if sys.platform == "linux" else [])):
            with self.subTest(name):
                taxes.unlink(missing_ok=True)
                taxes.symlink_to(target)
                self.zone["privateFolders"] = [{"path": str(self.bank)}, {"path": str(taxes)}]

                done = self.start_as(*run, READ_THE_SECRETS.format(paths=[str(self.bank / "secret.txt"), str(self.data_dir / "secret.txt")]))

                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertEqual(done.stdout.split(), ["refused", "refused"])
                self.assertIn(f"{UNPROTECTED}: {target}", done.stderr)

    @linux
    @sandboxed
    def test_a_link_to_a_folder_bubblewrap_cannot_cover_leaves_every_other_folder_sandboxed_and_says_which(self):
        # Under a tmpfs on `/usr` the check's own `/bin/true` is gone; a path this long bubblewrap cannot mount.
        deep = (str(self.tmp) + ("/" + "x" * 200) * 21)[:4090]
        os.makedirs(deep)
        taxes = self.tmp / "taxes"
        for target, said in (("/usr", "/usr"), (deep, f"bubblewrap could not mount {deep}")):
            with self.subTest(target[:20]):
                taxes.symlink_to(target)
                self.zone["privateFolders"] = [{"path": str(self.bank)}, {"path": str(taxes)}]

                done = self.python(f"""
load_plugin()
for path in {[str(self.bank / "secret.txt"), str(self.data_dir / "secret.txt")]!r}:
    try:
        open(path).read()
        print("read")
    except OSError:
        print("refused")""")

                self.assertEqual(done.stdout.split(), ["refused", "refused"])
                self.assertIn(UNPROTECTED, done.stderr)
                self.assertIn(said, done.stderr)
                taxes.unlink()

    @linux
    @sandboxed
    @unittest.skipIf(hasattr(os, "getuid") and os.getuid() == 0, "root reads through a 0o000 folder")
    def test_a_link_at_a_private_folder_past_a_locked_folder_hides_no_more_than_that_folder(self):
        lock = self.tmp / "lock"
        (lock / "x").mkdir(parents=True)
        taxes = self.tmp / "taxes"
        taxes.symlink_to(lock / "x")
        beside = self.tmp / "beside.txt"
        beside.write_text("beside")
        self.zone["privateFolders"] = [{"path": str(self.bank)}, {"path": str(taxes)}]
        lock.chmod(0o000)
        self.addCleanup(lock.chmod, 0o755)

        done = self.python(f"""
load_plugin()
print(open({str(beside)!r}).read())""")

        self.assertEqual(done.stdout.strip(), "beside")
        self.assertNotIn(UNPROTECTED, done.stderr)

    @linux
    def test_where_bubblewrap_cannot_sandbox_it_does_not_re_exec_and_warns_naming_the_fix(self):
        # A `wisp` whose check says what the real one says where AppArmor blocks bubblewrap's user namespaces.
        fake = self.tmp / "bin"
        fake.mkdir()
        (fake / "wisp").write_text("#!/bin/sh\n"
                                   "[ \"$1 $2\" = 'sandbox-exec --check' ] && echo 'AppArmor blocks it: apparmor_parser' && exit 1\n"
                                   "echo re-exec >&2; exit 9\n")
        (fake / "wisp").chmod(0o755)
        (self.plugin / "pin.json").write_text(json.dumps({
            "url": _closed_url(), "wisp": str(fake / "wisp"), "dataDir": str(self.data_dir),
            "deskRoot": str(self.data_dir / "desks"), "privateFolders": [{"path": str(self.bank)}]}))
        if not os.path.exists("/usr/bin/bwrap"):
            self.skipTest("no bubblewrap: the plugin never asks wisp")

        done = self.python(f"load_plugin(); print(open({str(self.bank / 'secret.txt')!r}).read())")

        self.assertEqual(done.stdout.strip(), "secret")
        self.assertIn(UNPROTECTED, done.stderr)
        self.assertIn("apparmor_parser", done.stderr)
        self.assertNotIn("re-exec", done.stderr)

    def _pinned_wisp(self, script):
        """Pins a `wisp` that runs `script`, its arguments in `$@`; bubblewrap must be there for the plugin to ask it."""
        if not os.path.exists("/usr/bin/bwrap"):
            self.skipTest("no bubblewrap: the plugin never asks wisp")
        fake = self.tmp / "bin"
        fake.mkdir()
        (fake / "wisp").write_text(f"#!/bin/sh\n{script}\n")
        (fake / "wisp").chmod(0o755)
        (self.plugin / "pin.json").write_text(json.dumps({
            "url": _closed_url(), "wisp": str(fake / "wisp"), "dataDir": str(self.data_dir),
            "deskRoot": str(self.data_dir / "desks"), "privateFolders": [{"path": str(self.bank)}]}))

    def _carries_on_and_says_so(self, reason=""):
        """Hermes reads on, unsandboxed, with the line on stderr and in its log, in a Hermes logging as the real one does."""
        log = self.tmp / "hermes.log"
        done = self.python(f"""
import logging
logging.getLogger().addHandler(logging.FileHandler({str(log)!r}))
load_plugin()
print(open({str(self.bank / 'secret.txt')!r}).read())""")
        self.assertEqual(done.stdout.strip(), "secret")
        for said in (done.stderr, log.read_text()):
            self.assertIn(UNPROTECTED, said)
            self.assertIn(reason, said)

    @linux
    def test_a_wisp_killed_at_its_check_leaves_hermes_running_and_says_so(self):
        self._pinned_wisp("kill -9 $$")

        self._carries_on_and_says_so("--check failed")

    @linux
    def test_a_wisp_killed_printing_the_arguments_leaves_hermes_running_and_says_so(self):
        self._pinned_wisp('[ "$2" = --check ] && exit 0; kill -9 $$')

        self._carries_on_and_says_so("wisp sandbox-exec failed")

    @linux
    def test_a_wisp_refusing_a_folder_as_it_prints_the_arguments_says_which(self):
        # Its parent locked after the check.
        self._pinned_wisp('[ "$2" = --check ] && exit 0; echo "cannot check /some/bank" >&2; exit 1')

        self._carries_on_and_says_so("cannot check /some/bank")

    @linux
    def test_a_bubblewrap_that_fails_at_the_start_leaves_hermes_running_and_says_so(self):
        self._pinned_wisp('[ "$2" = --check ] && exit 0; printf -- --no-such-flag')

        self._carries_on_and_says_so("wisp sandbox-exec failed")

    @linux
    def test_a_failed_start_is_said_even_with_every_zone_folder_empty(self):
        for folder in (self.data_dir / "desks", self.data_dir, self.bank):
            for entry in folder.iterdir():
                entry.unlink() if entry.is_file() else None
        self._pinned_wisp("kill -9 $$")

        self.assertIn(UNPROTECTED, self.python("load_plugin()").stderr)

    @linux
    @sandboxed
    def test_each_folder_hermes_was_left_able_to_read_is_named(self):
        # Too long once bubblewrap prefixes its new root.
        deep = [(str(self.tmp) + f"/{n}" + ("/" + "x" * 200) * 21)[:4090] for n in (1, 2)]
        for folder in deep:
            os.makedirs(folder)
            (Path(folder) / "s").write_text("secret")
        self.zone["privateFolders"] = [{"path": folder} for folder in deep]

        stderr = self.python("load_plugin()").stderr

        self.assertIn(f"Hermes can read {deep[0]}, {deep[1]}", stderr)

    @linux
    @sandboxed
    def test_a_folder_bubblewrap_cannot_mount_is_left_out_saying_so_and_the_others_stay_sandboxed(self):
        # Too long once bubblewrap prefixes its new root.
        deep = str(self.tmp) + ("/" + "x" * 200) * 21
        deep = deep[:4090]
        os.makedirs(deep)
        self.zone["privateFolders"] = [{"path": deep}, {"path": str(self.bank)}]

        done = self.python(f"""
load_plugin()
try:
    open({str(self.bank / 'secret.txt')!r}).read()
    print("read")
except OSError:
    print("refused")""")

        self.assertEqual(done.stdout.strip(), "refused")
        self.assertIn(UNPROTECTED, done.stderr)
        self.assertIn(f"bubblewrap could not mount {deep}", done.stderr)

    @linux
    @sandboxed
    def test_a_secret_file_bubblewrap_cannot_mount_is_left_out_saying_so_and_the_others_stay_sandboxed(self):
        deep = str(self.tmp) + ("/" + "x" * 200) * 21
        deep = deep[:4080]
        os.makedirs(deep)
        key = os.path.join(deep, "master.key")
        Path(key).write_text("root key")
        self.zone["secretFiles"] = [key]

        done = self.python(f"""
load_plugin()
try:
    open({str(self.bank / 'secret.txt')!r}).read()
    print("read")
except OSError:
    print("refused")""")

        self.assertEqual(done.stdout.strip(), "refused")
        self.assertIn(UNPROTECTED, done.stderr)
        self.assertIn(f"bubblewrap could not mount {key}", done.stderr)

    @linux
    @sandboxed
    def test_an_fd_its_parent_passed_down_reaches_the_sandboxed_hermes(self):
        # As `hermes update` hands its checkout lock to its children: lost, the child takes the lock for another update's.
        read, write = os.pipe()
        self.addCleanup(os.close, read)
        code = f"""
import os
load_plugin()
os.write({write}, b"held")"""
        done = subprocess.run([sys.executable, str(FAKE / "hermes"), "python", code], env=self.env(),
                              pass_fds=[write], capture_output=True, text=True)
        os.close(write)

        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(os.read(read, 16), b"held")

    @linux
    @sandboxed
    def test_a_directory_fd_from_the_launcher_is_not_open_inside_and_a_file_fd_is(self):
        # An fd on a Private Folder's parent would walk past its tmpfs.
        parent = os.open(self.tmp, os.O_RDONLY)
        self.addCleanup(os.close, parent)
        secret = os.open(self.bank / "secret.txt", os.O_RDONLY)
        self.addCleanup(os.close, secret)
        code = f"""
import os
load_plugin()
print(os.path.exists("/proc/self/fd/{parent}/bank/secret.txt"))
print(os.read({secret}, 16).decode())"""
        done = subprocess.run([sys.executable, str(FAKE / "hermes"), "python", code], env=self.env(),
                              pass_fds=[parent, secret], capture_output=True, text=True)

        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout.split(), ["False", "secret"])

    @linux
    @sandboxed
    def test_it_starts_through_arguments_wisp_printed_with_no_path_for_bubblewraps_info(self):
        # The real `wisp`, logging how it is asked.
        fake = self.tmp / "bin"
        fake.mkdir()
        log = self.tmp / "wisp.log"
        (fake / "wisp").write_text(f'#!/bin/sh\necho "$*" >> {log}\nexec {WISP / "wisp"} "$@"\n')
        (fake / "wisp").chmod(0o755)
        (self.plugin / "pin.json").write_text(json.dumps({
            "url": _closed_url(), "wisp": str(fake / "wisp"), "dataDir": str(self.data_dir),
            "deskRoot": str(self.data_dir / "desks"), "privateFolders": [{"path": str(self.bank)}]}))
        before = set(Path(tempfile.gettempdir()).glob("wisp-sandbox-*"))

        self.assertFalse(self.readable(self.bank / "secret.txt"))

        # Those two only; the last argument of `--print-args` is `self.readable`'s code, newlines and all.
        asked = [line for line in log.read_text().splitlines() if line.startswith("sandbox-exec")]
        self.assertEqual([line.split()[:2] for line in asked], [["sandbox-exec", "--check"], ["sandbox-exec", "--print-args"]])
        self.assertIn(f"--deny {self.bank}", asked[0])
        self.assertIn(f"--read-only {self.plugin}", asked[0])
        self.assertEqual(set(Path(tempfile.gettempdir()).glob("wisp-sandbox-*")), before)

    @linux
    def test_without_bubblewrap_it_warns_naming_the_install(self):
        if os.path.exists("/usr/bin/bwrap"):
            self.skipTest("bubblewrap is installed")

        self.assertIn("sudo apt install bubblewrap", self.python("load_plugin()").stderr)

    @sandboxed
    def test_a_private_folder_holding_hermess_home_is_left_out_with_a_warning(self):
        self.zone["privateFolders"] = [{"path": str(self.tmp)}]

        done = self.python("""
from hermes_cli.config import get_config_path
load_plugin()
print(get_config_path().read_text())""")

        self.assertIn("plugins", done.stdout)
        self.assertIn(f"{self.tmp} holds Hermes's home", done.stderr)



def _cmdline(pid):
    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return b""


def _kill(pid):
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _closed_url():
    """A loopback `/mcp` nothing listens on."""
    closed = socket.create_server(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()
    return f"http://127.0.0.1:{port}/mcp"


@linux
@sandboxed
@unittest.skipUnless(os.path.isdir("/run/systemd/system") and hasattr(os, "getuid") and os.getuid() == 0
                     and shutil.which("systemd-run"), "needs root and a running systemd")
class Systemd(HermesHome):
    """A fake gateway as Hermes's unit runs its own: `Type=notify`, `NotifyAccess=main`, a watchdog."""

    GATEWAY = """
import os, signal, socket, sys, threading, time
load_plugin()
target = os.environ["NOTIFY_SOCKET"]
address = "\\0" + target[1:] if target.startswith("@") else target
notify = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
def pings():
    while True:
        notify.sendto(b"WATCHDOG=1", address)
        time.sleep(1)
reloaded = {reloaded!r}
signal.signal(signal.SIGUSR1, lambda *_: open(reloaded, "w").close())
signal.signal(signal.SIGTERM, lambda *_: os._exit(42))
threading.Thread(target=pings, daemon=True).start()
notify.sendto(b"READY=1", address)
while True:
    signal.pause()
"""

    def test_the_unit_sees_ready_watchdog_reload_and_the_exit_code_of_hermes(self):
        unit = f"wisp-hermes-{os.getpid()}.service"
        reloaded = self.tmp / "reloaded"
        env = self.env()
        argv = ["systemd-run", "--wait", f"--unit={unit}", "-p", "Type=notify", "-p", "NotifyAccess=main",
                "-p", "WatchdogSec=10", "-p", "ExecReload=/bin/kill -USR1 $MAINPID",
                f"--setenv=HERMES_HOME={env['HERMES_HOME']}", f"--setenv=PATH={env['PATH']}",
                sys.executable, str(FAKE / "hermes"), "python", self.GATEWAY.format(reloaded=str(reloaded))]
        run = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(run.wait)
        self.addCleanup(subprocess.run, ["systemctl", "kill", "-s", "KILL", unit], capture_output=True)

        def show(prop):
            return subprocess.run(["systemctl", "show", "-p", prop, "--value", unit], capture_output=True, text=True).stdout.strip()

        for _ in range(600):
            if show("ActiveState") == "active":
                break
            time.sleep(0.1)
        self.assertEqual(show("ActiveState"), "active")
        main_pid = int(show("MainPID"))
        self.assertIn(b"supervise.py", Path(f"/proc/{main_pid}/cmdline").read_bytes())

        subprocess.run(["systemctl", "reload", unit], check=True)
        for _ in range(100):
            if reloaded.exists():
                break
            time.sleep(0.1)
        self.assertTrue(reloaded.exists())

        subprocess.run(["systemctl", "stop", "--no-block", unit], check=True)
        self.assertEqual(run.wait(timeout=60), 42)


    def gateway_unit(self, restart, wrap=lambda *command: command):
        """The fake `gateway run` started in a new unit."""
        unit = f"wisp-hermes-gw-{os.urandom(4).hex()}.service"
        env = self.env()
        subprocess.run(["systemd-run", f"--unit={unit}", "-p", f"Restart={restart}", f"--setenv=HERMES_HOME={env['HERMES_HOME']}",
                        f"--setenv=PATH={env['PATH']}", *wrap(sys.executable, str(FAKE / "hermes"), "gateway", "run")],
                       check=True, capture_output=True)
        self.addCleanup(subprocess.run, ["systemctl", "stop", unit], capture_output=True)
        return unit

    def gateway_says(self, unit):
        """What that gateway was started with: the plugin's own start, then the sandboxed one."""
        log = self.home / "argv.log"
        said = []
        for _ in range(600):
            said = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
            if len(said) >= 2:
                break
            time.sleep(0.1)
        return said[:2]

    def test_a_gateway_its_unit_respawns_declares_its_manager(self):
        self.assertEqual(self.gateway_says(self.gateway_unit("always")), [["gateway", "run"], ["gateway", "run", "--external-supervisor"]])

    def test_a_gateway_hermes_relaunched_through_its_bootstrap_declares_its_manager_on_its_command_line(self):
        # As `hermes_cli/venv_sync.py`: `sys.argv` set in `-c` code, so no `gateway run` in the command line. `hermes
        # update` reads the flag there, whatever the code then makes of it.
        def relaunched(python, hermes, *argv):
            return [python, "-c", f"import runpy, sys; sys.path.insert(0, {str(FAKE)!r}); sys.argv = {[hermes, *argv]!r}; "
                                  f"runpy.run_path({hermes!r}, run_name='__main__')"]

        unit = self.gateway_unit("always", relaunched)
        self.gateway_says(unit)
        for _ in range(600):
            main = _cmdline(subprocess.run(["systemctl", "show", "-p", "MainPID", "--value", unit], capture_output=True, text=True).stdout.strip())
            if b"supervise.py" in main:
                break
            time.sleep(0.1)
        child = main.split(b"\0")[-3].decode()

        self.assertIn(b"--external-supervisor", _cmdline(child).split(b"\0"))

    def test_a_gateway_of_a_unit_that_does_not_restart_does_not(self):
        self.assertEqual(self.gateway_says(self.gateway_unit("no")), [["gateway", "run"], ["gateway", "run"]])

    def test_a_gateway_two_shells_below_the_units_main_process_does_not(self):
        # `; :` keeps each shell from exec'ing.
        def under_two_shells(*command):
            return ["sh", "-c", f"sh -c '{' '.join(command)}; :'; :"]

        self.assertEqual(self.gateway_says(self.gateway_unit("always", under_two_shells)), [["gateway", "run"], ["gateway", "run"]])

    def test_a_gateway_that_is_a_child_of_the_units_main_process_does_not(self):
        # As under a tmux server that is the unit: on its exit tmux exits 0, and `on-failure` does not respawn.
        def under_a_shell(*command):
            return ["sh", "-c", f"{' '.join(command)}; :"]

        self.assertEqual(self.gateway_says(self.gateway_unit("always", under_a_shell)), [["gateway", "run"], ["gateway", "run"]])

    def test_a_gateway_of_an_on_failure_unit_declares_its_manager(self):
        self.assertEqual(self.gateway_says(self.gateway_unit("on-failure")), [["gateway", "run"], ["gateway", "run", "--external-supervisor"]])

    def test_a_gateway_of_an_on_abnormal_unit_does_not(self):
        # A drained gateway's clean exit is not abnormal: nothing would bring it back.
        self.assertEqual(self.gateway_says(self.gateway_unit("on-abnormal")), [["gateway", "run"], ["gateway", "run"]])


class Pin(HermesHome):
    """What `wisp integrate hermes` pinned beside the plugin, against a `config.yaml` Hermes's model
    repointed."""

    def setUp(self):
        super().setUp()
        (self.home / ".env").write_text("WISP_CREDENTIAL_TOKEN=wisp_hermes_s3cr3t\n")
        self.repoint(_closed_url())
        self.zone = None
        self.pin = {"url": _closed_url(), "dataDir": str(self.data_dir), "deskRoot": str(self.data_dir / "desks"),
                    "privateFolders": [{"path": str(self.bank)}]}
        self.fault_env = {}

    def env(self):
        return {**super().env(), **self.fault_env}

    def hermes(self, *argv, **kwargs):
        if self.pin is not None:
            (self.plugin / "pin.json").write_text(json.dumps(self.pin))
        return super().hermes(*argv, **kwargs)

    def endpoint(self, zone):
        """A fake Wisp MCP endpoint whose `wisp_zone` answers `zone`; its URL."""

        class Mcp(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                message = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if "id" not in message:
                    self.send_response(202)
                    self.end_headers()
                    return
                result = ({"content": [], "structuredContent": zone} if message["method"] == "tools/call"
                          else {"protocolVersion": "2025-06-18", "capabilities": {}, "serverInfo": {"name": "wisp"}})
                body = json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Mcp)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_address[1]}/mcp"

    def repoint(self, url):
        (self.home / "config.yaml").write_text(json.dumps(
            {"plugins": {"enabled": ["wisp"]}, "mcp_servers": {"wisp": {"url": url}}}))

    def blocked(self, path):
        done = self.hermes("pre-tool-call", stdin=json.dumps([["read_file", {"path": str(path)}]]))
        return json.loads(done.stdout)[0] is not None

    @sandboxed
    def test_a_repointed_url_answering_no_zone_still_leaves_the_pinned_folders_sandboxed_and_refused(self):
        self.repoint(self.endpoint({"dataDir": str(self.tmp / "nowhere"), "deskRoot": str(self.tmp / "nowhere"),
                                    "privateFolders": [], "services": []}))

        self.assertFalse(self.readable(self.bank / "secret.txt"))
        self.assertFalse(self.readable(self.data_dir / "secret.txt"))
        self.assertTrue(self.blocked(self.bank / "secret.txt"))

    @sandboxed
    def test_the_pinned_secret_files_and_those_an_answer_adds_are_sandboxed_and_refused(self):
        pinned, added = self.tmp / "master.key", self.tmp / "serve.json"
        for file in (pinned, added):
            file.write_text("secret")
        self.pin["secretFiles"] = [str(pinned)]
        self.pin["url"] = self.endpoint({"dataDir": str(self.data_dir), "deskRoot": str(self.data_dir / "desks"),
                                         "privateFolders": [], "secretFiles": [str(added)], "services": []})

        for file in (pinned, added):
            self.assertFalse(self.readable(file))
            self.assertTrue(self.blocked(file))

    @sandboxed
    def test_an_answer_widens_the_pinned_zone_and_never_narrows_it(self):
        added = self.tmp / "added"
        added.mkdir()
        (added / "secret.txt").write_text("secret")
        self.pin["url"] = self.endpoint({"dataDir": str(self.data_dir), "deskRoot": str(self.data_dir / "desks"),
                                         "privateFolders": [{"path": str(added)}], "services": []})

        self.assertFalse(self.readable(added / "secret.txt"))
        self.assertFalse(self.readable(self.bank / "secret.txt"))
        self.assertTrue(self.blocked(added / "secret.txt"))
        self.assertTrue(self.blocked(self.bank / "secret.txt"))

    def test_the_pinned_rule_names_the_answers_connectors_plainly(self):
        self.pin["url"] = self.endpoint({"dataDir": str(self.data_dir), "deskRoot": str(self.data_dir / "desks"),
                                         "privateFolders": [], "services": ["my-crm"], "connectors": [
                                             {"name": "my-crm", "displayName": "Acme CRM", "status": "connected"}]})

        rule = json.loads(self.hermes("sections").stdout)["wisp-routing"]

        self.assertIn("Wisp's services: Acme CRM (my-crm);", rule)

    def malformed_zones(self):
        """What an answer or a cached zone can hold that no folder can be: (what, the zone)."""
        zone = {"dataDir": str(self.data_dir), "deskRoot": str(self.data_dir / "desks"), "services": []}
        return [
            *((name, {**zone, "privateFolders": [{"path": str(self.tmp / "added")}, {"path": path}]}) for name, path in (
                ("a list", []), ("a number", 5), ("a relative path", "bank"), ("an empty path", ""),
                ("a NUL byte", "/tmp/a\0b"), ("a lone surrogate", "/tmp/\ud800"))),
            ("a NUL byte in dataDir", {**zone, "dataDir": "/tmp/a\0b", "privateFolders": []}),
            ("a relative deskRoot", {**zone, "deskRoot": "desks", "privateFolders": []}),
        ]

    def assert_only_the_pinned_zone_holds(self):
        done = self.python(f"""
load_plugin()
for path in {[str(self.bank / "secret.txt"), str(self.data_dir / "secret.txt")]!r}:
    try:
        open(path).read()
        print("read")
    except OSError:
        print("refused")""")
        self.assertEqual(done.stdout.split(), ["refused", "refused"])
        self.assertNotIn(UNPROTECTED, done.stderr)

    @sandboxed
    def test_a_malformed_answer_leaves_the_pinned_zone_standing_alone_and_uncached(self):
        for name, zone in self.malformed_zones():
            with self.subTest(name):
                self.pin["url"] = self.endpoint(zone)

                self.assert_only_the_pinned_zone_holds()
                self.assertFalse((self.plugin / "zone.json").exists())

    @sandboxed
    def test_a_malformed_cached_zone_leaves_the_pinned_zone_standing_alone(self):
        for name, zone in self.malformed_zones():
            with self.subTest(name):
                (self.plugin / "zone.json").write_text(json.dumps(zone))

                self.assert_only_the_pinned_zone_holds()

    def raw_endpoint(self, reply):
        """A port that answers every request with the bytes of `reply`, HTTP or not, and closes; its URL."""

        class Raw(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                self.wfile.write(reply)
                self.close_connection = True

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Raw)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_address[1]}/mcp"

    def valid_zone(self, folders):
        return {"dataDir": str(self.data_dir), "deskRoot": str(self.data_dir / "desks"), "services": [],
                "privateFolders": [{"path": str(folder)} for folder in folders]}

    def real_folders(self, count, depth=0):
        """`count` real folders, each `depth` levels below a parent of its own. Under a short root: 4600 of them
        stay within `ZONE_BYTES`, in the temp directory macOS names at length they would not."""
        root = Path(os.path.realpath(tempfile.mkdtemp(prefix="w", dir="/tmp")))
        self.addCleanup(shutil.rmtree, root)
        folders = [root / str(n) / "/".join("d" * depth) for n in range(count)]
        for folder in folders:
            folder.mkdir(parents=True)
        return folders

    def zones_past_a_limit(self):
        """Valid zones past `ZONE_FOLDERS`, past `ZONE_BYTES`, and within both but past bubblewrap's 9000 arguments."""
        return [
            ("501 folders", self.valid_zone(f"{self.tmp}/many/{n}" for n in range(501))),
            ("4600 real folders", self.valid_zone(self.real_folders(4600))),
            ("past ZONE_BYTES", self.valid_zone(f"{self.tmp}/long/{n}-{'x' * 400}" for n in range(400))),
            ("past bubblewrap's arguments", self.valid_zone(self.real_folders(400, 10))),
            ("past what sandbox_init reads", self.valid_zone(["/x" + "y" * 100000])),
            ("a path too deep to recurse through", self.valid_zone(["/a" * 60000])),
        ]

    def junk_zones(self):
        """Answers from a seeded `random`: junk JSON, and zones of junk paths."""
        rng = random.Random(49)

        def path():
            return rng.choice(["", "bank", "/x/\udcff", "/\ud800", "/a\0b", 5, None, [], {"path": "/x"},
                               "/" + "".join(rng.choices("ab\n\"\\ ", k=rng.randrange(9)))])

        def junk(depth=0):
            kinds = [None, True, rng.randrange(-9, 9), rng.random(), "x" * rng.randrange(9), path()]
            if depth < 3:
                kinds += [[junk(depth + 1) for _ in range(rng.randrange(4))],
                          {rng.choice(["dataDir", "deskRoot", "privateFolders", "path", "x"]): junk(depth + 1) for _ in range(rng.randrange(4))}]
            return rng.choice(kinds)

        return [
            *((f"junk JSON {n}", junk()) for n in range(8)),
            *((f"junk paths {n}", {"dataDir": path(), "deskRoot": path(), "services": junk(),
                                   "privateFolders": [{"path": path()} for _ in range(rng.randrange(4))]}) for n in range(8)),
        ]

    @sandboxed
    def test_nothing_an_answer_a_cache_or_the_config_says_opens_a_pinned_folder(self):
        def http_body(body):
            return b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body)

        zones = [("null", None), ("a surrogate in a path", self.valid_zone(["/x/\udcff"])), *self.zones_past_a_limit(), *self.junk_zones()]
        faults = [
            *((f"the endpoint says {name}", {"url": self.raw_endpoint(reply)}) for name, reply in (
                ("[]", http_body(b"[]")), ("null", http_body(b"null")), ('{"result":[]}', http_body(b'{"result":[]}')),
                ("[ x 200000", http_body(b"[" * 200000)), ("a status line of garbage", b"garbage\r\n\r\n"), ("nothing", b""),
                ("a short body", http_body(b"{" * 50)[:-40]), ("no HTTP", b"SSH-2.0-OpenSSH_9.6\r\n"))),
            *((f"the endpoint answers {name}", {"url": self.endpoint(zone)}) for name, zone in zones),
            *((f"the cache holds {name}", {"cache": json.dumps(zone).encode()}) for name, zone in zones),
            *((f"the cache holds {name}", {"cache": held}) for name, held in (
                ("nothing", b""), ("half a document", b"{"), ("[ x 200000", b"[" * 200000), ("bytes", b"\xff\xfe"))),
            ("config.yaml's mcp_servers is a word", {"config": {"mcp_servers": "x"}}),
            ("read_raw_config raises", {"env": {"FAKE_HERMES_RAW_CONFIG_RAISES": "1"}}),
            ("get_env_value raises", {"env": {"FAKE_HERMES_ENV_VALUE_RAISES": "1"}}),
        ]
        closed = self.pin["url"]
        for name, fault in faults:
            with self.subTest(name):
                self.pin["url"] = fault.get("url", closed)
                (self.plugin / "zone.json").unlink(missing_ok=True)
                if "cache" in fault:
                    (self.plugin / "zone.json").write_bytes(fault["cache"])
                (self.home / "config.yaml").write_text(json.dumps({"plugins": {"enabled": ["wisp"]}, **fault.get("config", {})}))
                self.fault_env = fault.get("env", {})

                self.assertFalse(self.readable(self.bank / "secret.txt"))

    @sandboxed
    def test_an_answer_of_null_is_no_answer_so_a_folder_added_earlier_stays_closed_on_the_next_start_too(self):
        added = self.tmp / "added"
        added.mkdir()
        (added / "secret.txt").write_text("secret")
        cached = json.dumps(self.valid_zone([added]))
        (self.plugin / "zone.json").write_text(cached)
        closed = self.pin["url"]

        for url in (self.endpoint(None), closed):
            with self.subTest(url):
                self.pin["url"] = url

                self.assertFalse(self.readable(added / "secret.txt"))
                self.assertEqual((self.plugin / "zone.json").read_text(), cached)

    @sandboxed
    def test_a_list_only_the_sandbox_refuses_leaves_the_pinned_folders_closed_in_one_sandbox_and_says_the_added_ones_are_not(self):
        # Past bubblewrap's 9000 arguments on Linux, past the longest string `sandbox_init` reads on macOS.
        added = self.real_folders(400, 10) if sys.platform == "linux" else ["/x" + "y" * 100000]
        self.pin["url"] = self.endpoint(self.valid_zone(added))

        done = self.python(f"""
import sys
load_plugin()
try:
    open({str(self.bank / "secret.txt")!r}).read()
    print("read")
except OSError:
    print("refused")
if sys.platform == "linux":
    print(sum(line.split()[4] == {str(self.plugin)!r} for line in open("/proc/self/mountinfo")))""")

        self.assertEqual(done.stdout.split()[0], "refused")
        if sys.platform == "linux":
            self.assertEqual(done.stdout.split()[1], "1")
        self.assertIn(f"{UNPROTECTED}: of the folders added since wisp integrate hermes, these are not sandboxed", done.stderr)
        self.assertIn(str(added[0]), done.stderr)

    @linux
    @sandboxed
    def test_one_added_folder_left_out_is_named_and_the_added_one_in_the_sandbox_is_not(self):
        # Too long once bubblewrap prefixes its new root.
        deep = (str(self.tmp) + ("/" + "x" * 200) * 21)[:4090]
        os.makedirs(deep)
        link = self.tmp / "taxes"
        link.symlink_to(deep)
        added = self.tmp / "added"
        added.mkdir()
        (self.plugin / "zone.json").write_text(json.dumps(self.valid_zone([added, link])))

        stderr = self.python("load_plugin()").stderr

        self.assertIn(f"these are not sandboxed: {deep}", stderr)
        self.assertNotIn(str(added), stderr)

    @linux
    @sandboxed
    def test_a_start_file_renamed_during_every_check_decides_nothing(self):
        source = self.tmp / "source"
        shutil.copytree(FAKE, source, ignore=shutil.ignore_patterns("__pycache__"))
        start_file = source / "hermes_cli" / "__init__.py"
        fake = self.tmp / "bin"
        fake.mkdir()
        (fake / "wisp").write_text(f"""#!/bin/sh
[ "$2" = --check ] || exec {WISP / "wisp"} "$@"
mv {start_file} {start_file}.away
{WISP / "wisp"} "$@"
said=$?
mv {start_file}.away {start_file}
exit $said
""")
        (fake / "wisp").chmod(0o755)
        self.pin["wisp"] = str(fake / "wisp")
        (self.plugin / "pin.json").write_text(json.dumps(self.pin))

        said = [subprocess.run([sys.executable, str(source / "hermes"), "python", f"""
load_plugin()
try:
    open({str(self.bank / "secret.txt")!r}).read()
    print("read")
except OSError:
    print("refused")"""], env=self.env(), capture_output=True, text=True).stdout.strip() for _ in range(10)]

        self.assertEqual(said, ["refused"] * 10)

    @sandboxed
    def test_a_real_pinned_folder_inside_what_hermes_starts_from_stays_closed(self):
        venv, source = self.hermes_as_it_lives()
        for name, folder in (("the venv", venv / "bank"), ("the source", source / "bank")):
            with self.subTest(name):
                folder.mkdir()
                (folder / "secret.txt").write_text("secret")
                self.pin["privateFolders"] = [{"path": str(folder)}]
                (self.plugin / "pin.json").write_text(json.dumps(self.pin))

                done = self.start_as(venv / "bin" / "python", source / "hermes", READ_THE_SECRETS.format(paths=[str(folder / "secret.txt")]))

                self.assertEqual(done.stdout.split(), ["refused"], done.stderr)

    @sandboxed
    def test_a_real_pinned_folder_holding_what_hermes_starts_from_is_left_out_saying_so(self):
        venv, source = self.hermes_as_it_lives()
        for name, folder in (("the venv", venv), ("the source", source), *([("/usr", Path("/usr"))] if sys.platform == "linux" else [])):
            with self.subTest(name):
                self.pin["privateFolders"] = [{"path": str(self.bank)}, {"path": str(folder)}]
                (self.plugin / "pin.json").write_text(json.dumps(self.pin))

                done = self.start_as(venv / "bin" / "python", source / "hermes", READ_THE_SECRETS.format(paths=[str(self.bank / "secret.txt")]))

                self.assertEqual(done.stdout.split(), ["refused"], done.stderr)
                self.assertIn(f"{UNPROTECTED}: {folder}", done.stderr)

    @sandboxed
    def test_a_pinned_folder_holding_a_folder_hermes_imports_from_is_left_out_saying_so(self):
        # As a Hermes whose interpreter lies in one place and its packages, on `sys.path` only, in another.
        environment = self.tmp / "environment"
        packages = environment / "lib" / "site-packages"
        packages.mkdir(parents=True)
        (packages / "imported_late.py").write_text("")
        self.fault_env["PYTHONPATH"] = str(packages)
        self.pin["privateFolders"] = [{"path": str(self.bank)}, {"path": str(environment)}]

        done = self.python(READ_THE_SECRETS.format(paths=[str(self.bank / "secret.txt")]) + "\nimport imported_late\nprint('imported')")

        self.assertEqual(done.stdout.split(), ["refused", "imported"], done.stderr)
        self.assertIn(f"{UNPROTECTED}: {environment} would take {packages}", done.stderr)

    def test_with_no_pin_an_answer_is_cached_as_it_came(self):
        # A second machine's: its Wisp may name folders in another machine's terms.
        self.pin = None
        zone = {"dataDir": "C:\\wisp", "deskRoot": "C:\\wisp\\desks", "privateFolders": [], "services": []}
        self.repoint(self.endpoint(zone))

        self.python("load_plugin()")

        self.assertEqual(json.loads((self.plugin / "zone.json").read_text()), zone)

    @posix
    def test_a_pinned_profile_that_comes_up_unsandboxed_warns(self):
        shutil.rmtree(self.data_dir)
        shutil.rmtree(self.bank)

        self.assertIn(UNPROTECTED, self.python("load_plugin()").stderr)

    @sandboxed
    def test_a_pinned_folder_missing_at_the_start_is_named_on_linux_where_no_tmpfs_covers_it(self):
        later = self.tmp / "later"
        self.pin["privateFolders"] = [{"path": str(self.bank)}, {"path": str(later)}]

        stderr = self.python("load_plugin()").stderr

        said = f"{later} is not there yet, so Hermes is not kept out of it once it appears; restart Hermes after it exists"
        if sys.platform == "linux":
            self.assertIn(said, stderr)
        else:
            self.assertNotIn(said, stderr)


    @linux
    @sandboxed
    def test_a_pinned_folder_a_model_planted_a_link_at_is_named_as_not_there_rather_than_unprotected(self):
        for name, folder, plant in _PLANTS:
            with self.subTest(name):
                at = self.tmp / folder
                self.pin["privateFolders"] = [{"path": str(self.bank)}, {"path": str(at)}]
                self.python(f"import os\nload_plugin()\n{plant(at)}")

                stderr = self.python("load_plugin()").stderr

                self.assertIn("is not there yet", stderr)
                self.assertNotIn(UNPROTECTED, stderr)

    @linux
    @sandboxed
    def test_a_folder_left_out_of_the_sandbox_does_not_silence_what_is_said_of_the_others(self):
        taxes = self.tmp / "taxes"
        taxes.symlink_to("/usr")
        later = self.tmp / "later"
        self.pin["privateFolders"] = [{"path": str(self.bank)}, {"path": str(taxes)}, {"path": str(later)}]

        stderr = self.python("load_plugin()").stderr

        self.assertIn(UNPROTECTED, stderr)
        self.assertIn(f"{later} is not there yet", stderr)

    @sandboxed
    def test_a_zone_folder_inside_another_is_not_called_missing(self):
        inner = self.bank / "desks"
        inner.mkdir()
        self.pin["deskRoot"] = str(inner)

        stderr = self.python("load_plugin()").stderr

        self.assertNotIn("is not there yet", stderr)


@posix
class ProbeFailures(unittest.TestCase):
    """`_reexec` against a `wisp` that fails a chosen number of times, keyed by its mode and the folders it was given
    (a toggled lock, a load that trips a timeout), and logs each run: no bubblewrap needed, so this runs on macOS too."""

    def setUp(self):
        spec = importlib.util.spec_from_file_location("wisp_sandbox_under_test", PLUGIN / "sandbox.py")
        self.sandbox = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.sandbox)
        self.tmp = Path(tempfile.mkdtemp(prefix="wisp-hermes-probes-"))
        self.addCleanup(shutil.rmtree, self.tmp)
        self.log = self.tmp / "log"
        self.log.touch()
        self.wisp = self.tmp / "wisp"
        self.wisp.write_text(f"""#!{sys.executable}
import json, os, sys
own = sys.argv[3:sys.argv.index("--")] if "--" in sys.argv else sys.argv[3:]
key = " ".join([sys.argv[2], *(os.path.basename(own[i + 1]) for i in range(0, len(own), 2) if own[i] == "--deny")])
log = open({str(self.log)!r}, "r+")
tried = log.read().splitlines().count(key)
log.write(key + "\\n")
if tried < json.load(open({str(self.tmp / "plan")!r})).get(key, 0):
    print("failed " + key)
    sys.exit(1)
""")
        self.wisp.chmod(0o755)

    def start(self, plan, folders=("a", "b")):
        """`_reexec`, with `true` in bubblewrap's place: what it says, and each run of `wisp`, in order."""
        (self.tmp / "plan").write_text(json.dumps(plan))
        with patch.object(self.sandbox, "BWRAP", shutil.which("true")), patch.object(self.sandbox, "_inherited_fds", list):
            said = self.sandbox._reexec([f"/zone/{folder}" for folder in folders], "/zone/plugin", str(self.wisp))
        return said, self.log.read_text().splitlines()

    STARTED = "wisp sandbox-exec failed: bubblewrap exited 0"

    def test_a_first_probe_that_passes_runs_no_other(self):
        self.assertEqual(self.start({}), (self.STARTED, ["--check a b", "--print-args a b"]))

    def test_a_folder_whose_probe_fails_once_or_twice_stays_in(self):
        for fails in (1, 2):
            with self.subTest(fails=fails):
                self.log.write_text("")

                said, runs = self.start({"--check a b": 1, "--check a": fails})

                self.assertEqual(said, self.STARTED)
                self.assertEqual(runs[-1], "--print-args a b")

    def test_a_folder_whose_probe_fails_three_times_in_a_row_is_left_out_alone(self):
        said, runs = self.start({"--check a b": 1, "--check a": 3})

        self.assertEqual(said, self.STARTED)
        self.assertEqual(runs[-1], "--print-args b")

    def test_the_folders_kept_that_fail_once_or_twice_more_keep_the_sandbox(self):
        # The first failure is the first probe's.
        said, runs = self.start({"--check a b": 3})

        self.assertEqual(said, self.STARTED)
        self.assertEqual(runs[-1], "--print-args a b")

    def test_the_folders_kept_that_fail_three_times_in_a_row_give_up_the_sandbox(self):
        said, runs = self.start({"--check a b": 4})

        self.assertEqual(said, "failed --check a b")
        self.assertNotIn("--print-args a b", runs)

    def test_a_probe_of_no_folders_that_fails_once_or_twice_keeps_the_sandbox(self):
        said, runs = self.start({"--check a b": 1, "--check": 2})

        self.assertEqual(said, self.STARTED)
        self.assertEqual(runs[-1], "--print-args a b")

    def test_a_probe_of_no_folders_that_keeps_failing_says_the_first_probes_reason(self):
        said, runs = self.start({"--check a b": 1, "--check": 3})

        self.assertEqual(said, "failed --check a b")
        self.assertEqual(runs, ["--check a b", "--check", "--check", "--check"])

    def test_printing_the_arguments_gets_three_tries(self):
        self.assertEqual(self.start({"--print-args a b": 2})[0], self.STARTED)
        self.log.write_text("")

        said, runs = self.start({"--print-args a b": 3})

        self.assertIn("wisp sandbox-exec failed", said)
        self.assertNotEqual(said, self.STARTED)
        self.assertEqual(runs.count("--print-args a b"), 3)


@posix
class LoaderVariables(unittest.TestCase):
    """What a model can write into Hermes's `.env`, which Hermes loads into its environment before the plugin: the
    dynamic loader's variables, which would run its code in each process started outside the sandbox. `_reexec`
    against a `wisp` and a bubblewrap that each log their arguments and environment: no bubblewrap needed."""

    LOADER = {"LD_PRELOAD": "libc.so.6", "LD_LIBRARY_PATH": "/nowhere", "LD_AUDIT": "/nowhere/audit.so", "GCONV_PATH": "/nowhere"}

    def test_neither_wisp_nor_bubblewrap_sees_them_and_the_sandboxed_hermes_gets_them_back(self):
        spec = importlib.util.spec_from_file_location("wisp_sandbox_under_test", PLUGIN / "sandbox.py")
        sandbox = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sandbox)
        tmp = Path(tempfile.mkdtemp(prefix="wisp-hermes-loader-"))
        self.addCleanup(shutil.rmtree, tmp)
        log = tmp / "log"
        for name in ("wisp", "bwrap"):
            (tmp / name).write_text(f"""#!{sys.executable}
import json, os, sys
with open({str(log)!r}, "a") as log:
    log.write(json.dumps({{"argv": sys.argv[1:], "env": dict(os.environ)}}) + "\\n")
if sys.argv[1:3] == ["sandbox-exec", "--print-args"]:
    sys.stdout.write("--bind\\0/\\0/\\0--\\0hermes")
""")
            (tmp / name).chmod(0o755)

        with patch.dict(os.environ, self.LOADER), patch.object(sandbox, "BWRAP", str(tmp / "bwrap")), \
                patch.object(sandbox, "_inherited_fds", list):
            sandbox._reexec(["/zone/a"], "/zone/plugin", str(tmp / "wisp"))

        runs = [json.loads(line) for line in log.read_text().splitlines()]
        self.assertEqual([run["argv"][:2] for run in runs[:2]], [["sandbox-exec", "--check"], ["sandbox-exec", "--print-args"]])
        for run in runs:
            self.assertEqual(sorted(set(self.LOADER) & set(run["env"])), [], run["argv"])
        # As bubblewrap: its own environment, and each `--setenv` among its options, for the command after `--`.
        argv = runs[2]["argv"]
        options = argv[:argv.index("--")]
        hermes = {**runs[2]["env"], **{options[i + 1]: options[i + 2] for i, arg in enumerate(options) if arg == "--setenv"}}
        self.assertEqual({name: hermes.get(name) for name in self.LOADER}, self.LOADER)
        self.assertEqual(argv[argv.index("--"):], ["--", "hermes"])


@posix
class LiveLoad(unittest.TestCase):
    """The plugin enabled under a running gateway: its chats are open, each held in Hermes's registry by this PID,
    which the supervisor keeps. `_reexec` up to its exec, against a `wisp` and a bubblewrap that start nothing."""

    def test_the_chats_this_process_holds_are_released_before_it_becomes_the_supervisor(self):
        spec = importlib.util.spec_from_file_location("wisp_sandbox_under_test", PLUGIN / "sandbox.py")
        sandbox = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sandbox)
        tmp = Path(tempfile.mkdtemp(prefix="wisp-hermes-live-"))
        self.addCleanup(shutil.rmtree, tmp)
        (tmp / "wisp").write_text(f"#!{sys.executable}\nimport sys\nif '--print-args' in sys.argv: sys.stdout.write('--\\0hermes')\n")
        # As bubblewrap: its child's PID on the info fd, then the child runs.
        (tmp / "bwrap").write_text(f"#!{sys.executable}\nimport os, sys, time\n"
                                   "os.write(int(sys.argv[2]), ('{\"child-pid\": %d}' % os.getpid()).encode())\ntime.sleep(30)\n")
        for name in ("wisp", "bwrap"):
            (tmp / name).chmod(0o755)
        registry = tmp / "runtime" / "active_sessions.json"
        registry.parent.mkdir()
        registry.write_text(json.dumps({"entries": [{"lease_id": "mine", "pid": os.getpid()}, {"lease_id": "cli", "pid": 1}]}))
        held = []

        def execve(*_):
            held.append([entry["lease_id"] for entry in json.loads(registry.read_text())["entries"]])
            raise OSError("not in a test")

        with patch.dict(os.environ, {"HERMES_HOME": str(tmp)}), patch.object(sys, "path", [str(FAKE), *sys.path]), \
                patch.dict(sys.modules), patch.object(sandbox, "BWRAP", str(tmp / "bwrap")), \
                patch.object(sandbox, "_inherited_fds", list), patch.object(sandbox.os, "execve", execve):
            for name in [n for n in sys.modules if n == "hermes_cli" or n.startswith("hermes_cli.")]:
                del sys.modules[name]
            sandbox._reexec(["/zone/a"], "/zone/plugin", str(tmp / "wisp"))

        self.assertEqual(held, [["cli"]])


class SandboxModule(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("wisp_sandbox_under_test", PLUGIN / "sandbox.py")
        self.sandbox = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.sandbox)

    def child_pid(self, said):
        read, write = os.pipe()
        os.write(write, said)
        os.close(write)
        try:
            return self.sandbox._child_pid(read)
        finally:
            os.close(read)

    def browser_args_after_apply(self, platform, before):
        """`AGENT_BROWSER_ARGS` after `apply` on `platform` with no bubblewrap, from `before` (None: unset)."""
        with patch.object(sys, "platform", platform), patch.object(self.sandbox, "BWRAP", "/nonexistent/bwrap"), \
                patch.dict(os.environ):
            os.environ.pop("AGENT_BROWSER_ARGS", None)
            if before is not None:
                os.environ["AGENT_BROWSER_ARGS"] = before
            self.assertIsNotNone(self.sandbox.apply(["/zone/a"], "/zone/plugin", None))
            return os.environ.get("AGENT_BROWSER_ARGS")

    def test_a_linux_without_bubblewrap_and_any_other_platform_leave_chromes_own_sandbox_on(self):
        for platform in ("linux", "win32", "freebsd14"):
            for before in (None, "--lang=de"):
                with self.subTest(platform=platform, before=before):
                    self.assertEqual(self.browser_args_after_apply(platform, before), before)

    def test_bubblewraps_info_names_the_child(self):
        self.assertEqual(self.child_pid(b'{\n    "child-pid": 42,\n    "net-namespace": 1\n}\n'), 42)

    def test_a_malformed_info_is_a_failed_start_never_an_exception(self):
        for said in (b"", b"not json", b"[]", b"7", b'{"child-pid": "x"}', b'{"child-pid": -1}', b'{"child-pid": true}', b"\xff"):
            with self.subTest(said=said):
                self.assertIsNone(self.child_pid(said))

    def test_only_a_gateway_run_in_a_systemd_service_hands_back_to_systemd(self):
        unit = {"INVOCATION_ID": "abc"}
        service = "0::/system.slice/hermes-gateway.service\n"
        back = self.sandbox._answers_to_systemd
        self.assertTrue(back(["-m", "hermes_cli.main", "gateway", "run"], unit, service))
        self.assertTrue(back(["-m", "hermes_cli.main", "--profile", "ops", "gateway", "run", "--replace"], unit, service))
        self.assertFalse(back(["-m", "hermes_cli.main", "gateway", "status"], unit, service))
        self.assertFalse(back(["-m", "hermes_cli.main", "chat"], unit, service))
        self.assertFalse(back(["-m", "hermes_cli.main", "gateway", "run"], {}, service))
        # A terminal tab's shell carries an INVOCATION_ID too; nothing respawns what runs in its scope.
        self.assertFalse(back(["-m", "hermes_cli.main", "gateway", "run"], unit, "0::/user.slice/vte-spawn-1.scope\n"))

    def respawned(self, shown, cgroup="0::/system.slice/gw.service\n", installed=(1,)):
        """Whether the unit is taken to respawn this process, with `shown` as `systemctl show`'s answer or failure, and
        a `systemctl` in each of the places `installed` numbers among three it looks in; `self.asked` the argv, else None."""
        self.asked = None
        tmp = Path(tempfile.mkdtemp(prefix="wisp-hermes-systemctl-"))
        self.addCleanup(shutil.rmtree, tmp)
        places = [tmp / str(n) for n in range(3)]
        for n, place in enumerate(places):
            place.mkdir()
            if n in installed:
                (place / "systemctl").write_text("#!/bin/sh\n")
                (place / "systemctl").chmod(0o755)
        self.places = places

        def run(argv, **kwargs):
            self.asked, self.asked_env = argv, kwargs.get("env")
            if isinstance(shown, Exception):
                raise shown
            return SimpleNamespace(stdout=shown, returncode=0)

        with patch.object(self.sandbox.subprocess, "run", run), patch.object(self.sandbox, "SYSTEMCTL_DIRS", list(map(str, places))):
            return self.sandbox._a_unit_respawns_this_process(cgroup)

    @posix
    def test_systemctl_is_the_first_of_its_places_and_never_one_on_path(self):
        shown = f"MainPID={os.getpid()}\nRestart=always\n"
        # What a model can put first on PATH through `.env`.
        planted = Path(tempfile.mkdtemp(prefix="wisp-hermes-path-"))
        self.addCleanup(shutil.rmtree, planted)
        (planted / "systemctl").write_text("#!/bin/sh\n")
        (planted / "systemctl").chmod(0o755)
        with patch.dict(os.environ, {"PATH": f"{planted}{os.pathsep}{os.environ['PATH']}"}):
            self.assertTrue(self.respawned(shown, installed=(1, 2)))
            self.assertEqual(self.asked[0], str(self.places[1] / "systemctl"))

            # Not even one on PATH: no `systemctl`, no unit to hand the gateway back to.
            self.assertFalse(self.respawned(shown, installed=()))
            self.assertIsNone(self.asked)

    @posix
    def test_systemctl_runs_without_the_loader_variables_and_with_what_the_user_bus_needs(self):
        user = {"HOME": "/home/u", "XDG_RUNTIME_DIR": "/run/user/1000", "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus"}
        with patch.dict(os.environ, {**LoaderVariables.LOADER, **user}):
            self.respawned(f"MainPID={os.getpid()}\nRestart=always\n", "0::/user.slice/user-1000.slice/user@1000.service/gw.service\n")

        self.assertEqual([name for name in LoaderVariables.LOADER if name in self.asked_env], [])
        self.assertEqual({name: self.asked_env.get(name) for name in user}, user)

    def test_only_this_process_as_main_with_a_restart_that_follows_every_failed_exit_counts(self):
        for restart, expected in (("always", True), ("on-failure", True), ("on-abnormal", False), ("on-abort", False),
                                  ("on-watchdog", False), ("on-success", False), ("no", False)):
            with self.subTest(restart=restart):
                self.assertEqual(self.respawned(f"MainPID={os.getpid()}\nRestart={restart}\n"), expected)
        self.assertFalse(self.respawned(f"MainPID={os.getppid()}\nRestart=always\n"))

    def test_any_failure_to_ask_systemd_is_no(self):
        for shown in (FileNotFoundError("systemctl"), subprocess.TimeoutExpired("systemctl", 10),
                      UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid"), "", "not properties\n"):
            with self.subTest(shown=shown):
                self.assertFalse(self.respawned(shown))

    def test_a_cgroup_it_cannot_decode_is_no_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            cgroup = Path(tmp) / "cgroup"
            cgroup.write_bytes(b"0::/system.slice/gw\xff.service\n")
            real_open = open
            with patch("builtins.open", lambda path, *a, **k: real_open(cgroup if path == "/proc/self/cgroup" else path, *a, **k)), \
                    patch.object(sys, "argv", ["hermes", "gateway", "run"]), patch.dict(os.environ, {"INVOCATION_ID": "abc"}):
                self.assertEqual(self.sandbox._command(), [sys.executable, *sys.orig_argv[1:]])

    def test_it_asks_the_systemd_that_owns_the_cgroup(self):
        shown = f"MainPID={os.getpid()}\nRestart=always\n"
        self.respawned(shown)
        self.assertEqual(self.asked[1:3], ["show", "gw.service"])
        self.assertTrue(self.respawned(shown, "0::/user.slice/user-1000.slice/user@1000.service/app.slice/gw.service\n"))
        self.assertEqual(self.asked[1:4], ["--user", "show", "gw.service"])

    def test_a_hermes_too_old_for_the_flag_is_not_given_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            parser = Path(tmp) / "gateway.py"
            spec = SimpleNamespace(origin=str(parser))
            with patch.object(importlib.util, "find_spec", return_value=spec):
                parser.write_text("--replace")
                self.assertFalse(self.sandbox._knows_external_supervisor())
                parser.write_text('"--external-supervisor"')
                self.assertTrue(self.sandbox._knows_external_supervisor())
        with patch.object(importlib.util, "find_spec", return_value=None):
            self.assertFalse(self.sandbox._knows_external_supervisor())

    @posix
    def test_a_controlling_terminal_is_found_with_stdin_elsewhere(self):
        import pty  # Here: on Windows it fails through `termios`, and at the top it would fail the whole module.

        read, write = os.pipe()
        pid, fd = pty.fork()
        if pid == 0:
            try:
                os.dup2(os.open(os.devnull, os.O_RDWR), 0)
                os.write(write, b"yes" if self.sandbox._has_terminal() else b"no")
            finally:
                os._exit(0)
        os.close(write)
        said = os.read(read, 16)
        os.close(read)
        os.waitpid(pid, 0)
        os.close(fd)

        self.assertEqual(said, b"yes")

    @posix
    def test_a_process_with_no_controlling_terminal_has_none(self):
        done = subprocess.run([sys.executable, "-c", f"""
import importlib.util
spec = importlib.util.spec_from_file_location("sandbox", {str(PLUGIN / "sandbox.py")!r})
sandbox = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sandbox)
print(sandbox._has_terminal())"""], start_new_session=True, capture_output=True, text=True)

        self.assertEqual(done.stdout.strip(), "False")


class TerminalWarning(unittest.TestCase):
    """What the kernel's `dev.tty.legacy_tiocsti` says of `TIOCSTI`, from a stand-in for its file."""

    def warning(self, content):
        spec = importlib.util.spec_from_file_location("wisp_sandbox_under_test", PLUGIN / "sandbox.py")
        sandbox = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sandbox)
        with tempfile.TemporaryDirectory() as tmp:
            sysctl = Path(tmp) / "legacy_tiocsti"
            if content is not None:
                sysctl.write_text(content)
            return sandbox.tiocsti_warning(str(sysctl))

    def test_a_kernel_that_allows_it_names_the_sysctl(self):
        self.assertIn("sysctl dev.tty.legacy_tiocsti=0", self.warning("1\n"))

    def test_a_kernel_before_the_switch_names_the_upgrade(self):
        self.assertIn("upgrade to kernel 6.2+", self.warning(None))

    def test_a_kernel_that_refuses_it_warns_of_nothing(self):
        self.assertIsNone(self.warning("0\n"))


@linux
@sandboxed
class Supervisor(HermesHome):
    """The process Hermes was started as, once the sandboxed Hermes runs: `HANDLERS` make a Hermes that says each
    signal it gets on stdout and exits 7 on `SIGTERM`."""

    HANDLERS = """
import os, signal, sys
load_plugin()
for s in (signal.SIGINT, signal.SIGQUIT, signal.SIGHUP, signal.SIGUSR1, signal.SIGUSR2):
    signal.signal(s, lambda n, _: print(signal.Signals(n).name, flush=True))
signal.signal(signal.SIGTERM, lambda n, _: (print("SIGTERM", flush=True), os._exit(7)))
"""
    SERVE = """
print("up", os.getpid(), flush=True)
while True:
    signal.pause()
"""

    def start(self, code, **kwargs):
        """The fake Hermes running `code`, once it is the supervisor: (the process, what `code` printed first)."""
        hermes = subprocess.Popen([sys.executable, str(FAKE / "hermes"), "python", code], env={**self.env(), **kwargs.pop("env", {})},
                                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, **kwargs)
        self.addCleanup(hermes.stdout.close)
        self.addCleanup(hermes.wait)
        self.addCleanup(hermes.kill)
        first = hermes.stdout.readline().strip()
        for _ in range(500):
            # Its last disposition set: a signal any sooner would find none of them.
            status = Path(f"/proc/{hermes.pid}/status").read_text()
            ignored = int(next(line.split()[1] for line in status.splitlines() if line.startswith("SigIgn:")), 16)
            if (b"supervise.py" in Path(f"/proc/{hermes.pid}/cmdline").read_bytes()
                    and ignored >> (signal.SIGQUIT - 1) & 1):
                break
            time.sleep(0.01)
        else:
            self.fail("the process Hermes was started as did not become the supervisor")
        # Killing the supervisor alone would leave the sandboxed Hermes running under pid 1.
        self.addCleanup(_kill, int(_cmdline(hermes.pid).split(b"\0")[-3]))
        return hermes, first

    def said(self, hermes):
        return hermes.stdout.readline().strip()

    def test_the_process_it_was_started_as_supervises_a_hermes_with_a_host_pid_of_its_own(self):
        hermes, first = self.start(self.HANDLERS + self.SERVE)
        child = int(first.split()[1])

        self.assertNotEqual(child, hermes.pid)
        self.assertIn(b"python", Path(f"/proc/{child}/cmdline").read_bytes())
        self.assertIn(b"hermes", Path(f"/proc/{child}/cmdline").read_bytes())

    def test_no_bubblewrap_stays_behind_with_hermess_command_line(self):
        hermes, first = self.start(self.HANDLERS + self.SERVE)
        child = int(first.split()[1])

        for _ in range(500):
            if int(Path(f"/proc/{child}/stat").read_text().rsplit(")", 1)[1].split()[1]) == hermes.pid:
                break
            time.sleep(0.01)

        # Hermes's process scan matches a command line: only the sandboxed Hermes is left to carry this one.
        self.assertEqual(int(Path(f"/proc/{child}/stat").read_text().rsplit(")", 1)[1].split()[1]), hermes.pid)
        others = [pid for pid in filter(str.isdigit, os.listdir("/proc"))
                  if b"bwrap" in _cmdline(pid) and str(self.bank).encode() in _cmdline(pid)]
        self.assertEqual(others, [])

    def test_it_forwards_what_a_manager_sends_and_exits_with_the_code_of_hermes(self):
        hermes, _ = self.start(self.HANDLERS + self.SERVE)

        for signum in (signal.SIGHUP, signal.SIGUSR1, signal.SIGUSR2, signal.SIGTERM):
            hermes.send_signal(signum)
            self.assertEqual(self.said(hermes), signum.name)

        self.assertEqual(hermes.wait(timeout=20), 7)

    def test_it_does_not_forward_what_a_terminal_already_sent_to_hermes(self):
        hermes, _ = self.start(self.HANDLERS + self.SERVE)

        hermes.send_signal(signal.SIGINT)
        hermes.send_signal(signal.SIGQUIT)
        hermes.send_signal(signal.SIGUSR1)

        self.assertEqual(self.said(hermes), "SIGUSR1")

    def test_ctrl_c_reaches_hermes_once_and_hermes_goes_on(self):
        hermes, _ = self.start(self.HANDLERS + self.SERVE, start_new_session=True)

        os.killpg(hermes.pid, signal.SIGINT)

        self.assertEqual(self.said(hermes), "SIGINT")
        hermes.send_signal(signal.SIGTERM)
        self.assertEqual(self.said(hermes), "SIGTERM")
        self.assertEqual(hermes.wait(timeout=20), 7)

    def test_it_exits_128_plus_the_signal_that_killed_hermes(self):
        hermes, _ = self.start(self.HANDLERS + """
print("up", flush=True)
signal.signal(signal.SIGUSR1, lambda *_: os.kill(os.getpid(), signal.SIGKILL))
while True:
    signal.pause()
""")

        hermes.send_signal(signal.SIGUSR1)

        self.assertEqual(hermes.wait(timeout=20), 128 + signal.SIGKILL)

    def test_the_loader_variables_hermes_was_started_with_reach_the_sandboxed_hermes_and_not_the_supervisor(self):
        loader = LoaderVariables.LOADER
        hermes, first = self.start(f"""
import json, os, signal
load_plugin()
print(json.dumps({{name: os.environ.get(name) for name in {list(loader)!r}}}), flush=True)
signal.pause()
""", env=loader)

        self.assertEqual(json.loads(first), loader)
        supervisor = dict(entry.split(b"=", 1) for entry in Path(f"/proc/{hermes.pid}/environ").read_bytes().split(b"\0") if entry)
        self.assertEqual([name for name in loader if name.encode() in supervisor], [])

    def test_it_relays_only_what_hermes_itself_may_tell_systemd(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as real:
            real.bind(str(self.tmp / "notify"))
            real.settimeout(20)
            hermes, _ = self.start("""
import os, socket, subprocess, sys
load_plugin()
target = os.environ["NOTIFY_SOCKET"]
print("up", target, flush=True)
address = "\\0" + target[1:] if target.startswith("@") else target
with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
    # A process Hermes started: `NotifyAccess=main` takes only the main PID's.
    subprocess.run([sys.executable, "-c", f"import socket; socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM).sendto(b'STOPPING=1', {address!r})"], check=True)
    s.sendto(b"FDSTORE=1", address)
    s.sendto(b"READY=1\\nMAINPID=1", address)
    s.sendto(b"WATCHDOG=1", address)
import signal
signal.pause()
""", env={"NOTIFY_SOCKET": str(self.tmp / "notify"), "WATCHDOG_PID": "1"})

            self.assertEqual(real.recv(4096), b"READY=1")
            self.assertEqual(real.recv(4096), b"WATCHDOG=1")


@linux
class RetiringBubblewrap(unittest.TestCase):
    """The real `supervise.py` over two children of this script, as bubblewrap and its fork: same command line."""

    SUPERVISE = f"""
os.execv(sys.executable, [sys.executable, "-I", "-S", {str(PLUGIN / "supervise.py")!r}, str(started), str(child), "-"])"""

    def test_a_supervisor_whose_two_children_died_first_exits_with_the_status_of_hermes(self):
        done = subprocess.run([sys.executable, "-c", f"""
import os, sys, time
started = os.fork()
if started == 0:
    os._exit(3)
child = os.fork()
if child == 0:
    os._exit(5)
while any(open(f"/proc/{{pid}}/cmdline", "rb").read() for pid in (started, child)):
    time.sleep(0.01)
{self.SUPERVISE}"""], capture_output=True, text=True, timeout=20)

        self.assertEqual(done.returncode, 5, done.stderr)

    def test_bubblewrap_lives_until_hermes_has_execd(self):
        done = subprocess.run([sys.executable, "-c", f"""
import os, signal, sys, time
started = os.fork()
if started == 0:
    signal.pause()
    os._exit(0)
child = os.fork()
if child == 0:
    # Still bubblewrap's fork, whose command line is its parent's: it would hang for good with its parent gone.
    time.sleep(1)
    state = open(f"/proc/{{started}}/stat").read().rsplit(")", 1)[1].split()[0]
    print("bubblewrap", "dead" if state == "Z" else "alive", flush=True)
    os.execv("/bin/sh", ["/bin/sh", "-c", "exit 5"])
{self.SUPERVISE}"""], capture_output=True, text=True, timeout=20)

        self.assertEqual(done.stdout.strip(), "bubblewrap alive")
        self.assertEqual(done.returncode, 5, done.stderr)


if __name__ == "__main__":
    unittest.main()
