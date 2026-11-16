"""The plugin's folder installs with a real Hermes's `hermes plugins install file://<path>#wisp --enable`, with no --force and no terminal, and loads.
Needs a real `hermes` on PATH; skipped without one. Installs the committed HEAD."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
HERMES = shutil.which("hermes")


@unittest.skipUnless(HERMES and "fake" not in HERMES, "needs a real hermes on PATH")
class Install(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="wisp-hermes-install-"))
        self.addCleanup(shutil.rmtree, self.tmp)
        self.env = {**os.environ, "HERMES_HOME": str(self.tmp / "home")}
        (self.tmp / "home").mkdir()

    def hermes(self, *argv, code=0):
        done = subprocess.run([HERMES, *argv], env=self.env, capture_output=True, text=True, stdin=subprocess.DEVNULL)
        self.assertEqual(done.returncode, code, done.stdout + done.stderr)
        return done.stdout

    def test_installs_only_the_plugin_folder_as_wisp_without_force_and_it_loads(self):
        # Hermes's scanner rates the plugin `safe`, so no --force and no terminal to confirm on are needed.
        self.hermes("plugins", "install", f"file://{REPO}#wisp", "--enable")

        # Hermes scans the clone it then installs: the installed tree is exactly the committed `wisp/` folder.
        installed = self.tmp / "home" / "plugins" / "wisp"
        committed = subprocess.run(["git", "-C", str(REPO / "wisp"), "ls-tree", "-r", "--name-only", "HEAD", "."],
                                   capture_output=True, text=True, check=True).stdout.split()
        self.assertEqual(sorted(str(p.relative_to(installed)) for p in installed.rglob("*") if p.is_file()),
                         sorted(committed))
        # The plugin's CLI command exists only once Hermes has loaded the plugin.
        self.assertIn("--remove", self.hermes("wisp", "connect", "--help"))


if __name__ == "__main__":
    unittest.main()
