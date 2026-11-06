"""This repository installs with a real Hermes's `hermes plugins install file://<path> --enable` and loads.
Needs a real `hermes` on PATH; skipped without one. Installs the committed HEAD."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

PLUGIN = Path(__file__).resolve().parents[1]
HERMES = shutil.which("hermes")


@unittest.skipUnless(HERMES and "fake" not in HERMES, "needs a real hermes on PATH")
class Install(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="wisp-hermes-install-"))
        self.addCleanup(shutil.rmtree, self.tmp)
        self.env = {**os.environ, "HERMES_HOME": str(self.tmp / "home")}
        (self.tmp / "home").mkdir()

    def hermes(self, *argv):
        done = subprocess.run([HERMES, *argv], env=self.env, capture_output=True, text=True, stdin=subprocess.DEVNULL)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        return done.stdout

    def test_installs_from_a_local_git_path_and_loads(self):
        # --force: Hermes's scanner says `caution` of this plugin, and with no terminal to ask on it refuses.
        self.hermes("plugins", "install", f"file://{PLUGIN}", "--enable", "--force")

        self.assertTrue((self.tmp / "home" / "plugins" / "wisp" / "plugin.yaml").exists())
        # The plugin's CLI command exists only once Hermes has loaded the plugin.
        self.assertIn("--remove", self.hermes("wisp", "connect", "--help"))


if __name__ == "__main__":
    unittest.main()
