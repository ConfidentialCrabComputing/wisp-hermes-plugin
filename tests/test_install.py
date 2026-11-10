"""The plugin's folder installs with a real Hermes's `hermes plugins install file://<path>#wisp --enable` and loads.
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

    def test_scans_and_installs_only_the_plugin_folder_as_wisp_and_it_loads(self):
        # Without --force and with no terminal to ask on, Hermes lists its scanner's `caution` findings and refuses.
        scan = self.hermes("plugins", "install", f"file://{REPO}#wisp", code=1)
        self.assertIn("Verdict: CAUTION", scan)
        self.assertIn("sandbox.py:", scan)
        self.assertNotIn("tests/", scan)
        self.assertNotIn("README", scan)

        self.hermes("plugins", "install", f"file://{REPO}#wisp", "--enable", "--force")

        self.assertTrue((self.tmp / "home" / "plugins" / "wisp" / "plugin.yaml").exists())
        # The plugin's CLI command exists only once Hermes has loaded the plugin.
        self.assertIn("--remove", self.hermes("wisp", "connect", "--help"))


if __name__ == "__main__":
    unittest.main()
