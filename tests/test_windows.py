"""What Windows lacks, on any machine: every test module still loads, and what needs a POSIX terminal skips.
Run: python3 -m unittest discover -s tests"""

import subprocess
import sys
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent
LACKING = """
import sys
for name in ("termios", "fcntl", "pwd", "grp", "resource"):
    sys.modules[name] = None
import http.server, shutil, subprocess, tempfile, unittest, unittest.mock  # Before the name below, or they look for Windows's API.
shutil.which = lambda *_: None
sys.platform = "win32"
loader = unittest.TestLoader()
suite = loader.discover({tests!r})
for error in loader.errors:
    print(error)
def tests(of):
    for test in of:
        if isinstance(test, unittest.TestSuite):
            yield from tests(test)
        else:
            yield test
result = unittest.TestResult()
for test in tests(suite):
    if test.id().endswith(".test_a_controlling_terminal_is_found_with_stdin_elsewhere"):
        test.run(result)
print(result.testsRun, len(result.skipped))
"""


class Windows(unittest.TestCase):
    def test_every_module_loads_and_a_terminal_is_never_opened(self):
        done = subprocess.run([sys.executable, "-c", LACKING.format(tests=str(TESTS))], capture_output=True, text=True)

        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout.split("\n")[0], "1 1", done.stdout)


if __name__ == "__main__":
    unittest.main()
