"""The plugin's `pre_tool_call` hook: a call that reaches into Wisp's zone, or
switches the plugin off, is refused naming `ask_wisp`; anything else proceeds. Against the fake `hermes`,
from the plugin's zone cache. Run: python3 -m unittest discover -s tests"""

import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

FAKE = Path(__file__).resolve().parent / "fake"
PLUGIN = Path(__file__).resolve().parents[1]
ZONE = {"dataDir": "/home/u/.wisp", "deskRoot": "/home/u/Wisp",
        "privateFolders": [{"path": "/home/u/bank"}], "services": ["gmail"]}


class Hook(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="wisp-hermes-hook-"))
        self.addCleanup(shutil.rmtree, self.home)
        shutil.copytree(PLUGIN, self.home / "plugins" / "wisp", ignore=shutil.ignore_patterns("__pycache__", ".git", "tests"))
        (self.home / "config.yaml").write_text(json.dumps({"plugins": {"enabled": ["wisp"]}}))
        self.zone(ZONE)

    def zone(self, zone):
        (self.home / "plugins" / "wisp" / "zone.json").write_text(json.dumps(zone))

    def verdicts(self, *calls):
        """The block message for each `(tool_name, args)`, None for each call that proceeds."""
        env = {**os.environ, "HERMES_HOME": str(self.home), "PATH": f"{FAKE}{os.pathsep}{os.environ['PATH']}"}
        done = subprocess.run(["hermes", "pre-tool-call"], input=json.dumps(calls), env=env,
                              capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        return json.loads(done.stdout)

    def assertBlocked(self, *calls):
        for call, verdict in zip(calls, self.verdicts(*calls)):
            with self.subTest(call=call):
                self.assertIsNotNone(verdict)
                self.assertIn("ask_wisp", verdict)

    def test_a_private_folder_path_in_a_file_tool_is_blocked(self):
        self.assertBlocked(
            ("read_file", {"path": "/home/u/bank/statement.pdf"}),
            ("read_file", {"path": "/home/u/bank"}),
            ("write_file", {"path": "/home/u/bank/notes.md", "content": "x"}),
            ("patch", {"path": "/home/u/bank/../bank/a.txt", "old_string": "a", "new_string": "b"}),
            ("search_files", {"pattern": "IBAN", "path": "/home/u/bank"}),
            ("patch", {"mode": "patch", "patch": "*** Begin Patch\n*** Update File: /home/u/bank/a.txt\n"}),
        )

    def test_a_private_folder_named_in_terminal_or_code_text_is_blocked(self):
        self.assertBlocked(
            ("terminal", {"command": "cat /home/u/bank/statement.csv | head"}),
            ("terminal", {"command": "ls /home/u/bank"}),
            ("execute_code", {"code": "open('/home/u/bank/a.csv').read()"}),
            ("terminal", {"command": "cat statement.csv", "workdir": "/home/u/bank"}),
        )

    def test_a_private_folder_as_a_file_url_in_browser_navigation_is_blocked(self):
        self.assertBlocked(
            ("browser_navigate", {"url": "file:///home/u/bank/statement.pdf"}),
            ("mcp_playwright_browser_navigate", {"url": "file:///home/u/bank/My%20Statement.pdf"}),
        )

    def test_the_desk_root_and_wisps_data_directory_are_blocked_the_same_way(self):
        self.assertBlocked(
            ("read_file", {"path": "/home/u/Wisp/report.md"}),
            ("read_file", {"path": "/home/u/.wisp/global.db"}),
            ("terminal", {"command": "sqlite3 /home/u/.wisp/data.db .dump"}),
            ("terminal", {"command": "ls /home/u/Wisp"}),
            ("browser_navigate", {"url": "file:///home/u/Wisp/report.html"}),
        )

    def test_a_zone_folder_under_home_named_with_a_tilde_is_blocked(self):
        home = Path.home()
        self.zone({**ZONE, "privateFolders": [{"path": str(home / "bank")}]})

        self.assertBlocked(
            ("read_file", {"path": "~/bank/a.csv"}),
            ("terminal", {"command": "cat ~/bank/a.csv"}),
        )

    def test_each_attempt_to_switch_the_plugin_off_is_blocked(self):
        self.assertBlocked(
            ("terminal", {"command": "hermes plugins disable wisp"}),
            ("terminal", {"command": "hermes plugins remove wisp && hermes gateway restart"}),
            ("terminal", {"command": "hermes plugins rm wisp"}),
            ("terminal", {"command": f"sed -i '/wisp/d' {self.home / 'config.yaml'}"}),
            ("terminal", {"command": "hermes config set plugins.enabled '[]'"}),
            ("terminal", {"command": "hermes config unset plugins"}),
            ("terminal", {"command": "hermes gateway install"}),
            ("terminal", {"command": "hermes gateway restart"}),
            ("execute_code", {"code": "subprocess.run(['hermes', 'plugins', 'disable', 'wisp'])"}),
            ("write_file", {"path": str(self.home / "config.yaml"), "content": "plugins:\n  enabled: []\n"}),
            ("patch", {"path": str(self.home / "config.yaml"), "old_string": "  - wisp\n", "new_string": ""}),
            # Plugins are opt-in: a config.yaml rewritten without the section switches Wisp off too.
            ("write_file", {"path": str(self.home / "config.yaml"), "content": "model: x\n"}),
            ("patch", {"mode": "patch", "patch": f"*** Update File: {self.home / 'config.yaml'}\n"}),
        )

    def test_a_call_to_a_server_moved_into_wisp_and_switching_it_back_on_are_blocked(self):
        # `wisp integrate hermes` records the servers it switched off beside the plugin.
        (self.home / "plugins" / "wisp" / "moved.json").write_text(json.dumps(["notes", "my-crm"]))

        self.assertBlocked(
            ("mcp_notes_search", {"query": "x"}),
            ("mcp_my_crm_list_deals", {}),
            ("terminal", {"command": "hermes config set mcp_servers.notes.enabled true"}),
            ("terminal", {"command": "hermes config unset mcp_servers.my-crm.enabled"}),
            ("terminal", {"command": "hermes mcp remove notes"}),
            ("terminal", {"command": f"sed -i 's/enabled: false/enabled: true/' {self.home / 'config.yaml'} # notes"}),
        )
        self.assertEqual(self.verdicts(
            ("mcp_notebook_search", {}),
            ("terminal", {"command": "hermes config set mcp_servers.notebook.enabled true"}),
        ), [None, None])

    def test_switch_off_attempts_are_blocked_even_with_no_zone(self):
        (self.home / "plugins" / "wisp" / "zone.json").unlink()

        self.assertBlocked(("terminal", {"command": "hermes plugins disable wisp"}))

    def test_a_malformed_zone_blocks_nothing_but_switch_off_attempts(self):
        self.zone({**ZONE, "privateFolders": [{"name": "bank"}]})

        self.assertEqual(self.verdicts(("read_file", {"path": "/home/u/notes.md"})), [None])
        self.assertBlocked(("terminal", {"command": "hermes plugins disable wisp"}))

    def test_an_unrelated_call_passes(self):
        self.assertEqual(self.verdicts(
            ("read_file", {"path": "/home/u/notes.md"}),
            ("read_file", {"path": "/home/u/bank2/a.csv"}),
            ("write_file", {"path": "/home/u/.wispy/a", "content": "x"}),
            ("terminal", {"command": "ls /home/u/bank2 /home/u && hermes plugins list"}),
            ("terminal", {"command": "hermes gateway status"}),
            ("execute_code", {"code": "print(1)"}),
            ("browser_navigate", {"url": "https://example.com/home/u/bank"}),
            ("browser_navigate", {"url": "file:///home/u/public/page.html"}),
            ("web_search", {"query": "/home/u/bank"}),
            ("mcp_wisp_ask_wisp", {"task": "summarise /home/u/bank/statement.pdf"}),
            ("read_file", {"path": str(self.home / "config.yaml")}),
            ("terminal", {"command": "ls /mnt/backup/home/u/bank"}),
            ("read_file", {"path": "a\x00b"}),
            ("browser_type", {"text": "file://[x/y"}),
        ), [None] * 14)

    def test_a_long_line_naming_hermes_is_judged_quickly(self):
        start = time.monotonic()

        self.assertEqual(self.verdicts(("terminal", {"command": "hermes " * 50000})), [None])
        self.assertLess(time.monotonic() - start, 5)

    def test_a_zone_folder_that_would_cover_everything_is_skipped(self):
        for folder in ("", ".", "~", "/", str(Path.home()), "relative/dir"):
            with self.subTest(folder=folder):
                self.zone({**ZONE, "privateFolders": [{"path": folder}]})

                self.assertEqual(self.verdicts(
                    ("terminal", {"command": "echo hi && ls src/ /tmp"}),
                    ("read_file", {"path": str(Path.home() / "notes.md")}),
                    ("read_file", {"path": "/etc/hosts"}),
                ), [None] * 3)
                self.assertBlocked(("read_file", {"path": "/home/u/.wisp/global.db"}))


if __name__ == "__main__":
    unittest.main()
