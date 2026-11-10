"""`/wisp` and `/wisp-model`, the plugin's slash commands, against the fake
`hermes`. Run: python3 -m unittest discover -s tests"""

import http.server
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

FAKE = Path(__file__).resolve().parent / "fake"
PLUGIN = Path(__file__).resolve().parents[1] / "wisp"
CREDENTIAL = "wisp_hermes_s3cr3t"


def answered(text, conversation="s1"):
    """`ask_wisp`/`wisp_result`'s answer, as Hermes's registry renders an MCP tool's result."""
    return {"result": f"{text}\n\n(conversation: {conversation})",
            "structuredContent": {"answer": text, "conversation": conversation}}


def running(run, conversation="s1"):
    return {"result": f"Wisp is still at work on it (run: {run}). Call wisp_result with run {run} for its answer.",
            "structuredContent": {"run": run, "conversation": conversation}}


class Commands(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="wisp-hermes-commands-"))
        self.addCleanup(shutil.rmtree, self.home)
        shutil.copytree(PLUGIN, self.home / "plugins" / "wisp", ignore=shutil.ignore_patterns("__pycache__"))
        self.config = {"plugins": {"enabled": ["wisp"]}}

    def hermes(self, *argv, tools=None):
        (self.home / "config.yaml").write_text(json.dumps(self.config))
        (self.home / "tools.json").write_text(json.dumps(tools or {}))
        env = {**os.environ, "HERMES_HOME": str(self.home), "PATH": f"{FAKE}{os.pathsep}{os.environ['PATH']}"}
        # By its interpreter: Windows does not start a script through its shebang.
        done = subprocess.run([sys.executable, str(FAKE / "hermes"), *argv], env=env, capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout

    def slash(self, name, args, tools=None):
        """`/<name> args` typed in the CLI."""
        return self.hermes("slash", name, args, tools=tools)

    def message(self, name, args):
        """`/<name> args` sent to a gateway (Telegram, Slack, ...)."""
        return self.hermes("message", name, args)

    def test_every_command_is_found_on_every_surface(self):
        names = json.loads(self.hermes("python", "import json; print(json.dumps(list(load_plugin().commands)))"))

        self.assertIn("wisp", names)
        for name in names:
            # Telegram's menu offers a hyphen as an underscore; other gateways send it as typed.
            for shown in {name.replace("-", "_"), name}:
                with self.subTest(message=shown):
                    self.assertNotIn("Unknown command", self.message(shown, ""))
            with self.subTest(slash=name):
                self.assertNotIn("Unknown command", self.slash(name, ""))

    def dispatched(self):
        try:
            return [json.loads(line) for line in (self.home / "tools.log").read_text().splitlines()]
        except OSError:
            return []

    def test_wisp_hands_the_task_to_ask_wisp_and_shows_its_answer(self):
        shown = self.slash("wisp", "what is my balance?",
                           {"mcp__wisp__ask_wisp": [answered("The balance is 42.")]})

        self.assertEqual(self.dispatched(), [["mcp__wisp__ask_wisp", {"task": "what is my balance?"}]])
        self.assertIn("The balance is 42.", shown)

    def test_wisp_on_running_asks_wisp_result_until_the_answer(self):
        shown = self.slash("wisp", "summarise my mail", {
            "mcp__wisp__ask_wisp": [running("r1")],
            "mcp__wisp__wisp_result": [running("r1"), answered("Three bills are due.")],
        })

        self.assertEqual(self.dispatched(), [
            ["mcp__wisp__ask_wisp", {"task": "summarise my mail"}],
            ["mcp__wisp__wisp_result", {"run": "r1"}],
            ["mcp__wisp__wisp_result", {"run": "r1"}],
        ])
        self.assertIn("Three bills are due.", shown)

    def test_wisp_shows_a_failed_call(self):
        shown = self.slash("wisp", "pay the bill", {"mcp__wisp__ask_wisp": [{"error": "Wisp is not signed in."}]})

        self.assertIn("Wisp is not signed in.", shown)

    def endpoint(self, answer, raw=None):
        """A fake Wisp MCP endpoint whose tools answer `answer`, or the body `raw` whole; returns the `tools/call`
        requests it got."""
        calls = []

        class Mcp(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                message = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if "id" not in message:
                    self.send_response(202)
                    self.end_headers()
                    return
                if message["method"] == "tools/call":
                    calls.append({"authorization": self.headers["Authorization"], **message["params"]})
                    result = {"content": [{"type": "text", "text": answer}]}
                else:
                    result = {"protocolVersion": "2025-06-18", "capabilities": {}, "serverInfo": {"name": "wisp"}}
                body = json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}).encode()
                if raw is not None and message["method"] == "tools/call":
                    body = raw
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Mcp-Session-Id", "m1")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_DELETE(self):
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Mcp)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.config["mcp_servers"] = {"wisp": {"url": f"http://127.0.0.1:{server.server_address[1]}/mcp"}}
        (self.home / ".env").write_text(f"WISP_CREDENTIAL_TOKEN={CREDENTIAL}\n")
        return calls

    def test_wisp_model_calls_the_endpoints_wisp_model_with_its_args_and_shows_its_answer(self):
        calls = self.endpoint("Model: balanced (thinking off).")

        shown = {"cli": self.slash("wisp-model", "balanced"), "telegram": self.message("wisp_model", "balanced")}

        # The plugin's load also asks `wisp_zone`.
        self.assertEqual([call for call in calls if call["name"] == "wisp_model"], 2 * [{"authorization": f"Bearer {CREDENTIAL}", "name": "wisp_model",
                                  "arguments": {"args": "balanced"}}])
        for surface, text in shown.items():
            with self.subTest(surface=surface):
                self.assertIn("Model: balanced (thinking off).", text)

    def test_wisp_model_on_a_malformed_answer_says_it_failed(self):
        for body in (b"[]", b"5", b'{"result": "x"}', b'{"result": {"isError": true, "content": "x"}}'):
            with self.subTest(body=body):
                self.endpoint(None, raw=body)

                self.assertIn("Wisp's wisp_model failed: ", self.slash("wisp-model", ""))

    def test_wisp_model_without_a_connected_endpoint_says_so(self):
        shown = self.slash("wisp-model", "")

        self.assertIn("hermes wisp connect", shown)


if __name__ == "__main__":
    unittest.main()
