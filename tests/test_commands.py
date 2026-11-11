"""`/wisp` and `/wisp-model`, the plugin's slash commands, against the fake
`hermes`. Run: python3 -m unittest discover -s tests"""

import http.server
import itertools
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

FAKE = Path(__file__).resolve().parent / "fake"
PLUGIN = Path(__file__).resolve().parents[1] / "wisp"
CREDENTIAL = "wisp_hermes_s3cr3t"


def answered(text, conversation="s1"):
    """`ask_wisp`/`wisp_result`'s answer, as Hermes's registry renders an MCP tool's result."""
    return {"result": f"{text}\n\n(conversation: {conversation})",
            "structuredContent": {"answer": text, "conversation": conversation}}


def text(answer, **structured):
    """A `CallToolResult` as Wisp's endpoint sends it."""
    return {"content": [{"type": "text", "text": answer}], **({"structuredContent": structured} if structured else {})}


def running(run, conversation="s1"):
    return {"result": f"Wisp is still at work on it (run: {run}). Call wisp_result with run {run} for its answer.",
            "structuredContent": {"run": run, "conversation": conversation}}


class Commands(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="wisp-hermes-commands-"))
        self.addCleanup(shutil.rmtree, self.home)
        shutil.copytree(PLUGIN, self.home / "plugins" / "wisp", ignore=shutil.ignore_patterns("__pycache__"))
        self.config = {"plugins": {"enabled": ["wisp"]}}

    def hermes(self, *argv, tools=None, choice=None, **fake):
        (self.home / "config.yaml").write_text(json.dumps(self.config))
        (self.home / "tools.json").write_text(json.dumps(tools or {}))
        env = {**os.environ, "HERMES_HOME": str(self.home), "PATH": f"{FAKE}{os.pathsep}{os.environ['PATH']}", **fake}
        env.pop("FAKE_HERMES_CHOICE", None)
        if choice is not None:
            env["FAKE_HERMES_CHOICE"] = choice
        # By its interpreter: Windows does not start a script through its shebang.
        done = subprocess.run([sys.executable, str(FAKE / "hermes"), *argv], env=env, capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout

    def slash(self, name, args, tools=None):
        """`/<name> args` typed in the CLI."""
        return self.hermes("slash", name, args, tools=tools)

    def message(self, name, args, choice=None):
        """`/<name> args` sent to a gateway (Telegram, Slack, ...); `choice` is the button the user taps when asked."""
        return self.hermes("message", name, args, choice=choice)

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
        self.endpoint("unused")  # a connected profile
        shown = self.slash("wisp", "what is my balance?",
                           {"mcp__wisp__ask_wisp": [answered("The balance is 42.")]})

        self.assertEqual(self.dispatched(), [["mcp__wisp__ask_wisp", {"task": "what is my balance?"}]])
        self.assertIn("The balance is 42.", shown)

    def test_wisp_on_running_asks_wisp_result_until_the_answer(self):
        self.endpoint("unused")  # a connected profile
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
        self.endpoint("unused")  # a connected profile
        shown = self.slash("wisp", "pay the bill", {"mcp__wisp__ask_wisp": [{"error": "Wisp is not signed in."}]})

        self.assertIn("Wisp is not signed in.", shown)

    def test_wisp_while_hermes_parked_wisp_says_wisp_is_not_answering_never_unknown_tool(self):
        self.endpoint("unused")
        # Hermes deregisters a parked server's tools.
        tools = {"mcp__wisp__ask_wisp": [{"error": "Unknown tool: mcp__wisp__ask_wisp"}]}

        shown = self.hermes("slash", "wisp", "pay the bill", tools=tools,
                            FAKE_HERMES_WISP_STATUS="failed", FAKE_HERMES_WISP_RECONNECTING="1")

        self.assertIn("Wisp is not answering", shown)
        self.assertNotIn("Unknown tool", shown)

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

    def asking_endpoint(self, answers):
        """A fake Wisp MCP endpoint as Wisp's is over Streamable HTTP: each `tools/call` is answered on its own SSE
        stream, in order, from `answers[tool]`: a `CallToolResult`, or for a call that parks on a Confirmation a
        function of the elicitation's action, asked after a ping, and only of a client that declared elicitation
        (else the function gets None, as Wisp's Run then runs under `policy`). Returns the client's answers to the
        endpoint's own requests, by id, and logs the calls to `calls`."""
        replies, calls, declared = {}, [], {}
        replied = threading.Condition()
        ids = itertools.count(1)

        class Mcp(http.server.BaseHTTPRequestHandler):
            def event(self, message):
                self.wfile.write(b"data: " + json.dumps(message).encode() + b"\n\n")
                self.wfile.flush()

            def do_POST(self):
                message = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if "method" not in message or "id" not in message:
                    with replied:
                        if "method" not in message:
                            replies[message["id"]] = message
                        replied.notify_all()
                    self.send_response(202)
                    self.end_headers()
                    return
                if message["method"] == "initialize":
                    session = f"m{next(ids)}"
                    declared[session] = message["params"]["capabilities"]
                    body = json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": {
                        "protocolVersion": "2025-06-18", "capabilities": {}, "serverInfo": {"name": "wisp"}}}).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Mcp-Session-Id", session)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                params = message["params"]
                calls.append([params["name"], params["arguments"]])
                # The plugin's load asks `wisp_zone` too.
                answer = (answers.get(params["name"]) or [{"content": []}]).pop(0)
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                if callable(answer):
                    action = None
                    if "elicitation" in declared.get(self.headers["Mcp-Session-Id"], {}):
                        ping, ask = f"p{next(ids)}", f"e{next(ids)}"
                        self.event({"jsonrpc": "2.0", "id": ping, "method": "ping"})
                        self.event({"jsonrpc": "2.0", "id": ask, "method": "elicitation/create", "params": {
                            "message": "Run bash_run: echo tg-ok", "requestedSchema": {"type": "object", "properties": {}}}})
                        with replied:
                            replied.wait_for(lambda: ask in replies and ping in replies, timeout=10)
                        action = ((replies.get(ask) or {}).get("result") or {}).get("action")
                    answer = answer(action)
                self.event({"jsonrpc": "2.0", "id": message["id"], "result": answer})

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
        self.calls = calls
        return replies

    def asked(self):
        try:
            return [json.loads(line) for line in (self.home / "choices.log").read_text().splitlines()]
        except OSError:
            return []

    def test_wisp_on_a_gateway_asks_its_confirmation_in_the_chat_and_allow_runs_it(self):
        replies = self.asking_endpoint({"ask_wisp": [
            lambda action: text("tg-ok" if action == "accept" else f"Denied ({action}): bash_run")]})

        shown = self.message("wisp", "Run in your bash exactly: echo tg-ok", choice="Allow for this task")

        self.assertEqual([question for question, _choices in self.asked()], ["Run bash_run: echo tg-ok"])
        self.assertIn("tg-ok", shown)
        self.assertEqual([r["result"] for r in replies.values() if "action" not in r["result"]], [{}])  # the ping's

    def test_wisp_on_a_gateway_refuses_on_deny_and_never_reports_an_unanswered_confirmation_as_a_decline(self):
        for choice, action in (("Deny", "decline"), (None, "cancel")):
            with self.subTest(choice=choice):
                self.asking_endpoint({"ask_wisp": [lambda action: text(f"Not run ({action}): bash_run")]})

                shown = self.message("wisp", "Run in your bash exactly: echo tg-ok", choice=choice)

                self.assertIn(f"Not run ({action}): bash_run", shown)

    def test_wisp_on_a_gateway_asks_wisp_result_until_the_answer(self):
        self.asking_endpoint({"ask_wisp": [text("still at work", run="r1")],
                              "wisp_result": [text("still at work", run="r1"), text("Three bills are due.")]})

        shown = self.message("wisp", "summarise my mail")

        self.assertEqual([call for call in self.calls if call[0] != "wisp_zone"], [
            ["ask_wisp", {"task": "summarise my mail"}], ["wisp_result", {"run": "r1"}], ["wisp_result", {"run": "r1"}]])
        self.assertIn("Three bills are due.", shown)

    def test_wisp_on_a_gateway_against_a_refusing_endpoint_says_wisp_is_not_answering_never_the_error(self):
        with socket.socket() as closed:
            closed.bind(("127.0.0.1", 0))
            port = closed.getsockname()[1]
        self.config["mcp_servers"] = {"wisp": {"url": f"http://127.0.0.1:{port}/mcp"}}
        (self.home / ".env").write_text(f"WISP_CREDENTIAL_TOKEN={CREDENTIAL}\n")

        shown = self.message("wisp", "summarise my mail")

        self.assertIn("Wisp is not answering", shown)
        self.assertNotIn("urlopen error", shown)

    def test_wisp_on_a_gateway_whose_connect_or_send_fails_for_any_reason_says_wisp_is_not_answering(self):
        # urllib wraps in a URLError only what fails before the request was sent: it never reached Wisp.
        for reason in ("TimeoutError()", "OSError(errno.EHOSTDOWN, 'Host is down')"):
            with self.subTest(reason=reason):
                self.config["mcp_servers"] = {"wisp": {"url": "http://127.0.0.1:9/mcp"}}
                (self.home / ".env").write_text(f"WISP_CREDENTIAL_TOKEN={CREDENTIAL}\n")

                shown = self.hermes("python", f"""
import errno, sys, urllib.error
sys.modules["__main__"].SURFACE = "telegram"
ctx = load_plugin()
def unreached(*args, **kwargs):
    raise urllib.error.URLError({reason})
sys.modules["hermes_plugins_wisp.commands"].call_tool = unreached
print(ctx.commands["wisp"]("pay the bill"))""")

                self.assertIn("Wisp is not answering", shown)
                self.assertNotIn("may still be running", shown)
                self.assertNotIn("urlopen error", shown)

    def test_wisp_on_a_gateway_that_cannot_reach_wisp_result_says_the_task_may_still_be_running(self):
        # The Run exists: "not answering, try again" would have the user start it twice.
        self.config["mcp_servers"] = {"wisp": {"url": "http://127.0.0.1:9/mcp"}}
        (self.home / ".env").write_text(f"WISP_CREDENTIAL_TOKEN={CREDENTIAL}\n")

        shown = self.hermes("python", """
import sys, urllib.error
sys.modules["__main__"].SURFACE = "telegram"
ctx = load_plugin()
def call_tool(url, credential, tool, args, **kwargs):
    if tool == "ask_wisp":
        return {"content": [{"type": "text", "text": "still at work"}], "structuredContent": {"run": "r1"}}
    raise urllib.error.URLError(TimeoutError())
sys.modules["hermes_plugins_wisp.commands"].call_tool = call_tool
print(ctx.commands["wisp"]("pay the bill"))""")

        self.assertNotIn("Wisp is not answering", shown)
        self.assertIn("may still be running", shown)

    def test_wisp_on_a_gateway_that_cannot_send_a_confirmations_answer_says_the_task_may_still_be_running(self):
        # The Run exists and waits on the Confirmation.
        self.asking_endpoint({"ask_wisp": [lambda action: text("paid")]})

        shown = self.hermes("python", """
import json, sys, urllib.error
sys.modules["__main__"].SURFACE = "telegram"
ctx = load_plugin()
client = sys.modules["hermes_plugins_wisp.mcp_client"]
opened = client._open
def unreached_answers(request, **kwargs):
    if request.data and "method" not in json.loads(request.data):
        raise urllib.error.URLError(ConnectionRefusedError())
    return opened(request, **kwargs)
client._open = unreached_answers
print(ctx.commands["wisp"]("pay the bill"))""", choice="Allow for this task")

        self.assertNotIn("Wisp is not answering", shown)
        self.assertIn("may still be running", shown)

    def test_wisp_on_a_gateway_that_outlasts_its_wait_after_wisp_took_it_says_it_timed_out_never_not_answering(self):
        # The Run exists: "not answering, try again" would have the user start it twice.
        self.asking_endpoint({"ask_wisp": [lambda action: time.sleep(2) or text("paid")]})

        shown = self.hermes("python", """
import sys
sys.modules["__main__"].SURFACE = "telegram"
ctx = load_plugin()
sys.modules["hermes_plugins_wisp.commands"].WAIT = 0.5
print(ctx.commands["wisp"]("pay the bill"))""", choice="Allow for this task")

        self.assertEqual([question for question, _choices in self.asked()], ["Run bash_run: echo tg-ok"])
        self.assertNotIn("Wisp is not answering", shown)
        self.assertIn("Wisp's ask_wisp failed", shown)
        self.assertIn("timed out", shown)
        self.assertIn("may still be running", shown)

    def test_wisp_on_a_gateway_without_a_connected_endpoint_says_so(self):
        self.assertIn("hermes wisp connect", self.message("wisp", "summarise my mail"))

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
