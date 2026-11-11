"""The plugin's own short MCP client: one tool call on Wisp's endpoint over Streamable HTTP.

It runs before Hermes connects its MCP servers (at the plugin's load), from `/wisp-model`, and from `/wisp` on a
gateway, where Hermes's client has no one to ask a Confirmation of (a command runs outside an agent turn), so this one
asks it itself. Standard library only."""

import http.client
import ipaddress
import json
import queue
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

PROTOCOL_VERSION = "2025-06-18"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect would carry the credential's header to wherever it points; refused (an HTTPError)."""

    def redirect_request(self, *args, **kwargs):
        return None


# No proxy: an `HTTP_PROXY` would get the credential's header in the clear, even for a loopback URL over
# an `ssh -L` tunnel. Hermes's own MCP transport never proxies loopback either.
_open = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect).open


class McpError(Exception):
    """The endpoint answered, but not with the tool's result."""


def loopback(url):
    """Whether `url` names this machine's loopback; a malformed one does not."""
    host = urllib.parse.urlsplit(url or "").hostname
    try:
        return host == "localhost" or ipaddress.ip_address(host or "").is_loopback
    except ValueError:
        return False


def refuses(url, timeout=1.0):
    """Whether nothing listens on a loopback `url` (a Runtime stopped or restarting, or an `ssh -L` tunnel down).
    A slow endpoint is not refusing, and another host's is never probed: Hermes may reach it through a proxy this
    would not take, and Hermes's own client tells of it."""
    if not loopback(url):
        return False
    parts = urllib.parse.urlsplit(url)
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        return False
    try:
        socket.create_connection((parts.hostname, port), timeout=timeout).close()
    except ConnectionError:
        return True
    except OSError:
        return False
    return False


def call_tool(url, credential, name, arguments=None, timeout=5.0, elicit=None):
    """The `CallToolResult` of tool `name`; raises `McpError` for a refusal or a tool error and `OSError`
    when the endpoint cannot be reached or its answer breaks off, or `TimeoutError` when the whole call outlasts
    `timeout`. With `elicit`, the client declares elicitation and answers each of the server's form elicitations with
    `elicit(message)`: "accept", "decline" or "cancel"."""
    session = {}
    deadline = time.monotonic() + timeout

    def left():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"{name} took longer than {timeout:g} s")
        return remaining

    def send(message, method="POST"):
        headers = {"Authorization": f"Bearer {credential}", "Accept": "application/json, text/event-stream"}
        if session:
            headers.update({"Mcp-Session-Id": session["id"], "Mcp-Protocol-Version": PROTOCOL_VERSION})
        data = None
        if message is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(message).encode()
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with _open(request, timeout=left()) as response:
                if "id" not in session and response.headers.get("Mcp-Session-Id"):
                    session["id"] = response.headers["Mcp-Session-Id"]
                if message is None or "id" not in message or "method" not in message:
                    return None  # a notification or our answer to a request of the server's
                return _answer(response, message["id"], left, reply)
        except http.client.HTTPException as exc:
            # An answer broken off or not HTTP, after the request was sent: a network failure, as every caller takes it.
            raise OSError(f"the endpoint's answer broke off or was not HTTP ({exc!r})") from exc

    def reply(request):
        """Our answer to the server's own `request`, sent while its stream waits on it."""
        params = request.get("params") if isinstance(request.get("params"), dict) else {}
        if request["method"] == "ping":
            answer = {"result": {}}
        elif request["method"] == "elicitation/create" and elicit and params.get("mode", "form") == "form":
            action = elicit(str(params.get("message") or ""))
            answer = {"result": {"action": action, **({"content": {}} if action == "accept" else {})}}
        else:
            answer = {"error": {"code": -32601, "message": f"{request['method']} is not supported"}}
        try:
            send({"jsonrpc": "2.0", "id": request["id"], **answer})
        except urllib.error.URLError as exc:
            # Not a URLError: the tool call reached the endpoint already, unlike a connect that fails before it.
            raise OSError(f"the answer to {request['method']} could not be sent: {exc}") from exc

    initialized = _object(send({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {"elicitation": {}} if elicit else {},
                   "clientInfo": {"name": "wisp-hermes-plugin", "version": "1"}},
    }), "initialize's answer")
    if "result" not in initialized:
        raise McpError(f"initialize refused: {initialized.get('error')}")
    try:
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        called = _object(send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                               "params": {"name": name, "arguments": arguments or {}}}), f"{name}'s answer")
    finally:
        if session:
            try:
                send(None, method="DELETE")
            except OSError:
                pass
    if "result" not in called:
        raise McpError(f"{name} refused: {called.get('error')}")
    result = _object(called["result"], f"{name}'s result")
    content = result.get("content", [])
    if not isinstance(content, list) or not all(isinstance(c, dict) for c in content):
        raise McpError(f"{name}'s content is not a list of objects")
    if result.get("isError"):
        raise McpError(" ".join(c.get("text", "") for c in content) or f"{name} failed")
    return result


def _object(value, what):
    if not isinstance(value, dict):
        raise McpError(f"{what} is not an object")
    return value


def _chunks(response, left):
    """The body as it arrives, `left()` checked before each read. ponytail: a stalled read of a JSON body is bounded
    only by the socket timeout `left()` gave at the open (up to twice `timeout` in all), and headers dripped byte by
    byte not at all; reading them on a thread, as `_answer` reads a stream, would bound both, if an endpoint ever
    does that."""
    while True:
        left()
        if not (chunk := response.read1(65536)):
            return
        yield chunk


def _lines(response, left):
    rest = b""
    for chunk in _chunks(response, left):
        *lines, rest = (rest + chunk).split(b"\n")
        yield from lines
    yield rest


def _answer(response, request_id, left, reply):
    """The JSON-RPC response to `request_id`, from a JSON body or an SSE stream (skipping the server's
    notifications, and handing its own requests to `reply`)."""
    if response.headers.get_content_type() == "application/json":
        return json.loads(b"".join(_chunks(response, left)))
    # The stream is read on a thread of its own and an elicitation asked on another: the server's pings are answered
    # while the user takes their time, as the server takes an unanswered one for a dropped connection. Either thread's
    # failure comes back here, where it ends the call.
    events = queue.Queue()
    closed = McpError("the endpoint closed the stream without an answer")
    if response.isclosed():  # an empty body: no socket left to read
        raise closed

    def background(work):
        def run():
            try:
                work()
            except BaseException as exc:
                events.put(exc)
        threading.Thread(target=run, daemon=True).start()

    def read():
        for line in _lines(response, left):
            events.put(line)
        events.put(closed)

    # One asker, the elicitations in turn, as the server asks them: an endpoint sending many gets no thread or
    # question in the chat per elicitation, and none is asked once the call has ended.
    asks, ended = queue.Queue(), threading.Event()

    def ask():
        while (message := asks.get()) is not None and not ended.is_set():
            reply(message)

    # A duplicate of the connection's socket, taken before the reader can end it (its family plays no part).
    stream = socket.fromfd(response.fileno(), socket.AF_INET, socket.SOCK_STREAM)
    background(read)
    background(ask)
    try:
        while True:
            try:
                line = events.get(timeout=left())
            except queue.Empty:
                continue  # left() raises the call's TimeoutError
            if isinstance(line, BaseException):
                raise line
            if not line.startswith(b"data:"):
                continue
            message = json.loads(line[5:])
            if not isinstance(message, dict):
                continue
            if "method" in message:
                if "id" in message and isinstance(message["method"], str):
                    if message["method"] == "elicitation/create":
                        asks.put(message)
                    else:
                        reply(message)
            elif message.get("id") == request_id:
                return message
    finally:
        ended.set()
        asks.put(None)
        # Ends the reader's read: the response's close would otherwise wait on it until the stream next speaks.
        with stream:
            try:
                stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass  # the server closed it already
