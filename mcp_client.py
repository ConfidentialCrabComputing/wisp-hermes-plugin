"""The plugin's own short MCP client: one tool call on Wisp's endpoint over Streamable HTTP.

It runs before Hermes connects its MCP servers (at the plugin's load) and from `/wisp_model`, so it
cannot borrow Hermes's client. Standard library only. ponytail: no elicitation and no ping replies, which
only `ask_wisp` and `wisp_result` need; Hermes's own client makes those calls."""

import json
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


def call_tool(url, credential, name, arguments=None, timeout=5.0):
    """The `CallToolResult` of tool `name`; raises `McpError` for a refusal or a tool error and `OSError`
    when the endpoint cannot be reached."""
    session = {}

    def send(message, method="POST"):
        headers = {"Authorization": f"Bearer {credential}", "Accept": "application/json, text/event-stream"}
        if session:
            headers.update({"Mcp-Session-Id": session["id"], "Mcp-Protocol-Version": PROTOCOL_VERSION})
        data = None
        if message is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(message).encode()
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        with _open(request, timeout=timeout) as response:
            if "id" not in session and response.headers.get("Mcp-Session-Id"):
                session["id"] = response.headers["Mcp-Session-Id"]
            if message is None or "id" not in message:
                return None
            return _answer(response, message["id"])

    initialized = send({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                   "clientInfo": {"name": "wisp-hermes-plugin", "version": "1"}},
    })
    if "result" not in initialized:
        raise McpError(f"initialize refused: {initialized.get('error')}")
    try:
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        called = send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                       "params": {"name": name, "arguments": arguments or {}}})
    finally:
        if session:
            try:
                send(None, method="DELETE")
            except OSError:
                pass
    if "result" not in called:
        raise McpError(f"{name} refused: {called.get('error')}")
    result = called["result"]
    if result.get("isError"):
        raise McpError(" ".join(c.get("text", "") for c in result.get("content", [])) or f"{name} failed")
    return result


def _answer(response, request_id):
    """The JSON-RPC response to `request_id`, from a JSON body or an SSE stream (skipping the server's
    own requests and notifications)."""
    if response.headers.get_content_type() == "application/json":
        return json.load(response)
    for line in response:
        if not line.startswith(b"data:"):
            continue
        message = json.loads(line[5:])
        if "method" not in message and message.get("id") == request_id:
            return message
    raise McpError("the endpoint closed the stream without an answer")
