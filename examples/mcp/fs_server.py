"""A tiny MCP filesystem server for the reader.sipar demo (stdlib Python, stdio, newline-delimited JSON-RPC).

It speaks both MCP 2026-07-28 (server/discover) and 2025-11-25 (initialize) and offers two read-only tools,
read_text_file(path) and list_directory(path), limited to the folder it runs in. It is a stand-in for
`npx -y @modelcontextprotocol/server-filesystem DIR`, so the demo runs without Node.js or a network."""
import json
import os
import sys

NEW, OLD = "2026-07-28", "2025-11-25"
PV = "io.modelcontextprotocol/protocolVersion"
PATH = {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}
TOOLS = [{"name": "read_text_file", "description": "Read a text file and return its contents.", "inputSchema": PATH},
         {"name": "list_directory", "description": "List the entries of a directory.", "inputSchema": PATH}]
ROOT = os.path.realpath(os.getcwd())


def send(rid, result=None, error=None):
    msg = {"jsonrpc": "2.0", "id": rid}
    msg.update({"error": error} if error else {"result": result})
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def safe(path):
    p = os.path.realpath(os.path.join(ROOT, str(path)))
    if p != ROOT and not p.startswith(ROOT + os.sep):
        raise ValueError(f"access denied: {path} is outside {ROOT}")
    return p


def call(name, args):
    if name == "read_text_file":
        with open(safe(args["path"]), encoding="utf-8") as f:
            return f.read()
    p = safe(args["path"])
    return "\n".join(("[DIR] " if os.path.isdir(os.path.join(p, e)) else "[FILE] ") + e for e in sorted(os.listdir(p)))


def handle(msg):
    method, rid, params = msg.get("method"), msg.get("id"), msg.get("params") or {}
    if rid is None or method is None:
        return                                    # notifications and replies
    modern = PV in (params.get("_meta") or {})
    if method == "server/discover":
        return send(rid, {"supportedVersions": [NEW], "capabilities": {"tools": {}}})
    if method == "initialize":
        return send(rid, {"protocolVersion": OLD, "capabilities": {"tools": {}},
                          "serverInfo": {"name": "demo-fs", "version": "1"}})
    if method == "ping":
        return send(rid, {})
    if method == "tools/list":
        return send(rid, {"tools": TOOLS})
    if method == "tools/call":
        try:
            res = {"content": [{"type": "text", "text": call(params.get("name"), params.get("arguments") or {})}]}
        except (OSError, ValueError, KeyError) as e:
            res = {"content": [{"type": "text", "text": f"Error: {e}"}], "isError": True}
        if modern:
            res["resultType"] = "complete"
        return send(rid, res)
    send(rid, error={"code": -32601, "message": f"Method not found: {method}"})


for line in sys.stdin:
    if line.strip():
        try:
            handle(json.loads(line))
        except ValueError:
            send(None, error={"code": -32700, "message": "Parse error"})
