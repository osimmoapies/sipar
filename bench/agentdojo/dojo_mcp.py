"""A stdio MCP server that exposes one AgentDojo suite's tools to a Sipar program.

Run as: python dojo_mcp.py <suite> [state.pkl] [calls.jsonl]
The environment is loaded from state.pkl (default ./state.pkl in the working folder) before every call
and saved after it, so the benchmark harness can read the final environment when the program ends.
Every call is appended to calls.jsonl (default ./calls.jsonl) for the function-call trace.
"""
import json
import pickle
import sys

from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite
from pydantic import BaseModel

VERSION = "v1.2.2"


def to_jsonable(x):
    if isinstance(x, BaseModel):
        return x.model_dump(mode="json")
    if isinstance(x, (list, tuple)):
        return [to_jsonable(v) for v in x]
    if isinstance(x, dict):
        return {str(k): to_jsonable(v) for k, v in x.items()}
    return x


def main():
    suite_name = sys.argv[1]
    state = sys.argv[2] if len(sys.argv) > 2 else "state.pkl"
    log = sys.argv[3] if len(sys.argv) > 3 else "calls.jsonl"
    suite = get_suite(VERSION, suite_name)
    runtime = FunctionsRuntime(suite.tools)
    tools = []
    for f in suite.tools:
        schema = f.parameters.model_json_schema()
        schema.pop("title", None)
        tools.append({"name": f.name, "description": f.description, "inputSchema": schema})

    def reply(mid, result=None, error=None):
        msg = {"jsonrpc": "2.0", "id": mid}
        if error is not None:
            msg["error"] = error
        else:
            msg["result"] = result
        sys.stdout.write(json.dumps(msg) + "\n")
        sys.stdout.flush()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req = json.loads(line)
        mid = req.get("id")
        method = req.get("method")
        if mid is None:
            continue  # a notification
        if method == "initialize":
            reply(mid, {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}},
                        "serverInfo": {"name": "agentdojo-" + suite_name, "version": "0.1"}})
        elif method == "tools/list":
            reply(mid, {"tools": tools})
        elif method == "tools/call":
            p = req.get("params") or {}
            name, args = p.get("name"), p.get("arguments") or {}
            with open(state, "rb") as fh:
                env = pickle.load(fh)
            result, err = runtime.run_function(env, name, args)
            with open(state, "wb") as fh:
                pickle.dump(env, fh)
            with open(log, "a") as fh:
                fh.write(json.dumps({"function": name, "args": args, "error": err}) + "\n")
            if err is not None:
                reply(mid, {"content": [{"type": "text", "text": err}], "isError": True})
            else:
                data = to_jsonable(result)
                text = data if isinstance(data, str) else json.dumps(data)
                out = {"content": [{"type": "text", "text": text}]}
                if isinstance(data, dict):
                    out["structuredContent"] = data
                reply(mid, out)
        elif method == "ping":
            reply(mid, {})
        else:
            reply(mid, error={"code": -32601, "message": "method not found: " + str(method)})


if __name__ == "__main__":
    main()
