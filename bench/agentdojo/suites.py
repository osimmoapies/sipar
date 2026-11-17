"""Per-suite configuration: which tools are readonly, and the Sipar header (allow lines + types)."""
import enum
import inspect
import os
import sys
import types
import typing
from pathlib import Path

from agentdojo.task_suite.load_suites import get_suite
from pydantic import BaseModel

VERSION = "v1.2.2"
HERE = Path(__file__).resolve().parent
PY = sys.executable

# A tool is readonly only when calling it with attacker-chosen arguments is harmless (SPEC §7a).
READONLY = {
    "banking": ["get_iban", "get_balance", "get_most_recent_transactions", "get_scheduled_transactions",
                "read_file", "get_user_info"],
}


def sipar_type(t, records):
    """Map a Python annotation to a Sipar type; collects pydantic records into `records`."""
    origin = typing.get_origin(t)
    args = typing.get_args(t)
    if t is str:
        return "Str"
    if t is bool:
        return "Bool"
    if t is int:
        return "Int"
    if t is float:
        return "Float"
    if t is type(None) or t is None:
        return "None"
    if origin in (list, typing.List, tuple):
        return f"List[{sipar_type(args[0], records)}]"
    if origin in (dict, typing.Dict):
        return f"Map[{sipar_type(args[1], records)}]"
    if origin in (typing.Union, types.UnionType):
        rest = [a for a in args if a is not type(None)]
        inner = sipar_type(rest[0], records) if len(rest) == 1 else "Str"
        return inner + "?" if type(None) in args else inner
    if inspect.isclass(t) and issubclass(t, enum.Enum):
        return "Str"
    if inspect.isclass(t) and issubclass(t, BaseModel):
        name = t.__name__
        if name not in records:
            records[name] = None  # reserve (recursion guard)
            fields = []
            for fname, finfo in t.model_fields.items():
                fields.append(f"{fname}: {sipar_type(finfo.annotation, records)}")
            records[name] = "type " + name + " = { " + ", ".join(fields) + " }"
        return name
    return "Str"  # datetime, date and other scalars arrive as JSON strings


def suite_info(name):
    suite = get_suite(VERSION, name)
    records = {}
    sigs = []
    ro = READONLY[name]
    for f in suite.tools:
        params = []
        fn = f.run
        hints = typing.get_type_hints(fn, include_extras=False)
        for pname, field in f.parameters.model_fields.items():
            pt = sipar_type(field.annotation, records)
            opt = "" if field.is_required() else " (optional)"
            params.append(f"{pname}: {pt}{opt}")
        ret = sipar_type(hints.get("return", str), records)
        kind = "readonly" if f.name in ro else "NOT readonly (every argument must be trusted)"
        desc = " ".join(f.description.split())
        sigs.append(f"mcp.dojo.{f.name}({', '.join(params)}) -> {ret}   // {kind}. {desc}")
    tools = [f.name for f in suite.tools]
    header = (
        "allow ai\nallow io\n"
        f'allow mcp "dojo" ["{PY}", "{HERE / "dojo_mcp.py"}", "{name}"]\n'
        "    tools [" + ", ".join(f'"{t}"' for t in tools) + "]\n"
        "    readonly [" + ", ".join(f'"{t}"' for t in ro) + "]\n"
    )
    types_ = "\n".join(r for r in records.values() if r)
    return {"suite": suite, "header": header, "types": types_, "sigs": sigs}


if __name__ == "__main__":
    info = suite_info(sys.argv[1] if len(sys.argv) > 1 else "banking")
    print(info["header"])
    print(info["types"])
    print("\n".join(info["sigs"]))
