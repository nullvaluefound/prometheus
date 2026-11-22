"""Static provider calls. This module runs inside the disconnected worker."""

import asyncio
from contextlib import nullcontext
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from .policy import ADDRESS, match

GHIDRA_TOOLS = {
    "ghidra_functions": "list_functions",
    "ghidra_xrefs": "get_xrefs_to",
    "ghidra_decompile": "decompile_function_by_address",
}
MAX_PROVIDER_RESPONSE = 2 * 1024 * 1024


def provider_object(raw):
    if len(raw) > MAX_PROVIDER_RESPONSE:
        raise ValueError("provider_response_too_large")
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("provider_response_shape")
    return obj


async def ghidra(name, path, options, diagnostics):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    server = StdioServerParameters(command="ghidra-mcp", env=dict(os.environ), args=[
        "--headless", "--binary", str(path), "--discard", "--ready-timeout", "105",
    ])
    log = nullcontext(sys.stderr) if diagnostics else open(os.devnull, "w", encoding="utf-8")
    with log as err:
        async with stdio_client(server, errlog=err) as streams:
            async with ClientSession(*streams) as session:
                await session.initialize()
                result = await session.call_tool(GHIDRA_TOOLS[name], options)
                if result.isError:
                    if diagnostics:
                        print(result.content, file=sys.stderr)
                    raise ValueError("ghidra_tool_error")
                if result.structuredContent is not None:
                    return provider_object(json.dumps(result.structuredContent))
                if len(result.content) == 1 and result.content[0].type == "text":
                    return provider_object(result.content[0].text)
                raise ValueError("ghidra_response_shape")


def rea(name, path, options, diagnostics):
    action = "inspect" if name == "rea_inspect" else "decompile"
    args = ["rea", action, str(path)]
    if action == "decompile":
        args.append(options["address"])
    with tempfile.TemporaryFile() as out:
        proc = subprocess.run(args + ["--provider", "ghidra", "--json"], stdin=subprocess.DEVNULL,
                              stdout=out, stderr=None if diagnostics else subprocess.DEVNULL, timeout=125, check=False)
        if proc.returncode:
            raise ValueError("rea_tool_error")
        out.seek(0)
        obj = provider_object(out.read(MAX_PROVIDER_RESPONSE + 1))
        if obj.get("status") in ("error", "failed", "blocked", "unsupported") or obj.get("isError"):
            raise ValueError("rea_tool_error")
        return obj


def require_native(path):
    with Path(path).open("rb") as stream:
        head = stream.read(4096)
    if head.startswith(b"\x7fELF"):
        valid = len(head) >= 52 and head[4] in (1, 2) and head[5] in (1, 2)
    elif head.startswith(b"MZ") and len(head) >= 64:
        offset = int.from_bytes(head[60:64], "little")
        valid = offset >= 64 and head[offset:offset + 4] == b"PE\x00\x00"
    else:
        valid = head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe",
                           b"\xcf\xfa\xed\xfe") and len(head) >= 32
    if not valid:
        raise ValueError("unsupported_native_header")


def safe_address(value):
    if isinstance(value, str) and re.fullmatch(r"(?:0x)?[0-9a-fA-F]{1,16}", value):
        address = hex(int(value, 16))
        if match(address, ADDRESS):
            return address
    return None


def ghidra_index(name, payload, limit):
    items = payload.get("items")
    if not isinstance(items, list):
        raise ValueError("ghidra_page_shape")
    if name == "ghidra_functions":
        fields = ("address", "entry", "entry_point")
    else:
        fields = ("from_address", "to_address", "from", "to", "address")
    rows = []
    for item in items[:limit]:
        if not isinstance(item, dict):
            continue
        row = {field: converted for field in fields if (converted := safe_address(item.get(field)))}
        if row:
            rows.append(row)
    return {"rows": rows, "entries_returned": min(len(items), limit),
            "has_more": payload.get("has_more") is True}


def run(name, path, options, diagnostics=False):
    require_native(path)
    if name in GHIDRA_TOOLS:
        return asyncio.run(asyncio.wait_for(ghidra(name, path, options, diagnostics), timeout=125))
    return rea(name, path, options, diagnostics)
