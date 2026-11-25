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

from . import policy
from .policy import ADDRESS, match

GHIDRA_TOOLS = {
    "ghidra_functions": "list_functions",
    "ghidra_xrefs": "get_xrefs_to",
    "ghidra_decompile": "decompile_function_by_address",
}
MAX_PROVIDER_RESPONSE = 2 * 1024 * 1024
YARA_TIMEOUT = 60
YARA_MATCH_DATA = 64
MAX_YARA_RULES_MATCHED = 512
MAX_YARA_STRINGS = 32
MAX_YARA_INSTANCES = 8
CAPA = Path("/opt/capa")
CAPA_TIMEOUT = 240
MAX_CAPA_RESPONSE = 64 * 1024 * 1024
MAX_CAPA_ADDRESSES = 64


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


def quiet(_message):
    return None


def yara_compile(source):
    """Compile operator rules with includes off and only the data-parsing modules."""
    import yara

    if len(source) > policy.MAX_YARA_RULES:
        raise ValueError("yara_rules_too_large")
    rules = yara.compile(source=source.decode("utf-8"), includes=False, error_on_warning=False)
    yara_match(rules, data=b"")
    return rules


def yara_match(rules, **target):
    import yara

    def module(data):
        if data.get("module") not in policy.YARA_MODULES:
            raise ValueError("yara_module_not_allowed")
        return yara.CALLBACK_CONTINUE

    yara.set_config(max_match_data=YARA_MATCH_DATA)
    return rules.match(**target, timeout=YARA_TIMEOUT, modules_callback=module, console_callback=quiet)


def yara_meta(meta):
    values = {}
    for key, value in list(meta.items())[:32]:
        if match(key, policy.YARA_IDENTIFIER) and type(value) in (str, int, bool):
            values[key] = value[:256] if isinstance(value, str) else value
    return values


def yara_scan(rules_path, path, options):
    matches = yara_match(yara_compile(Path(rules_path).read_bytes()), filepath=str(path))
    rows = []
    for item in matches[:MAX_YARA_RULES_MATCHED]:
        strings = [{"identifier": found.identifier, "instances": len(found.instances),
                    "matches": [{"offset": hit.offset, "length": hit.matched_length,
                                 "data_hex": bytes(hit.matched_data).hex()}
                                for hit in found.instances[:MAX_YARA_INSTANCES]]}
                   for found in item.strings[:MAX_YARA_STRINGS]]
        rows.append({"rule": item.rule, "namespace": item.namespace, "tags": list(item.tags)[:16],
                     "meta": yara_meta(item.meta), "strings": strings})
    rows.sort(key=lambda row: (row["namespace"], row["rule"]))
    start, limit = options["offset"], options["limit"]
    page = rows[start:start + limit]
    summary = {"rows": [{"rule": row["rule"], "namespace": row["namespace"], "tags": row["tags"],
                         "strings": [{"identifier": found["identifier"], "instances": found["instances"],
                                      "matches": [{"offset": hit["offset"], "length": hit["length"]}
                                                  for hit in found["matches"]]}
                                     for found in row["strings"]]} for row in page],
               "has_more": start + len(page) < len(rows), "matched_rules": len(rows),
               "matches_truncated": len(matches) > MAX_YARA_RULES_MATCHED}
    return summary, {"matches": page}


def capa_ids(entries, pattern):
    if not isinstance(entries, list):
        return []
    return sorted({entry["id"] for entry in entries if isinstance(entry, dict) and match(entry.get("id"), pattern)})[:16]


def capa_address(value):
    if isinstance(value, dict) and value.get("type") == "absolute" and type(value.get("value")) is int:
        if 0 <= value["value"] < 2**64:
            return hex(value["value"])
    return None


def capa_enum(value):
    return value if match(value, policy.CAPA_ENUM) else "unknown"


def capa_triage(path, options, diagnostics=False):
    require_native(path)
    env = {**os.environ, "XDG_CACHE_HOME": str(CAPA / "cache")}
    with tempfile.TemporaryFile() as out:
        proc = subprocess.run(["capa", "-q", "-j", "-r", str(CAPA / "rules"), "-s", str(CAPA / "sigs"), str(path)],
                              stdin=subprocess.DEVNULL, stdout=out, stderr=None if diagnostics else subprocess.DEVNULL,
                              env=env, timeout=CAPA_TIMEOUT, check=False)
        if proc.returncode:
            raise ValueError("capa_tool_error")
        out.seek(0)
        raw = out.read(MAX_CAPA_RESPONSE + 1)
    if len(raw) > MAX_CAPA_RESPONSE:
        raise ValueError("provider_response_too_large")
    document = json.loads(raw)
    analysis = document["meta"]["analysis"]
    rows, limitations, withheld = [], [], 0
    for name, item in document["rules"].items():
        meta = item["meta"]
        namespace = meta.get("namespace") or ""
        if meta.get("lib") or meta.get("is_subscope_rule"):
            continue
        if not match(name, policy.CAPA_TEXT) or (namespace and not match(namespace, policy.CAPA_NAMESPACE)):
            withheld += 1
            continue
        if namespace.startswith("internal/limitation/"):
            limitations.append(name)
            continue
        if namespace.startswith("internal/"):
            continue
        addresses = [found for pair in item["matches"] if (found := capa_address(pair[0]))]
        description = meta.get("description")
        rows.append({"rule": name, "namespace": namespace, "attack": capa_ids(meta.get("attack"), policy.ATTACK_ID),
                     "mbc": capa_ids(meta.get("mbc"), policy.MBC_ID), "matches": len(item["matches"]),
                     "addresses": addresses[:MAX_CAPA_ADDRESSES],
                     "description": description[:512] if isinstance(description, str) else ""})
    rows.sort(key=lambda row: (row["namespace"], row["rule"]))
    start, limit = options["offset"], options["limit"]
    page = rows[start:start + limit]
    layout = analysis.get("layout") if isinstance(analysis.get("layout"), dict) else {}
    functions = layout.get("functions") if isinstance(layout.get("functions"), list) else []
    summary = {"rows": [{**{key: row[key] for key in ("rule", "namespace", "attack", "mbc", "matches")},
                         "addresses": row["addresses"][:8]} for row in page],
               "has_more": start + len(page) < len(rows), "capabilities": len(rows),
               "limitations": sorted(limitations)[:16], "rules_withheld": withheld,
               "format": capa_enum(analysis.get("format")), "arch": capa_enum(analysis.get("arch")),
               "os": capa_enum(analysis.get("os"))}
    detail = {"base_address": capa_address(analysis.get("base_address")), "functions_with_matches": len(functions),
              "capa_version": document["meta"].get("version"), "capabilities": page}
    return summary, detail
