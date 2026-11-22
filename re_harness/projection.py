"""Validate and reconstruct worker results before evidence crosses into MCP."""

from . import policy


def invalid():
    return ValueError("worker_result_outside_contract")


def object_fields(value, fields):
    if not isinstance(value, dict) or value.keys() != fields:
        raise invalid()
    return value


def number(value, maximum=policy.MAX_ARTIFACT):
    if type(value) is not int or not 0 <= value <= maximum:
        raise invalid()
    return value


def boolean(value):
    if type(value) is not bool:
        raise invalid()
    return value


def technical_summary(value):
    mandatory = {"size", "format_hint", "strings_count", "strings_truncated"}
    if not mandatory <= value.keys() or value.keys() - mandatory - {"pe", "elf"}:
        raise invalid()
    kind = value["format_hint"]
    if kind not in ("PE candidate", "ELF", "ZIP candidate", "script", "unknown"):
        raise invalid()
    result = {"size": number(value["size"]), "format_hint": kind,
              "strings_count": number(value["strings_count"], 10000),
              "strings_truncated": boolean(value["strings_truncated"])}
    if "pe" in value and kind == "PE candidate":
        pe = object_fields(value["pe"], {"parsed", "sections_count", "import_libraries_count", "certificate_bytes"})
        result["pe"] = {"parsed": boolean(pe["parsed"]), **{
            field: number(pe[field], 0xFFFFFFFF)
            for field in ("sections_count", "import_libraries_count", "certificate_bytes")}}
    if "elf" in value and kind == "ELF":
        elf = object_fields(value["elf"], {"elf_class", "data_encoding", "machine"})
        result["elf"] = {field: number(elf[field], 65535) for field in elf}
    return result


def page(name, value, limit):
    other = "scan_truncated" if name == "artifact_strings" else "entries_returned"
    object_fields(value, {"rows", "has_more", other})
    rows = value["rows"]
    if not isinstance(rows, list) or len(rows) > limit:
        raise invalid()
    result = {"rows": [], "has_more": boolean(value["has_more"])}
    if name == "artifact_strings":
        result[other] = boolean(value[other])
        for row in rows:
            object_fields(row, {"offset", "encoding", "full_byte_length"})
            if row["encoding"] not in ("ascii", "utf-16le"):
                raise invalid()
            result["rows"].append({"offset": number(row["offset"]), "encoding": row["encoding"],
                                   "full_byte_length": number(row["full_byte_length"])})
    else:
        result[other] = number(value[other], limit)
        fields = ({"address", "entry", "entry_point"} if name == "ghidra_functions" else
                  {"from_address", "to_address", "from", "to", "address"})
        for row in rows:
            if not isinstance(row, dict) or not row or row.keys() - fields:
                raise invalid()
            if any(not policy.match(address, policy.ADDRESS) for address in row.values()):
                raise invalid()
            result["rows"].append(row)
    return result


def approved_excerpt(value):
    object_fields(value, {"trust", "text", "sha256_of_serialized_result", "serialized_bytes", "truncated"})
    if value["trust"] != "untrusted_sample_derived_data" or not isinstance(value["text"], str):
        raise invalid()
    if len(value["text"]) > policy.MAX_EXCERPT or any(not " " <= ch <= "~" for ch in value["text"]):
        raise invalid()
    if not policy.match(value["sha256_of_serialized_result"], policy.DIGEST):
        raise invalid()
    return {**value, "serialized_bytes": number(value["serialized_bytes"], 2**32 - 1),
            "truncated": boolean(value["truncated"])}


def project(reply, name, arguments, include):
    required = {"tool", "artifact", "artifact_bytes", "summary"}
    if include and name != "artifact_summary":
        required.add("evidence_excerpt")
    object_fields(reply, required)
    if reply["tool"] != name or reply["artifact"] != arguments["artifact"]:
        raise invalid()
    summary = reply["summary"]
    if not isinstance(summary, dict):
        raise invalid()
    if name == "artifact_summary":
        summary = technical_summary(summary)
    elif name in policy.PAGED:
        summary = page(name, summary, arguments["limit"])
    else:
        object_fields(summary, {"provider_response", "top_level_fields"})
        if summary["provider_response"] != "structured":
            raise invalid()
        summary = {"provider_response": "structured", "top_level_fields": number(summary["top_level_fields"], 10000)}
    result = {"tool": name, "artifact": arguments["artifact"], "artifact_bytes": number(reply["artifact_bytes"]),
              "summary": summary}
    if "evidence_excerpt" in required:
        result["evidence_excerpt"] = approved_excerpt(reply["evidence_excerpt"])
    return result
