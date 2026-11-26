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


HEX16 = r"0x[0-9a-f]{1,4}"
HEX32 = r"0x[0-9a-f]{1,8}"
HEX64 = r"0x[0-9a-f]{1,16}"
MAX_SECTIONS = 96
PE_COUNTS = {"parsed", "sections_count", "import_libraries_count", "certificate_bytes"}
PE_HEADER = {"machine", "entry_rva", "image_base", "overlay_offset", "sections"}
SECTION = {"rva", "raw_offset", "raw_size", "virtual_size", "flags", "entropy"}
ELF_IDENT = {"elf_class", "data_encoding", "machine"}
ELF_HEADER = {"e_type", "e_entry", "phnum", "shnum"}


def entropy(value):
    if type(value) is not float or not 0.0 <= value <= 8.0 or round(value, 3) != value:
        raise invalid()
    return value


def pe_summary(value):
    if not isinstance(value, dict) or type(value.get("parsed")) is not bool:
        raise invalid()
    pe = object_fields(value, PE_COUNTS | PE_HEADER if value["parsed"] else PE_COUNTS)
    result = {"parsed": pe["parsed"], **{
        field: number(pe[field], 0xFFFFFFFF) for field in ("sections_count", "import_libraries_count", "certificate_bytes")}}
    if not pe["parsed"]:
        return result
    sections = listed(pe["sections"], MAX_SECTIONS)
    if len(sections) != min(result["sections_count"], MAX_SECTIONS):
        raise invalid()
    overlay = pe["overlay_offset"]
    result.update({"machine": text(pe["machine"], HEX16), "entry_rva": text(pe["entry_rva"], HEX32),
                   "image_base": text(pe["image_base"], HEX64),
                   "overlay_offset": None if overlay is None else number(overlay),
                   "sections": [{"rva": text(section["rva"], HEX32), "raw_offset": number(section["raw_offset"], 0xFFFFFFFF),
                                 "raw_size": number(section["raw_size"], 0xFFFFFFFF),
                                 "virtual_size": number(section["virtual_size"], 0xFFFFFFFF),
                                 "flags": text(section["flags"], HEX32), "entropy": entropy(section["entropy"])}
                                for section in sections if object_fields(section, SECTION)]})
    return result


def elf_summary(value):
    if not isinstance(value, dict) or value.keys() not in (ELF_IDENT, ELF_IDENT | ELF_HEADER):
        raise invalid()
    result = {field: number(value[field], 65535) for field in value if field != "e_entry"}
    if "e_entry" in value:
        result["e_entry"] = number(value["e_entry"], 2**64 - 1)
    return result


def technical_summary(value):
    mandatory = {"size", "format_hint", "strings_count", "strings_truncated"}
    if not mandatory <= value.keys() or value.keys() - mandatory - {"pe", "elf", "macho"}:
        raise invalid()
    kind = value["format_hint"]
    if kind not in ("PE candidate", "ELF", "Mach-O", "Mach-O universal", "ZIP candidate", "script", "unknown"):
        raise invalid()
    result = {"size": number(value["size"]), "format_hint": kind,
              "strings_count": number(value["strings_count"], 10000),
              "strings_truncated": boolean(value["strings_truncated"])}
    if "pe" in value and kind == "PE candidate":
        result["pe"] = pe_summary(value["pe"])
    if "elf" in value and kind == "ELF":
        result["elf"] = elf_summary(value["elf"])
    if "macho" in value and kind == "Mach-O":
        macho = object_fields(value["macho"], {"cputype", "filetype"})
        result["macho"] = {field: number(macho[field], 0xFFFFFFFF) for field in ("cputype", "filetype")}
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


def listed(value, maximum):
    if not isinstance(value, list) or len(value) > maximum:
        raise invalid()
    return value


def text(value, pattern):
    if not policy.match(value, pattern):
        raise invalid()
    return value


def yara_page(value, limit, rules):
    object_fields(value, {"rows", "has_more", "matched_rules", "matches_truncated", "rules_sha256"})
    if not policy.match(rules, policy.DIGEST) or value["rules_sha256"] != rules:
        raise invalid()
    rows = []
    for row in listed(value["rows"], limit):
        object_fields(row, {"rule", "namespace", "tags", "strings"})
        strings = []
        for found in listed(row["strings"], 32):
            object_fields(found, {"identifier", "instances", "matches"})
            hits = [{"offset": number(hit["offset"]), "length": number(hit["length"])}
                    for hit in listed(found["matches"], 8) if object_fields(hit, {"offset", "length"})]
            strings.append({"identifier": text(found["identifier"], policy.YARA_STRING),
                            "instances": number(found["instances"], 2**32 - 1), "matches": hits})
        rows.append({"rule": text(row["rule"], policy.YARA_IDENTIFIER),
                     "namespace": text(row["namespace"], policy.YARA_IDENTIFIER),
                     "tags": [text(tag, policy.YARA_IDENTIFIER) for tag in listed(row["tags"], 16)],
                     "strings": strings})
    return {"rows": rows, "has_more": boolean(value["has_more"]), "matched_rules": number(value["matched_rules"], 512),
            "matches_truncated": boolean(value["matches_truncated"]), "rules_sha256": rules}


def capa_page(value, limit):
    object_fields(value, {"rows", "has_more", "capabilities", "limitations", "rules_withheld", "format", "arch", "os"})
    rows = []
    for row in listed(value["rows"], limit):
        object_fields(row, {"rule", "namespace", "attack", "mbc", "matches", "addresses"})
        if row["namespace"] != "":
            text(row["namespace"], policy.CAPA_NAMESPACE)
        rows.append({"rule": text(row["rule"], policy.CAPA_TEXT), "namespace": row["namespace"],
                     "attack": [text(item, policy.ATTACK_ID) for item in listed(row["attack"], 16)],
                     "mbc": [text(item, policy.MBC_ID) for item in listed(row["mbc"], 16)],
                     "matches": number(row["matches"], 2**32 - 1),
                     "addresses": [text(item, policy.ADDRESS) for item in listed(row["addresses"], 8)]})
    return {"rows": rows, "has_more": boolean(value["has_more"]), "capabilities": number(value["capabilities"], 10000),
            "limitations": [text(item, policy.CAPA_TEXT) for item in listed(value["limitations"], 16)],
            "rules_withheld": number(value["rules_withheld"], 10000),
            **{field: text(value[field], policy.CAPA_ENUM) for field in ("format", "arch", "os")}}


IMPORT_ROW = {"kind", "index", "library", "name", "name_hex", "name_bytes", "ordinal", "address"}
LIBRARY_KINDS = {"pe_import": "pe_library", "pe_delay_import": "pe_delay_library"}


def optional(value, check):
    return None if value is None else check(value)


def imports_page(value, limit):
    object_fields(value, {"rows", "has_more", "total_rows", "format", "limitations"})
    if value["format"] not in ("pe", "elf", "unknown"):
        raise invalid()
    rows = []
    for row in listed(value["rows"], limit):
        object_fields(row, IMPORT_ROW)
        if row["kind"] not in policy.IMPORT_KINDS or (row["library"] is None) == (row["kind"] in LIBRARY_KINDS):
            raise invalid()
        name, raw = text(row["name"], policy.IMPORT_NAME), text(row["name_hex"], r"(?:[0-9a-f]{2}){0,256}")
        length = number(row["name_bytes"], 2**32 - 1)
        # Hex appears exactly when the printable name differs from, or cuts, the original bytes.
        original = bytes.fromhex(raw)
        printable = "".join(chr(byte) if 0x20 <= byte <= 0x7E else "?" for byte in original)
        if (len(name) != length if not raw else len(original) != min(length, policy.MAX_IMPORT_NAME) or
                name != printable or length == len(original) and printable.encode("ascii") == original):
            raise invalid()
        if row["ordinal"] is not None and row["kind"] not in LIBRARY_KINDS:
            raise invalid()
        rows.append({"kind": row["kind"], "index": number(row["index"], policy.MAX_IMPORT_ROWS),
                     "library": optional(row["library"], lambda item: number(item, 255)), "name": name,
                     "name_hex": raw, "name_bytes": length, "ordinal": optional(row["ordinal"], lambda item: number(item, 65535)),
                     "address": optional(row["address"], lambda item: text(item, HEX64))})
    limitations = listed(value["limitations"], len(policy.IMPORT_LIMITATIONS))
    if any(item not in policy.IMPORT_LIMITATIONS for item in limitations) or limitations != sorted(set(limitations)):
        raise invalid()
    return {"rows": rows, "has_more": boolean(value["has_more"]), "format": value["format"],
            "total_rows": number(value["total_rows"], policy.MAX_IMPORT_ROWS), "limitations": list(limitations)}


PE32_MACHINES = frozenset({"0x14c", "0x1c0", "0x1c2", "0x1c4"})  # i386 and 32-bit ARM: 32-bit pointers


def derived(reply):
    """Arithmetic on validated artifact_summary fields, so a model never has to convert or add addresses itself.

    PE: the entry point's virtual address (image_base + entry_rva, wrapped as the loader's pointer width wraps it)
    and the index of the section that holds it, or None when no section does. The index is left out when the
    header lists more sections than the summary carries, since the entry may be in one not shown.
    ELF: the entry address in hex. No judgments, only numbers the projected fields already imply.
    """
    summary = reply.get("summary") if isinstance(reply.get("summary"), dict) else {}
    found = {}
    pe = summary.get("pe")
    if isinstance(pe, dict) and pe.get("parsed") and "entry_rva" in pe:
        entry, base = int(pe["entry_rva"], 16), int(pe["image_base"], 16)
        width = 32 if pe.get("machine") in PE32_MACHINES and base <= 0xFFFFFFFF else 64
        found["entry_va"] = hex((base + entry) % (1 << width))
        if pe.get("sections_count") == len(pe["sections"]):
            found["entry_section"] = next((index for index, section in enumerate(pe["sections"])
                                           if int(section["rva"], 16) <= entry < int(section["rva"], 16)
                                           + max(section["virtual_size"], section["raw_size"])), None)
    elf = summary.get("elf")
    if isinstance(elf, dict) and "e_entry" in elf:
        found["e_entry_hex"] = hex(elf["e_entry"])
    return {**reply, "derived": found} if found else reply


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


def project(reply, name, arguments, include, rules=None):
    required = {"tool", "artifact", "artifact_bytes", "summary"}
    # Import names are the granted result itself, so they cross as validated rows, not an excerpt.
    if include and name not in ("artifact_summary", "artifact_imports"):
        required.add("evidence_excerpt")
    object_fields(reply, required)
    if reply["tool"] != name or reply["artifact"] != arguments["artifact"]:
        raise invalid()
    summary = reply["summary"]
    if not isinstance(summary, dict):
        raise invalid()
    if name == "artifact_summary":
        summary = technical_summary(summary)
    elif name == "yara_scan":
        summary = yara_page(summary, arguments["limit"], rules)
    elif name == "capa_triage":
        summary = capa_page(summary, arguments["limit"])
    elif name == "artifact_imports":
        if not include:
            raise invalid()
        summary = imports_page(summary, arguments["limit"])
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
