"""Closed tool contract shared by the host broker and offline worker."""

import re

DIGEST = r"[a-f0-9]{64}"
ADDRESS = r"0x[0-9a-f]{1,16}"
CASE_ID = r"[a-z0-9][a-z0-9-]{0,47}"
MAX_ARTIFACT = 128 * 1024 * 1024
MAX_EXCERPT = 8192
MAX_TOOL_CALLS = 32
MAX_LINE = 128 * 1024
MAX_YARA_RULES = 1024 * 1024
YARA_IDENTIFIER = r"[A-Za-z_][A-Za-z0-9_]{0,127}"
YARA_STRING = r"\$[A-Za-z0-9_]{0,127}"
# Only data-parsing modules. console writes to stdout, and others are not compiled in.
YARA_MODULES = frozenset({"pe", "elf", "math", "hash", "dotnet", "string", "time"})
CAPA_TEXT = r"[ -~]{1,200}"
CAPA_NAMESPACE = r"[a-z0-9][a-z0-9/_.-]{0,127}"
CAPA_ENUM = r"[a-z0-9_]{1,16}"
ATTACK_ID = r"T[0-9]{4}(?:\.[0-9]{3})?"
MBC_ID = r"[A-Z][0-9]{4}(?:\.[a-z0-9]{3})?"
MAX_IMPORT_NAME = 256
MAX_IMPORT_ROWS = 8192
IMPORT_NAME = r"[ -~]{0,256}"
IMPORT_KINDS = frozenset({"pe_section", "pe_library", "pe_import", "pe_delay_library", "pe_delay_import",
                          "elf_needed", "elf_import", "elf_export"})
IMPORT_LIMITATIONS = frozenset({"pefile_unavailable", "pe_parse_failed", "elf_parse_failed", "unsupported_format",
                                "sections_capped", "libraries_capped", "functions_capped", "rows_capped"})

TOOLS = {
    "artifact_summary": "Verify one artifact and summarize its headers and string count.",
    "artifact_strings": "Page string offsets and lengths. String contents require an operator grant.",
    "ghidra_functions": "List Ghidra function entry addresses. Symbol names require an operator grant.",
    "ghidra_xrefs": "Inspect cross-references to an address in Ghidra.",
    "ghidra_decompile": "Produce a bounded Ghidra decompilation excerpt under an operator grant.",
    "rea_inspect": "Inspect a native binary with REA's static Ghidra provider.",
    "rea_decompile": "Produce a bounded REA decompilation excerpt under an operator grant.",
    "yara_scan": "Page the case's operator-imported YARA rule matches with string offsets. Matched bytes require "
                 "an operator grant.",
    "capa_triage": "Page capa capability matches from the pinned capa rules, with ATT&CK and MBC IDs and "
                   "function addresses.",
    "artifact_imports": "Page PE section and import names, or ELF needed libraries and dynamic symbols, under an "
                        "operator grant.",
}
ADDRESSED = {"ghidra_xrefs", "ghidra_decompile", "rea_decompile"}
PAGED = {"artifact_strings", "ghidra_functions", "ghidra_xrefs", "yara_scan", "capa_triage", "artifact_imports"}
EXCERPT_ONLY = {"ghidra_decompile", "rea_decompile", "artifact_imports"}


class Denied(ValueError):
    """An intent outside the tool contract."""


def tool_schema(name):
    properties = {"artifact": {"type": "string", "pattern": "^" + DIGEST + "$"}}
    required = ["artifact"]
    if name in ADDRESSED:
        properties["address"] = {"type": "string", "pattern": "^" + ADDRESS + "$"}
        required.append("address")
    if name in PAGED:
        properties["offset"] = {"type": "integer", "minimum": 0, "maximum": 10000, "default": 0}
        properties["limit"] = {"type": "integer", "minimum": 1, "maximum": 50, "default": 20}
    return {"type": "object", "properties": properties, "required": required,
            "additionalProperties": False}


def match(value, pattern):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def validate(name, arguments):
    if not isinstance(name, str) or name not in TOOLS:
        raise Denied("unknown_tool")
    if not isinstance(arguments, dict):
        raise Denied("invalid_arguments")
    schema = tool_schema(name)
    properties = schema["properties"]
    if arguments.keys() - properties.keys() or set(schema["required"]) - arguments.keys():
        raise Denied("invalid_fields")
    values = {}
    for field, spec in properties.items():
        value = arguments.get(field, spec.get("default"))
        if spec["type"] == "string":
            valid = match(value, spec["pattern"])
        else:
            valid = type(value) is int and spec["minimum"] <= value <= spec["maximum"]
        if not valid:
            raise Denied("invalid_" + field)
        values[field] = value
    if "address" in values:
        values["address"] = hex(int(values["address"], 16))
    return values
