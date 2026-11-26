"""Benign fixtures with known properties, and the questions a benchmark run asks about them."""

import hashlib

from re_harness import worker


def synthetic_pe():
    """The PE32 the worker builds for parser checks: one .idata section importing KERNEL32.dll!ExitProcess."""
    data = worker.synthetic_pe()
    digest = hashlib.sha256(data).hexdigest()
    truths = [
        {"id": "pe-format", "artifact": digest, "kind": "observed", "terms": ["PE"]},
        {"id": "pe-entry", "artifact": digest, "kind": "observed", "address": "0x1000", "terms": ["entry"]},
        {"id": "pe-import", "artifact": digest, "kind": "observed", "terms": ["ExitProcess"]},
    ]
    questions = [{"text": "What kind of executable is this, and where does it start?",
                  "outcome": "Its format and entry point RVA, cited from a tool result", "artifacts": [digest]},
                 {"text": "Which functions does it import?",
                  "outcome": "Import names under an operator grant, cited from artifact_imports", "artifacts": [digest]}]
    return {"name": "synthetic-pe", "bytes": data, "sha256": digest, "truths": truths, "questions": questions,
            "source": "Benchmark synthetic PE"}


def benign_elf(data):
    """The compiled benign ELF baked into the image (worker fixture mode). Its bytes come from the Apprentice."""
    digest = hashlib.sha256(data).hexdigest()
    truths = [
        {"id": "elf-format", "artifact": digest, "kind": "observed", "terms": ["ELF"]},
        {"id": "elf-libc", "artifact": digest, "kind": "observed", "terms": ["libc"]},
    ]
    questions = [{"text": "What format is this file, and which shared libraries does it need?",
                  "outcome": "Its format and needed libraries, cited from tool results", "artifacts": [digest]}]
    return {"name": "benign-elf", "bytes": data, "sha256": digest, "truths": truths, "questions": questions,
            "source": "Benchmark benign ELF"}
