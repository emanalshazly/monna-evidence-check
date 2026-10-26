"""Standard-library-only checker. Never executes or fetches supplied evidence."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any

from . import __version__

MAX_MANIFEST_BYTES = 262_144
MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_TOTAL_BYTES = 50 * 1024 * 1024
MAX_RECORDS = 2000
SCOPE = (
    "Checks declared counts, record relationships, local attachments and SHA-256 bindings only. "
    "Does not authenticate execution, establish claim truth, assess answer quality, "
    "or certify security or release readiness. Omitted real-world events cannot be discovered."
)


class InputError(ValueError):
    """Invalid or unsupported input; no evaluation verdict can be issued."""


def _object(pairs: list[tuple[str, Any]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise InputError("Duplicate JSON object key.")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise InputError("Non-finite JSON number is not allowed.")


def _keys(value: Any, required: set[str], optional: set[str] = frozenset()) -> None:
    if not isinstance(value, dict) or set(value) - required - optional or required - set(value):
        raise InputError("Missing, unexpected or invalid object fields; see docs/manifest.md.")


def _string(value: Any, *, identifier: bool = False) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > 2000:
        raise InputError("Expected a nonempty string of at most 2000 characters.")
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise InputError("Control characters are not allowed in input strings.")
    if identifier and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", value):
        raise InputError("IDs must use 1-80 ASCII letters, digits, dot, underscore or hyphen.")


def _integer(value: Any, minimum: int = 0, maximum: int = MAX_RECORDS) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise InputError("Integer out of range or boolean supplied as a count.")


def _list(value: Any, maximum: int = MAX_RECORDS) -> None:
    if not isinstance(value, list) or len(value) > maximum:
        raise InputError("Expected a bounded JSON array.")


def _ids(value: Any, maximum: int = 128) -> None:
    _list(value, maximum)
    for item in value:
        _string(item, identifier=True)
    if len(set(value)) != len(value):
        raise InputError("Repeated ID in an ID list.")


def load_manifest(path: Path) -> dict:
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_MANIFEST_BYTES + 1)
    except OSError as exc:
        raise InputError("Cannot read manifest.") from exc
    if len(raw) > MAX_MANIFEST_BYTES:
        raise InputError("Manifest exceeds 256 KiB.")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_object, parse_constant=_constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise InputError("Invalid UTF-8 JSON, duplicate keys, nesting or non-finite values.") from exc
    validate_manifest(value)
    return value


def validate_manifest(data: Any) -> None:
    _keys(data, {"schema_version", "label", "synthetic", "plan", "summary", "attempts", "evidence", "claims"})
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise InputError("Only schema_version 1 is supported.")
    _string(data["label"])
    if type(data["synthetic"]) is not bool:
        raise InputError("synthetic must be a boolean.")
    plan = data["plan"]
    _keys(plan, {"case_ids", "repetitions"})
    _ids(plan["case_ids"], MAX_RECORDS)
    if not plan["case_ids"]:
        raise InputError("Plan must contain at least one case.")
    _integer(plan["repetitions"], 1, 100)
    if len(plan["case_ids"]) * plan["repetitions"] > MAX_RECORDS:
        raise InputError("Plan exceeds 2000 case/repetition slots.")
    _keys(data["summary"], {"planned", "attempted", "completed", "scored", "successful"})
    for count in data["summary"].values():
        _integer(count)
    _list(data["attempts"])
    for row in data["attempts"]:
        _keys(row, {"attempt_id", "case_id", "repetition", "status", "scored", "evidence_ids"}, {"retry_of"})
        _string(row["attempt_id"], identifier=True)
        _string(row["case_id"], identifier=True)
        _integer(row["repetition"], 1, 100)
        if row["status"] not in ("success", "failure", "error", "cancelled", "not_run"):
            raise InputError("Unknown attempt status.")
        if type(row["scored"]) is not bool:
            raise InputError("scored must be a boolean.")
        _ids(row["evidence_ids"])
        if "retry_of" in row:
            _string(row["retry_of"], identifier=True)
    _list(data["evidence"], 128)
    for row in data["evidence"]:
        _keys(row, {"evidence_id", "path", "sha256"})
        _string(row["evidence_id"], identifier=True)
        _string(row["path"])
        if not isinstance(row["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"]):
            raise InputError("sha256 must be 64 lowercase hexadecimal characters.")
    _list(data["claims"], 128)
    for row in data["claims"]:
        _keys(row, {"claim_id", "kind", "statement", "evidence_ids"})
        _string(row["claim_id"], identifier=True)
        _string(row["statement"])
        if row["kind"] not in ("evaluation", "publication", "deployment", "other"):
            raise InputError("Unknown claim kind.")
        _ids(row["evidence_ids"])


def _linked(path: Path) -> bool:
    return path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())


def _safe_file(root: Path, name: str) -> Path:
    # Require portable relative paths; reject Windows drives, UNC, ADS and backslashes on every OS.
    if "\\" in name or ":" in name or name.startswith("/"):
        raise ValueError("Evidence path must be a portable relative path.")
    parts = name.split("/")
    if any(p in ("", ".", "..") or p.endswith((" ", ".")) for p in parts):
        raise ValueError("Evidence path contains an unsafe path component.")
    if any(re.fullmatch(r"(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", p) for p in parts):
        raise ValueError("Evidence path contains a reserved device name.")
    if PurePosixPath(name).is_absolute():
        raise ValueError("Absolute evidence paths are not allowed.")
    current = root
    for part in parts:
        current = current / part
        if _linked(current):
            raise ValueError("Linked evidence paths are not allowed.")
    resolved = current.resolve(strict=True)
    if not resolved.is_relative_to(root):
        raise ValueError("Evidence path leaves the selected root.")
    if not resolved.is_file():
        raise ValueError("Evidence must be a regular file.")
    return resolved


def check_manifest(data: dict, evidence_root: Path) -> dict:
    """Return structural findings. Even a PASS cannot prove truth or completeness."""
    validate_manifest(data)
    findings: list[dict] = []

    def add(status: str, code: str, message: str) -> None:
        findings.append({"status": status, "code": code, "message": message})

    root_input = evidence_root.absolute()
    # Reject user-selected roots that traverse a symlink/junction as well.
    if any(_linked(p) for p in (root_input, *root_input.parents)):
        raise InputError("Evidence root must not traverse a symbolic link or junction.")
    try:
        root = root_input.resolve(strict=True)
        if not root.is_dir():
            raise InputError("Evidence root must be a directory.")
    except OSError as exc:
        raise InputError("Cannot access evidence root directory.") from exc

    evidence: dict[str, str] = {}
    seen_paths: set[str] = set()
    total = 0
    for row in data["evidence"]:
        eid = row["evidence_id"]
        if eid in evidence:
            add("FAIL", "DUPLICATE_EVIDENCE", f"Duplicate evidence ID: {eid}.")
            continue
        evidence[eid] = "UNRESOLVED"
        try:
            path = _safe_file(root, row["path"])
            # Case-folding intentionally enforces portable uniqueness.
            key = path.relative_to(root).as_posix().casefold()
            if key in seen_paths:
                add("FAIL", "DUPLICATE_PATH", f"Evidence {eid} reuses a file path.")
                evidence[eid] = "FAIL"
                continue
            seen_paths.add(key)
            size = path.stat().st_size
            if size > MAX_FILE_BYTES or total + size > MAX_TOTAL_BYTES:
                add("FAIL", "EVIDENCE_LIMIT", f"Evidence {eid} exceeds the file/total byte budget.")
                evidence[eid] = "FAIL"
                continue
            digest = hashlib.sha256()
            read = 0
            with path.open("rb") as handle:
                while chunk := handle.read(65536):
                    read += len(chunk)
                    if read > MAX_FILE_BYTES or total + read > MAX_TOTAL_BYTES:
                        raise ValueError("Evidence changed or exceeded the byte budget during reading.")
                    digest.update(chunk)
            total += read
            if digest.hexdigest() != row["sha256"]:
                evidence[eid] = "FAIL"
                add("FAIL", "HASH_MISMATCH", f"Evidence {eid} bytes do not match the declared SHA-256.")
            else:
                evidence[eid] = "PASS"
                add("PASS", "HASH_MATCH", f"Evidence {eid} matches its declared SHA-256; origin is unverified.")
        except OSError:
            add("UNRESOLVED", "EVIDENCE_UNAVAILABLE", f"Evidence {eid} is missing or unreadable.")
        except (ValueError, RuntimeError):
            evidence[eid] = "FAIL"
            add("FAIL", "UNSAFE_EVIDENCE", f"Evidence {eid} has an unsafe path, type or size.")

    def attachments(refs: list[str], owner: str, required: bool) -> None:
        if not refs and required:
            add("UNRESOLVED", "NO_EVIDENCE", f"{owner} has no evidence attachment.")
        for eid in refs:
            if eid not in evidence:
                add("FAIL", "UNKNOWN_EVIDENCE", f"{owner} references undeclared evidence {eid}.")
            elif evidence[eid] != "PASS":
                add(evidence[eid], "UNBOUND_EVIDENCE", f"{owner} references unavailable or mismatched evidence {eid}.")

    slots = {(cid, rep) for cid in data["plan"]["case_ids"] for rep in range(1, data["plan"]["repetitions"] + 1)}
    seen: dict[str, dict] = {}
    slot_rows: dict[tuple, list] = {}
    retried: set[str] = set()
    for row in data["attempts"]:
        aid = row["attempt_id"]
        if aid in seen:
            add("FAIL", "DUPLICATE_ATTEMPT", f"Duplicate attempt ID: {aid}.")
            continue
        slot = (row["case_id"], row["repetition"])
        if slot not in slots:
            add("FAIL", "UNPLANNED_ATTEMPT", f"Attempt {aid} is outside the declared plan.")
        previous = slot_rows.get(slot, [])
        parent = row.get("retry_of")
        if parent:
            source = seen.get(parent)
            if (source is None or source["status"] == "not_run" or row["status"] == "not_run"
                    or (source["case_id"], source["repetition"]) != slot
                    or parent in retried or not previous or previous[-1]["attempt_id"] != parent):
                add("FAIL", "INVALID_RETRY", f"Attempt {aid} must retry the immediately preceding record in its slot.")
            retried.add(parent)
        elif previous:
            add("FAIL", "MISSING_RETRY_LINK", f"Attempt {aid} duplicates a planned slot without retry_of.")
        if row["scored"] and row["status"] not in ("success", "failure"):
            add("FAIL", "INVALID_SCORED_STATE", f"Attempt {aid} is scored although execution did not complete.")
        attachments(row["evidence_ids"], f"Attempt {aid}", row["status"] != "not_run")
        seen[aid] = row
        slot_rows.setdefault(slot, []).append(row)
    missing = slots - set(slot_rows)
    if missing:
        add("FAIL", "MISSING_PLANNED_SLOTS", f"{len(missing)} planned case/repetition slots have no record; use not_run explicitly.")
    else:
        add("PASS", "PLAN_COVERAGE", "Every planned case/repetition slot has a record, including explicit not_run states.")
    computed = {
        "planned": len(slots),
        "attempted": sum(r["status"] != "not_run" for r in data["attempts"]),
        "completed": sum(r["status"] in ("success", "failure") for r in data["attempts"]),
        "scored": sum(r["scored"] for r in data["attempts"]),
        "successful": sum(r["status"] == "success" for r in data["attempts"]),
    }
    for key, value in computed.items():
        if data["summary"][key] != value:
            add("FAIL", "COUNT_MISMATCH", f"Summary {key} declares {data['summary'][key]}; records imply {value}.")
        else:
            add("PASS", "COUNT_MATCH", f"Summary {key} matches the declared plan/records: {value}.")
    claim_ids: set[str] = set()
    for claim in data["claims"]:
        cid = claim["claim_id"]
        if cid in claim_ids:
            add("FAIL", "DUPLICATE_CLAIM", f"Duplicate claim ID: {cid}.")
        claim_ids.add(cid)
        attachments(claim["evidence_ids"], f"Claim {cid}", True)
        if claim["evidence_ids"] and all(evidence.get(e) == "PASS" for e in claim["evidence_ids"]):
            add("PASS", "CLAIM_ATTACHMENT", f"Claim {cid} has hash-matching attachments; claim truth is not assessed.")
    status = "FAIL" if any(f["status"] == "FAIL" for f in findings) else "UNRESOLVED" if any(f["status"] == "UNRESOLVED" for f in findings) else "PASS"
    return {"tool": "MONNA Evidence Check", "version": __version__, "check_status": status,
            "scope": SCOPE, "label": data["label"], "synthetic": data["synthetic"],
            "declared_summary": data["summary"], "computed_summary": computed,
            "unscored_attempted": computed["attempted"] - computed["scored"],
            "claim_truth_assessed": False, "findings": findings}


def _escape(value: str) -> str:
    # Reports are text; never render supplied HTML or terminal control sequences.
    value = "".join(c if ord(c) >= 32 and ord(c) != 127 else " " for c in value)
    value = value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    for c in "\\`*_{}[]()#+!|":
        value = value.replace(c, "\\" + c)
    return value


def render_markdown(report: dict) -> str:
    lines = ["# MONNA Evidence Check", "", f"Structural check: **{report['check_status']}**", "",
             f"Label: {_escape(report['label'])}", f"Synthetic data: {str(report['synthetic']).lower()}", "",
             report["scope"], "", "## Counts from supplied records", "",
             "| Field | Declared | Computed |", "|---|---:|---:|"]
    for key, value in report["computed_summary"].items():
        lines.append(f"| {key} | {report['declared_summary'][key]} | {value} |")
    lines += ["", "## Findings", ""]
    lines.extend(f"- **{f['status']}** `{f['code']}` — {_escape(f['message'])}" for f in report["findings"])
    return "\n".join(lines) + "\n"
