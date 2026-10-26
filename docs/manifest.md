# Manifest v1

The checker validates JSON shape and cross-record invariants directly in Python. Unknown fields, duplicate JSON keys, NaN/Infinity, malformed types and unsupported schema versions are rejected. UTF-8 JSON is required. It reads structured declarations, not arbitrary evaluation-report prose.

## Top-level fields

All fields are required; objects reject unknown fields.

| Field | Type / meaning |
|---|---|
| `schema_version` | Integer `1` |
| `label` | Nonempty descriptive string, maximum 2000 characters, no control characters |
| `synthetic` | Boolean indicating whether the submitted data is synthetic; not independently checked |
| `plan` | `case_ids` (unique ID array) and `repetitions` (integer 1–100) |
| `summary` | Nonnegative integer counts: `planned`, `attempted`, `completed`, `scored`, `successful` |
| `attempts` | Array of attempt records in execution/retry order |
| `evidence` | Array of local file bindings |
| `claims` | Array of explicit claims; may be empty |

IDs are 1–80 ASCII letters, digits, dots, underscores or hyphens, starting with a letter or digit. Ordinary strings are limited to 2000 characters and may not contain control characters.

## Counts

`planned` is the number of unique case IDs multiplied by repetitions. Each case/repetition slot must have at least one record. Explicitly record an unexecuted slot as `not_run`.

`attempted` counts every record except `not_run`. `completed` counts statuses `success` or `failure`. `scored` counts records with `scored: true`. `successful` counts status `success`. Counts are **attempt-level**, including retries; they are not unique-task success rates. Scoring is a separate declaration and need not equal completion. Only completed attempts can be marked scored. The tool does not independently validate success/failure labels or require a success to be scored.

Example: one case has an error and then a successful retry. Counts are planned 1, attempted 2, completed 1, scored 1 (if declared scored), successful 1. The error remains visible. The checker supplies no headline accuracy percentage.

## Attempt record

Required: `attempt_id`, `case_id`, `repetition`, `status`, `scored`, `evidence_ids`.

- `attempt_id`: unique ID; `case_id`: a planned case; `repetition`: a planned repetition.
- `status`: `success`, `failure`, `error`, `cancelled` or `not_run`.
- `scored`: boolean, true only for `success`/`failure` records.
- `evidence_ids`: unique IDs referencing declared evidence. Every status except `not_run` needs an attachment; absent evidence is UNRESOLVED.
- Optional `retry_of`: ID of the immediately preceding attempt in the same slot. Both records must represent attempted execution, not `not_run`. Retry chains cannot branch; original records are retained. A missing retry link for a second record in a slot is FAIL.

Attempt records may reference the same evidence bundle. The checker cannot establish that a bundle actually contains distinct outputs or all failed retries.

## Evidence record

Required: `evidence_id`, `path`, `sha256`.

`path` is a portable relative path under `--evidence-root`, using `/`. Absolute paths, `..`, `.`, empty path components, backslashes, colons, Windows device names, trailing dots/spaces, symlinks and detected junctions are rejected. Files must be regular files. Each file path has one binding; path uniqueness is case-insensitive for portability. Hard links and concurrent filesystem replacement are outside the security boundary.

`sha256` is exactly 64 lowercase hexadecimal characters. A match proves only that bytes read match the declared digest. A fabricated file can have a valid hash. Missing/unreadable files are UNRESOLVED; mismatched hashes and unsafe paths are FAIL. No URLs are fetched.

To compute a hash with Python:

```sh
python -c "import hashlib,pathlib; print(hashlib.sha256(pathlib.Path('my-evidence/output.json').read_bytes()).hexdigest())"
```

## Claim record

Required: `claim_id`, `kind`, `statement`, `evidence_ids`.

`claim_id` is unique. `kind` is `evaluation`, `publication`, `deployment` or `other`. `statement` is a nonempty string. Missing attachments are UNRESOLVED. Undeclared references are FAIL. Hash-matching attachments receive `CLAIM_ATTACHMENT` PASS for their binding only; their relevance, authenticity and claim truth are never assessed. There is no special publication-verification integration.

## Resource bounds

- Manifest: at most 256 KiB; planned slots and attempt records: at most 2000 each.
- Evidence records: at most 128; claim records: at most 128.
- Evidence file: at most 10 MiB; files read: at most 50 MiB total.
- String: at most 2000 characters; IDs: at most 80 characters; evidence-ID list: at most 128.

Limits bound normal processing; they are not a denial-of-service guarantee for a hostile operating environment. Keep inputs stable during checking. The tool reports what it read rather than authenticating how the files were generated.
