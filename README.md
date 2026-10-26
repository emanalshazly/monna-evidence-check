# MONNA Evidence Check

**Catch inconsistent evaluation counts, missing attachments and changed evidence files.**

A small local Python CLI for people building AI agents, applications and prompt products. It checks a structured run manifest against files you explicitly provide. It makes no model calls and needs no API key or runtime third-party packages.

**v0.1.0 — initial release.** A structural PASS means the supplied records and attachments passed these checks. It does **not** mean the evaluated system succeeded, the evidence is authentic, or a publication/deployment happened.

## Try it

Requires Python 3.11 or newer. Download this repository's ZIP and extract it, or clone it. Open a terminal in the extracted repository folder:

```sh
python -m monna_evidence_check examples/clean.json --evidence-root examples
```

On Windows, use `py` instead of `python` if that is how your Python installation is configured. These examples are **synthetic**; they are not customer results or genuine model evaluations.

Try a report whose summary hides an error:

```sh
python -m monna_evidence_check examples/hidden-error.json --evidence-root examples
```

This intentionally exits with code 1 and reports `COUNT_MISMATCH`.

Try a publication claim with no attachment:

```sh
python -m monna_evidence_check examples/missing-receipt.json --evidence-root examples --format json
```

This intentionally exits with code 2 and reports `NO_EVIDENCE`. It does not conclude that publication did or did not happen.

## What it checks

- Planned case/repetition slots have records, including explicit `not_run` states.
- Summary counts agree with supplied records; failed attempts and retries remain visible.
- Retry links, IDs, scored states and evidence references are structurally consistent.
- Referenced local files exist, fit byte limits, stay inside the selected evidence root and match declared SHA-256 hashes.
- Claims and executed attempts have evidence attachments. Hash-matching attachments establish a byte binding, not claim truth.

## What it cannot check

It cannot discover real attempts omitted from both the plan and records, determine whether a supplied document supports a claim, authenticate receipts, grade model answers, detect all fabricated evidence or certify safety/security/release readiness. It does not parse free-form prose or screenshots into a manifest. Counts and statuses remain user declarations. Do not turn a green report into a product-performance certificate.

The checker has no network feature, does not execute supplied content and does not modify evidence. Use a stable, trusted local directory: path checks are not a hardened sandbox against a concurrent attacker changing the filesystem. Do not run it as administrator on hostile inputs. See [the threat model](docs/threat-model.md).

## Use your own records

Copy `examples/clean.json`, replace its synthetic records with your own, and use relative file paths under your chosen evidence directory. Set `synthetic` accurately. The [manifest guide](docs/manifest.md) defines every field, count and limit. Do not include secrets, personal data or internal MONNA material in public reports.

```sh
python -m monna_evidence_check my-run.json --evidence-root my-evidence --format json
```

Output goes to stdout; input errors go to stderr. The tool creates no report files. Redirect output if you want to save a report.

| Exit | Meaning |
|---:|---|
| 0 | PASS: supplied structure/bindings pass |
| 1 | FAIL: contradiction, unsafe path or mismatched binding found |
| 2 | UNRESOLVED: required evidence is absent/unavailable, with no structural FAIL |
| 3 | INPUT_ERROR: invalid manifest, root or command arguments |

FAIL takes precedence over UNRESOLVED; inspect all findings. An honestly documented failed model run can receive a structural PASS.

## Reproduce the checks

```sh
python -m unittest discover -s tests -v
```

[Validation scope](docs/validation.md) separates tested behavior from untested claims. GitHub Actions runs the same standard-library test suite on Linux and Windows. A workflow file alone is not evidence that CI passed; inspect the actual run.

## Ownership and contributions

This standalone component is licensed under [Apache-2.0](LICENSE). It does not include or grant access to the complete private MONNA framework. Source-code permissions and use of the MONNA brand are separate; see [NOTICE](NOTICE) and [brand guidance](BRAND.md).

For a reproducible bug, open a GitHub issue using synthetic or redacted input. Review [CONTRIBUTING.md](CONTRIBUTING.md) first. This is an initial community release, with no support response-time promise.
