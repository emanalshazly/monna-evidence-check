# Validation scope

The public test suite checks strict JSON parsing, schema/type rejection, summary contradictions, explicit not-run states, retry history, planned-slot coverage, missing evidence, hash tampering, byte limits, path escapes, linked paths, rendering and CLI exit codes. Its fixtures are synthetic.

The initial local Windows/Python 3.13 run collected 48 tests. Symbolic-link creation may be skipped where the OS denies that privilege; a skip does not demonstrate that behavior. Linux CI exercises linked-file cases where supported. Read actual workflow logs for platform-specific outcomes.

The release preparation also exercises the three README examples from a fresh allowlisted ZIP with Python site packages disabled. The expected structural statuses are PASS (exit 0), FAIL (exit 1) and UNRESOLVED (exit 2). These tests establish behavior for those examples and cases only.

No live model evaluation, customer study, receipt authentication, external publication/deployment verification, independent security audit, comprehensive OS compatibility or production reliability claim is made. No measured speedup or financial saving is claimed. This tool checks supplied declarations; it cannot discover every omission or deception.

The repository's tests and CI are reproducible evidence, not a certificate of correctness. If a later commit changes behavior, evaluate that exact commit again.
