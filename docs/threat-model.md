# Scope and threat model

This is a local inspection aid, not a security certification tool, receipt authenticator or sandbox. No claim is made that it prevents all fabricated evidence.

It accepts potentially malformed JSON and untrusted path strings. It uses strict JSON/schema checks, bounded reads, explicit root selection, path traversal rejection, symlink/junction rejection where detectable and SHA-256 comparisons. It does not execute evidence, import evidence as code, deserialize pickle, fetch URLs, send telemetry or make model calls. Evidence content is hashed as bytes and is not interpreted as instructions.

Trust assumptions: the installed Python interpreter and checker source are trusted; the selected directory remains stable; no attacker can swap files or mounts during checking. A compromised host, malicious concurrent filesystem actor, hard-link exfiltration, hidden real attempts, false semantic labels and forged-but-consistent attachments are outside the protection provided. The checker can detect a path/reference problem without proving that an entire evaluation is trustworthy.

Run without elevated privileges. Use a copied evidence directory you control. Review and redact output before publishing. Avoid placing private files in a public issue. The tool makes no network requests, but your terminal, operating system or hosting platform may have their own behavior.

For a security concern, do not publish confidential exploit data. Until a private reporting channel is configured, report only a minimal non-sensitive description through GitHub's available reporting mechanisms. No response-time guarantee or independent security audit is claimed.
