# Security Policy

## Scope and threat model

safedata-guard is **defense in depth for cooperative / semi-trusted model
output**. The static AST screen, reduced builtins, and invariant checks stop the
destructive accidents an honest model makes and the obvious escape attempts. They
are **not** a sandbox for deliberately malicious code: in-process Python
screening can be defeated, and the default subprocess runner shares the host's
filesystem permissions.

For **untrusted** code, use `isolation="docker"` (no network, read-only root
filesystem, memory/CPU limits) or run inside your own OS-level isolation
(container, locked-down user, or VM). PII masking and data-quality checks are
best-effort heuristics, not a compliance guarantee.

## Supported versions

The latest released `1.x` line receives security fixes.

## Reporting a vulnerability

Please report suspected vulnerabilities privately via GitHub Security Advisories
("Report a vulnerability" on the repository's **Security** tab) rather than a
public issue. Include a minimal reproduction and the affected version. We aim to
acknowledge within 5 business days.

Especially valuable: a code snippet that passes `check_code()` / the static
screen yet reaches the filesystem, network, or host process — that is exactly the
boundary this project documents as best-effort, and concrete bypasses help us
tighten it.
