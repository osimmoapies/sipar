# Security policy

Sipar is a security tool, so reports are welcome and taken seriously.

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting** (Security tab → "Report a vulnerability").
Do not open a public issue for a vulnerability.

Useful reports include a Sipar program (or Python API call) and the exact command that shows the problem,
what happened, and what SPEC.md says should happen.

## What counts as a vulnerability

- Untrusted data (`untrusted:*`) reaching a sink (`shell.run`, `fs.write`, `http.*` URL/body, MCP tool
  arguments) without `trust(...)` or `approve(...)`.
- A secret value from `env.secret(...)` appearing in output, prompts, files, journals, traces, error messages
  or memory.
- An effect that runs without the matching `allow` / `uses` capability, or a budget that can be exceeded.
- Replay serving recorded data to a program that diverged from the recorded run.

## Known limits (not vulnerabilities)

These are documented design limits — see SPEC.md §6:

- Implicit flows through control flow (`if untrusted == "x" { ... }`) are not tracked.
- `Bool` and plain `enum` values are never labelled (choice declassification), by design.
- A copy of a secret that a program, server or model re-encodes in a form SPEC.md §6 lists as
  "Not seen" (for example base64, double encoding, an unusual mixed-case copy) is not redacted in its output.
- Side channels (timing, number of calls) are out of scope.

## Supported versions

Only the latest release on the `main` branch gets security fixes while Sipar is below 1.0.
