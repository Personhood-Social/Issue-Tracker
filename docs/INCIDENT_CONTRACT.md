# Incident pipeline contract

Implementation: `personhood_issue_tracker.issue` (this package).

## Source of truth

This package is the **only** creator for the automated incident flow wired by each host (`init_issue_tracking`). Downstream systems (index, OpenClaw) consume emitted payloads.

## End-to-end sequence

For each qualifying log record (typically `WARNING` and above on the GitHub issue handler):

1. Fingerprint and optional two-stage Gravity classification; models/timeouts via `SCD_ISSUES_*` (or service-prefixed env in AIF).
2. Render Markdown in memory and compute repo-relative paths (`Warn`/`Error` lifecycle + severity; `Debug`/`INFO` dated).
3. Push `.md` to `Personhood-Social/Issues` via GitHub Contents API when enabled (optional local mirror).
4. Create the issue on the owning repository.
5. Optionally create a linked issue on `Personhood-Social/Issues`.
6. POST canonical payload to OpenClaw and index webhooks when URLs are set.

## Environment (SCD host example)

| Variable | Role |
|----------|------|
| `SCD_ISSUES_MD_GITHUB_REPO` | Target Markdown repo |
| `SCD_ISSUES_MD_GITHUB_PUSH` | Force on/off; if unset, defaults on when a PAT is available |
| `SCD_ISSUES_OPENCLAW_WEBHOOK_*` | OpenClaw intake |
| `SCD_ISSUES_INDEX_WEBHOOK_*` | Index ingest |

See package module docstring and `PLAN.md` in SCD for deployment notes.
