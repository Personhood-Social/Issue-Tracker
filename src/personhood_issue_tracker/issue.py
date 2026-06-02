"""GitHub Issues + Markdown observability for automated incidents (`issue.py`).

Architecture overview (details: repo-root ``PLAN.md``):

1. **Owning-repo GitHub Issues** — WARNING+ via PyGithub on a bounded queue, with optional two-stage
   Gravity classification (triage then remediation; models/timeouts from ``SCD_ISSUES_*`` env).
2. **Personhood-Social/Issues** — Markdown artifacts pushed via the GitHub Contents API when
   ``SCD_ISSUES_MD_GITHUB_PUSH`` is enabled. **GitHub-only mode** needs no local checkout: paths are
   rendered in memory and uploaded. With ``SCD_ISSUES_MD_ROOT``, files are written locally and the
   same relative paths are mirrored remotely when push is on.
3. **Secondary issue** on the Issues repo may be opened from the same incident bundle (links back to
   the owning-repo issue and the `.md` paths).
4. **Webhooks** — Optional POST to OpenClaw (``SCD_ISSUES_OPENCLAW_WEBHOOK_*``) and to the incident
   index (``SCD_ISSUES_INDEX_WEBHOOK_*``) with the canonical payload including ``markdown_exports``.
5. **Breadcrumbs** — Small ring buffer on the root logger for correlation in exports.

Call ``init_issue_tracking()`` or ``init_github_logging()`` once at process start (idempotent).
Tokens must come from the environment or explicit arguments — never hardcoded.

"""

from __future__ import annotations

import asyncio
import collections
import concurrent.futures
import contextlib
import hashlib
import json
import linecache
import logging
import os
import queue
import re
import shlex
import subprocess
import threading
import time
import traceback
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_GH_AVAILABLE = False
GithubException = Exception  # type: ignore[misc, assignment]
try:
    from github import Auth, Github
    from github import GithubException as _PyGithubException
    from github.GithubRetry import GithubRetry

    GithubException = _PyGithubException  # type: ignore[misc]
    _GH_AVAILABLE = True
except ImportError:
    Github = None  # type: ignore
    Auth = None  # type: ignore
    GithubRetry = None  # type: ignore
    _GH_AVAILABLE = False

_breadcrumb_handler_installed: bool = False
_github_issue_handler_installed: bool = False
_markdown_export_handler_installed: bool = False
_gravity_v2_init_logged: bool = False
_classification_cache: dict[str, tuple[float, dict[str, Any] | None]] = {}
_classification_cache_lock = threading.Lock()
_markdown_export_runtime_root: Path | None = None
# Last init_issue_tracking() snapshot for Issues-repo pushes when env omits SCD_ISSUES_* .
_issues_md_runtime: dict[str, Any] = {}

# Export folder names (must match Personhood-Social/Issues layout).
_MD_FOLDER_DEBUG = "Debug"
_MD_FOLDER_INFO = "INFO"
_MD_FOLDER_WARN = "Warn"
_MD_FOLDER_ERROR = "Error"
_MD_STATE_UNRESOLVED = "Unresolved"
_MD_STATE_IN_PROGRESS = "In-Progress"
_MD_STATE_RESOLVED = "Resolved"

_breadcrumbs: collections.deque[logging.LogRecord] = collections.deque(maxlen=50)
_SECRET_KEY_PARTS = ("token", "secret", "password", "cookie", "authorization", "api_key", "key")


def _redact(value: object, *, key: str = "") -> str:
    if any(part in key.lower() for part in _SECRET_KEY_PARTS):
        return "<redacted>"
    text = str(value)
    lowered = text.lower()
    if any(part in lowered for part in ("bearer ", "gho_", "github_pat_", "sk-")):
        return "<redacted>"
    if len(text) > 500:
        return text[:500] + "...<truncated>"
    return text


# ── Label taxonomy ────────────────────────────────────────────────────────────
_LABEL_META: dict[str, tuple[str, str]] = {
    # severity
    "severity/critical": ("b60205", "P0 — service down or data loss"),
    "severity/high": ("e4e669", "P1 — major feature broken"),
    "severity/medium": ("f9c513", "P2 — degraded but functional"),
    "severity/low": ("0e8a16", "P3 — cosmetic / minor"),
    "severity/noise": ("cccccc", "Expected operational chatter, not a bug"),
    # components
    "comp/ai-router": ("1d76db", "AI model routing & fallback"),
    "comp/kms-memory": ("5319e7", "KMS long/short-term memory"),
    "comp/redis": ("e11d48", "Redis connectivity or ops"),
    "comp/websocket": ("0052cc", "WebSocket connections & heartbeat"),
    "comp/bridge": ("006b75", "AIF ↔ SCD bridge"),
    "comp/auth": ("bfd4f2", "Firebase / token auth"),
    "comp/database": ("c5def5", "Postgres / Supabase"),
    "comp/volition": ("fef2c0", "Volition / proactive engine"),
    "comp/dating": ("f9d0c4", "Dating / standouts / matching"),
    "comp/media": ("d4c5f9", "Photo / video / YouTube"),
    "comp/startup": ("e6e6e6", "Process startup / init"),
    "comp/infra": ("ededed", "Server / OS / deployment"),
    # type
    "type/crash": ("b60205", "Unhandled exception or fatal error"),
    "type/degraded": ("f9c513", "Partial failure with graceful fallback"),
    "type/connectivity": ("0075ca", "Network / external service unreachable"),
    "type/rate-limit": ("e4e669", "API quota or rate limit hit"),
    "type/config": ("bfd4f2", "Misconfiguration or missing env var"),
    "type/timeout": ("d4c5f9", "Async timeout or slow path"),
    "type/noise": ("cccccc", "Expected / benign operational log"),
    # fixed
    "auto-reported": ("0075ca", "Opened automatically by the error logger"),
    "bug": ("d73a4a", "Something isn't working"),
}

_CLASSIFICATION_PROMPT_STAGE1_SUMMARY = """\
You are a senior backend engineer triaging automated error reports for Cady (SCD = Social Character Daemon).

Return ONLY valid JSON for STAGE 1 — fast triage summary (no remediation steps here).

=== EVENT ===
Level: {level}
Logger: {logger}
Message: {message}
Culprit: {culprit}
Stack trace (truncated):
{stacktrace}
Recent breadcrumbs (last 5):
{breadcrumbs}

=== SCHEMA ===
{{
  "summary": "<1-2 sentence plain-English explanation of what went wrong and whether it needs immediate action>",
  "severity": "<one of: critical, high, medium, low, noise>",
  "components": ["<zero or more of: ai-router, kms-memory, redis, websocket, bridge, auth, database, volition, dating, media, startup, infra>"],
  "type": "<one of: crash, degraded, connectivity, rate-limit, config, timeout, noise>",
  "is_noise": <true if expected/benign operational chatter, false otherwise>
}}

Rules:
- severity=noise / is_noise=true for: bridge reconnects, WS closes, Redis fallback, successful rate-limit retries
- severity=critical only for: data loss, auth broken, total chat failure
- Return ONLY the JSON object, no markdown fences.
"""

_CLASSIFICATION_PROMPT_STAGE2_REMEDIATION = """\
You are the remediation engineer for Cady (SCD). In enterprise setups your audience mirrors an IDE agent stack (Cursor-class tooling): they can edit code, open PRs, run terminals, and delegate subtasks — but THIS endpoint only receives text (no live tools). Produce concrete, repo-aware steps they can execute offline.

STAGE 1 triage (trust but verify):
{stage1_json}

=== FULL EVENT (same as triage) ===
Level: {level}
Logger: {logger}
Message: {message}
Culprit: {culprit}
Stack trace (truncated):
{stacktrace}
Recent breadcrumbs (last 5):
{breadcrumbs}

=== SCHEMA ===
Return ONLY valid JSON:
{{
  "remediation_markdown": "<Markdown bullet list with leading - ; concrete fix/mitigation steps; name modules/paths when inferable; never secrets>",
  "verification": "<one paragraph: pytest slices, smoke checks, metrics>",
  "root_cause_hypothesis": "<optional one sentence>",
  "trigger_conditions": "<optional short paragraph describing what situation triggers the issue>",
  "fix_summary": "<optional short paragraph describing how the fix resolves the issue>",
  "handling_summary": "<optional short paragraph describing degraded mode, retries, or fallback handling>",
  "pr_title": "<optional concise PR title>",
  "pr_body_markdown": "<optional PR body markdown using the repo template style>"
}}

Rules:
- Assume Windsurf already summarized; you focus on HOW to fix and verify.
- If noise incident: say \"no code change\" or monitoring-only steps.
- Return ONLY the JSON object, no markdown fences.
"""


def _truthy_env(value: str | None) -> bool:
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


def _resolve_gravity_v2_accounts_path() -> tuple[str | None, str]:
    env_candidates = (
        ("SCD_GRAVITY_V2_ACCOUNTS_PATH", os.getenv("SCD_GRAVITY_V2_ACCOUNTS_PATH")),
        ("KMS_GRAVITY_V2_ACCOUNTS_PATH", os.getenv("KMS_GRAVITY_V2_ACCOUNTS_PATH")),
    )
    for source, raw in env_candidates:
        path = str(raw or "").strip()
        if path:
            return path, source
    return None, "auto-discovery"


def _gravity_v2_runtime_metadata() -> dict[str, Any]:
    accounts_path, accounts_source = _resolve_gravity_v2_accounts_path()
    backend = os.getenv("SCD_ISSUES_REMEDIATION_BACKEND", "gravity").strip().lower() or "gravity"
    metadata: dict[str, Any] = {
        "gravity_v2_accounts_path": accounts_path,
        "gravity_v2_accounts_source": accounts_source,
        "issues_summary_model": os.getenv(
            "SCD_ISSUES_SUMMARY_MODEL", "windsurf/swe-1-6-fast"
        ).strip(),
        "issues_remediation_backend": backend,
    }
    if backend == "gravity":
        metadata["issues_remediation_model"] = os.getenv(
            "SCD_ISSUES_REMEDIATION_MODEL", "cursor/auto"
        ).strip()
    elif backend == "openclaw":
        metadata["issues_openclaw_command"] = os.getenv("OPENCLAW_STAGE2_COMMAND", "").strip()
    return metadata


def _load_openclaw_template(filename: str) -> str:
    template_path = Path(__file__).resolve().parents[3] / "Issues" / "docs" / filename
    try:
        return template_path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _repo_slug() -> str:
    raw = (
        os.getenv("SCD_ISSUES_SOURCE_REPO", "").strip()
        or os.getenv("GITHUB_REPOSITORY", "").strip()
        or "scd"
    )
    return re.sub(r"[^a-zA-Z0-9_.-]+", "-", raw).strip("-")[:72] or "scd"


def _branch_slug(branch: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "-", (branch or "unknown")).strip("-")[:72] or "unknown"


def _severity_bucket(classification: dict[str, Any] | None, record: logging.LogRecord) -> str:
    if classification and classification.get("severity"):
        sev = str(classification.get("severity")).strip().lower()
        if sev in ("critical", "high", "medium", "low", "noise"):
            return sev
    return "critical" if record.levelno >= logging.CRITICAL else "high"


def _markdown_export_filename(
    record: logging.LogRecord, fp: str, branch: str, repo_slug: str | None = None
) -> str:
    unix_ts = str(int(record.created))
    level = record.levelname.upper()
    repo = re.sub(r"[^a-zA-Z0-9_.-]+", "-", (repo_slug or _repo_slug())).strip("-")[:72] or "scd"
    return f"{level}_{unix_ts}_{_branch_slug(branch)}_{repo}.md"


def _issues_repo_name() -> str:
    return (
        os.getenv("SCD_ISSUES_INDEX_REPO", "").strip()
        or os.getenv("SCD_ISSUES_MD_GITHUB_REPO", "").strip()
        or str(_issues_md_runtime.get("markdown_github_repo") or "").strip()
        or "Personhood-Social/Issues"
    )


def _record_issues_md_runtime(
    *,
    markdown_github_repo: str | None,
    issues_md_token_effective: str,
    markdown_github_push: bool,
) -> None:
    global _issues_md_runtime
    _issues_md_runtime = {
        "markdown_github_repo": (markdown_github_repo or "").strip(),
        "issues_md_token_effective": (issues_md_token_effective or "").strip(),
        "markdown_github_push": bool(markdown_github_push),
    }


def _ensure_markdown_repo_layout(root: Path) -> None:
    base = Path(root)
    for folder in (_MD_FOLDER_DEBUG, _MD_FOLDER_INFO):
        (base / folder).mkdir(parents=True, exist_ok=True)
    for folder in (_MD_FOLDER_WARN, _MD_FOLDER_ERROR):
        for state in (_MD_STATE_UNRESOLVED, _MD_STATE_IN_PROGRESS, _MD_STATE_RESOLVED):
            (base / folder / state).mkdir(parents=True, exist_ok=True)


def _issues_markdown_github_config() -> dict[str, str | bool]:
    token = (
        os.getenv("SCD_ISSUES_MD_GITHUB_TOKEN", "").strip()
        or os.getenv("AGENT_INTAKE_GITHUB_TOKEN", "").strip()
        or os.getenv("GITHUB_TOKEN", "").strip()
        or os.getenv("GITHUB_ISSUE_TOKEN", "").strip()
        or str(_issues_md_runtime.get("issues_md_token_effective") or "").strip()
    )
    # Push is enabled if SCD_ISSUES_MD_GITHUB_PUSH is truthy. If unset, default to mirroring
    # whenever any PAT is available (opt-out with SCD_ISSUES_MD_GITHUB_PUSH=0|false|no|off).
    push_raw = os.getenv("SCD_ISSUES_MD_GITHUB_PUSH", "").strip()
    if push_raw:  # noqa: SIM108
        enabled = _truthy_env(push_raw)
    else:
        enabled = bool(token)
    return {
        "enabled": enabled,
        "repo": _issues_repo_name(),
        "token": token,
        "branch": os.getenv("SCD_ISSUES_MD_GITHUB_BRANCH", "main").strip() or "main",
        "subdir": os.getenv("SCD_ISSUES_MD_GITHUB_SUBDIR", "").strip().strip("/"),
    }


def _markdown_export_targets(
    root: Path,
    record: logging.LogRecord,
    fp: str,
    classification: dict[str, Any] | None,
) -> list[tuple[str, Path]]:
    utc_day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    branch, _ = _git_info()
    fname = _markdown_export_filename(record, fp, branch)
    severity_bucket = _severity_bucket(classification, record)
    base = Path(root)

    targets: list[tuple[str, Path]] = [
        (_MD_FOLDER_DEBUG, base / _MD_FOLDER_DEBUG / utc_day / fname),
    ]
    if record.levelno == logging.INFO:
        targets.append((_MD_FOLDER_INFO, base / _MD_FOLDER_INFO / utc_day / fname))
    if record.levelno == logging.WARNING and not _is_noise_record(record):
        targets.append(
            (
                _MD_FOLDER_WARN,
                base / _MD_FOLDER_WARN / _MD_STATE_UNRESOLVED / severity_bucket / utc_day / fname,
            )
        )
    if record.levelno >= logging.ERROR:
        targets.append(
            (
                _MD_FOLDER_ERROR,
                base / _MD_FOLDER_ERROR / _MD_STATE_UNRESOLVED / severity_bucket / utc_day / fname,
            )
        )
    return targets


def _write_markdown_exports(
    *,
    root: Path,
    record: logging.LogRecord,
    fp: str,
    classification: dict[str, Any] | None,
    service: str,
) -> list[dict[str, str]]:
    _ensure_markdown_repo_layout(root)
    doc = _build_markdown_export_document(record, fp, classification, service=service)
    targets = _markdown_export_targets(root, record, fp, classification)
    metadata: list[dict[str, str]] = []
    for folder_label, dest in targets:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(doc, encoding="utf-8")
        metadata.append(
            {
                "folder": folder_label,
                "path": str(dest),
                "relative_path": dest.relative_to(root).as_posix(),
            }
        )
    return metadata


def _render_markdown_export_entries(
    *,
    record: logging.LogRecord,
    fp: str,
    classification: dict[str, Any] | None,
    service: str,
) -> tuple[str, list[dict[str, str]]]:
    doc = _build_markdown_export_document(record, fp, classification, service=service)
    virtual_root = Path("/__issues__")
    entries: list[dict[str, str]] = []
    for folder_label, dest in _markdown_export_targets(virtual_root, record, fp, classification):
        entries.append(
            {
                "folder": folder_label,
                "path": str(dest),
                "relative_path": dest.relative_to(virtual_root).as_posix(),
            }
        )
    return doc, entries


def _push_markdown_entries_to_github(
    *,
    doc: str,
    entries: list[dict[str, str]],
) -> None:
    cfg = _issues_markdown_github_config()
    if not cfg["enabled"] or not cfg["repo"] or not cfg["token"]:
        return
    subdir = str(cfg["subdir"])
    for item in entries:
        rel_path = item["relative_path"]
        if subdir:
            rel_path = f"{subdir}/{rel_path}"
        _push_markdown_to_github(
            token=str(cfg["token"]),
            repo_full_name=str(cfg["repo"]),
            repo_relative_path=rel_path,
            content=doc,
            commit_message=f"auto: [{item['folder']}] {rel_path}",
        )


def _dispatch_json_webhook(
    *,
    url: str,
    secret: str,
    timeout: float,
    payload: dict[str, Any],
    webhook_name: str,
) -> None:
    if not url:
        return
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "SCD-issue-tracker/1.0",
    }
    if secret:
        headers["Authorization"] = f"Bearer {secret}"
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            if int(getattr(response, "status", 200)) >= 300:
                logging.getLogger(__name__).warning(
                    "%s returned status=%s url=%s",
                    webhook_name,
                    getattr(response, "status", "unknown"),
                    url,
                )
    except urllib.error.HTTPError as exc:
        logging.getLogger(__name__).warning(
            "%s HTTP error status=%s url=%s: %s",
            webhook_name,
            exc.code,
            url,
            exc,
        )
    except Exception as exc:
        logging.getLogger(__name__).warning("%s dispatch failed url=%s: %s", webhook_name, url, exc)


def _build_openclaw_webhook_payload(
    *,
    record: logging.LogRecord,
    fp: str,
    classification: dict[str, Any] | None,
    service: str,
    github_issue_url: str | None = None,
    markdown_exports: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    cls = classification or {}
    bundle = _event_bundle_for_classification(record)
    markdown_exports = markdown_exports or []
    primary_markdown = markdown_exports[0] if markdown_exports else {}
    return {
        "source": "scd.issue_tracker",
        "service": service,
        "issue_fingerprint": fp,
        "github_issue_url": github_issue_url,
        "issues_repo": _issues_repo_name(),
        "markdown_primary": primary_markdown,
        "event": bundle,
        "classification": cls,
        "templates": {
            "execution": _load_openclaw_template("OPENCLAW_ISSUE_EXECUTION_TEMPLATE.md"),
            "pull_request": _load_openclaw_template("OPENCLAW_PR_TEMPLATE.md"),
        },
        "issue_contract": {
            "what_happened": cls.get("summary") or bundle.get("message"),
            "why_it_happened": cls.get("root_cause_hypothesis", ""),
            "what_triggers_it": cls.get("trigger_conditions", ""),
            "how_to_fix_it": cls.get("fix_summary", ""),
            "how_to_handle_it": cls.get("handling_summary", ""),
            "verification": cls.get("verification", ""),
        },
        "markdown_exports": markdown_exports,
    }


def _dispatch_openclaw_webhook(
    *,
    record: logging.LogRecord,
    fp: str,
    classification: dict[str, Any] | None,
    service: str,
    github_issue_url: str | None = None,
    markdown_exports: list[dict[str, str]] | None = None,
) -> None:
    url = os.getenv("SCD_ISSUES_OPENCLAW_WEBHOOK_URL", "").strip()
    if not url:
        return
    secret = os.getenv("SCD_ISSUES_OPENCLAW_WEBHOOK_SECRET", "").strip()
    timeout = float(os.getenv("SCD_ISSUES_OPENCLAW_WEBHOOK_TIMEOUT_SEC", "10"))
    payload = _build_openclaw_webhook_payload(
        record=record,
        fp=fp,
        classification=classification,
        service=service,
        github_issue_url=github_issue_url,
        markdown_exports=markdown_exports,
    )
    _dispatch_json_webhook(
        url=url,
        secret=secret,
        timeout=timeout,
        payload=payload,
        webhook_name="OpenClaw webhook",
    )


def _dispatch_index_webhook(
    *,
    record: logging.LogRecord,
    fp: str,
    classification: dict[str, Any] | None,
    service: str,
    github_issue_url: str | None = None,
    markdown_exports: list[dict[str, str]] | None = None,
) -> None:
    url = os.getenv("SCD_ISSUES_INDEX_WEBHOOK_URL", "").strip()
    if not url:
        return
    secret = os.getenv("SCD_ISSUES_INDEX_WEBHOOK_SECRET", "").strip()
    timeout = float(os.getenv("SCD_ISSUES_INDEX_WEBHOOK_TIMEOUT_SEC", "10"))
    payload = _build_openclaw_webhook_payload(
        record=record,
        fp=fp,
        classification=classification,
        service=service,
        github_issue_url=github_issue_url,
        markdown_exports=markdown_exports,
    )
    payload["index_contract"] = {
        "role": "authoritative-incident-index",
        "completion_callback_expected": True,
        "consolidation_interval_hours": 3,
        "issues_repo": _issues_repo_name(),
        "initial_status": _MD_STATE_UNRESOLVED.lower(),
        "supports_related_issue_lookup": True,
        "semantic_similarity_source": "windsurf-embeddings",
        "lifecycle_states": [
            _MD_STATE_UNRESOLVED,
            _MD_STATE_IN_PROGRESS,
            _MD_STATE_RESOLVED,
        ],
    }
    _dispatch_json_webhook(
        url=url,
        secret=secret,
        timeout=timeout,
        payload=payload,
        webhook_name="Issue index webhook",
    )


def _log_gravity_v2_init_once(issue_log: logging.Logger) -> None:
    global _gravity_v2_init_logged
    if _gravity_v2_init_logged:
        return
    runtime = _gravity_v2_runtime_metadata()
    accounts_path = runtime.get("gravity_v2_accounts_path")
    backend = runtime.get("issues_remediation_backend")
    if accounts_path:
        issue_log.info(
            "Issue tracking Gravity V2 configured backend=%s accounts_source=%s accounts_path=%s summary_model=%s remediation_model=%s",
            backend,
            runtime.get("gravity_v2_accounts_source"),
            accounts_path,
            runtime.get("issues_summary_model"),
            runtime.get("issues_remediation_model") or "(external)",
        )
    else:
        issue_log.warning(
            "Issue tracking Gravity V2 accounts path not set; backend=%s source=%s summary_model=%s remediation_model=%s",
            backend,
            runtime.get("gravity_v2_accounts_source"),
            runtime.get("issues_summary_model"),
            runtime.get("issues_remediation_model") or "(external)",
        )
    _gravity_v2_init_logged = True


def _parse_llm_json_object(raw: str) -> dict[str, Any] | None:
    text = (raw or "").strip()
    if text.startswith("```"):
        parts = text.split("```")
        text = parts[1] if len(parts) > 1 else text
        if text.startswith("json"):
            text = text[4:].lstrip()
    try:
        out = json.loads(text.strip())
    except json.JSONDecodeError:
        return None
    return out if isinstance(out, dict) else None


async def _async_gravity_chat_json(
    *,
    model: str,
    prompt: str,
    timeout_sec: float,
) -> dict[str, Any] | None:
    from gravity import AsyncGravityClient
    from gravity.io import load_accounts

    accounts_path, _ = _resolve_gravity_v2_accounts_path()
    try:
        accounts = load_accounts(accounts_path)
    except Exception:
        from gravity.accounts import AccountsFile

        accounts = AccountsFile(accounts=[])

    client = AsyncGravityClient(accounts=accounts)
    try:
        from gravity.types import Message

        response = await asyncio.wait_for(
            client.chat(model=model, messages=[Message(role="user", content=prompt)]),
            timeout=timeout_sec,
        )
        raw = str(getattr(getattr(response, "message", None), "content", "") or "").strip()
        return _parse_llm_json_object(raw)
    except (asyncio.TimeoutError, TimeoutError, Exception):
        return None
    finally:
        with contextlib.suppress(Exception):
            await client.close()


def _sync_gravity_chat_json(
    *, model: str, prompt: str, timeout_sec: float
) -> dict[str, Any] | None:
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            fut = pool.submit(
                asyncio.run,
                _async_gravity_chat_json(model=model, prompt=prompt, timeout_sec=timeout_sec),
            )
            return fut.result(timeout=max(timeout_sec + 5.0, 15.0))
    except Exception:
        return None


def _run_openclaw_stage2(
    *,
    record: logging.LogRecord,
    stage1: dict[str, Any],
    bundle: dict[str, str],
) -> dict[str, Any] | None:
    command = os.getenv("OPENCLAW_STAGE2_COMMAND", "").strip()
    if not command:
        return None

    timeout: float | None = None
    timeout_raw = os.getenv("SCD_ISSUES_OPENCLAW_TIMEOUT_SEC", "").strip()
    if timeout_raw:
        with contextlib.suppress(ValueError):
            parsed_timeout = float(timeout_raw)
            if parsed_timeout > 0:
                timeout = parsed_timeout

    payload = {
        "event": bundle,
        "stage1": {
            key: stage1.get(key)
            for key in ("summary", "severity", "components", "type", "is_noise")
            if key in stage1
        },
        "issue_fingerprint": _issue_fingerprint(record),
        "logger": record.name,
        "level": record.levelname,
        "repo": {
            "root": str(Path(__file__).resolve().parents[3]),
            "branch": _git_info()[0],
            "commit": _git_info()[1],
        },
        "templates": {
            "pull_request": _load_openclaw_template("OPENCLAW_PR_TEMPLATE.md"),
            "issue_execution": _load_openclaw_template("OPENCLAW_ISSUE_EXECUTION_TEMPLATE.md"),
        },
        "required_outputs": {
            "remediation_markdown": "Markdown bullet list of implementation steps or actual work completed",
            "verification": "Targeted tests or smoke checks performed or required",
            "root_cause_hypothesis": "Why the issue happened",
            "trigger_conditions": "What situation reproduces or triggers the bug",
            "fix_summary": "How the fix resolves the bug",
            "handling_summary": "How the system now handles the issue or degraded mode",
            "pr_title": "Pull request title if code changes were made",
            "pr_body_markdown": "Pull request body using the provided template",
            "pr_url": "Created PR URL if available",
        },
    }

    try:
        completed = subprocess.run(
            shlex.split(command),
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except Exception as exc:
        logging.getLogger(__name__).warning("OpenClaw Stage 2 command failed to start: %s", exc)
        return None

    if completed.returncode != 0:
        logging.getLogger(__name__).warning(
            "OpenClaw Stage 2 command exited non-zero rc=%s stderr=%s",
            completed.returncode,
            _redact((completed.stderr or "").strip()[:500]),
        )
        return None

    parsed = _parse_llm_json_object(completed.stdout or "")
    if parsed is None:
        logging.getLogger(__name__).warning(
            "OpenClaw Stage 2 command returned invalid JSON stdout=%s",
            _redact((completed.stdout or "").strip()[:500]),
        )
    return parsed


def _event_bundle_for_classification(record: logging.LogRecord) -> dict[str, str]:
    crash_file, crash_line = _innermost_frame(record)
    tb_text = ""
    if record.exc_info:
        tb_text = "".join(traceback.format_exception(*record.exc_info)).rstrip()[-1200:]
    crumb_lines = []
    for r in list(_breadcrumbs)[-5:]:
        if r is not record:
            crumb_lines.append(f"[{r.levelname}] {r.name}: {r.getMessage()[:120]}")
    breadcrumbs_text = "\n".join(crumb_lines) or "(none)"
    return {
        "level": record.levelname,
        "logger": record.name,
        "message": record.getMessage()[:300],
        "culprit": f"{crash_file}:{crash_line}",
        "stacktrace": tb_text or "(no stack trace)",
        "breadcrumbs": breadcrumbs_text,
    }


class _BreadcrumbHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        _breadcrumbs.append(record)


def _git_info() -> tuple[str, str]:
    def _run(cmd: list[str]) -> str:
        try:
            return subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode().strip()
        except Exception:
            return "unknown"

    return _run(["git", "rev-parse", "--abbrev-ref", "HEAD"]), _run(
        ["git", "rev-parse", "--short", "HEAD"]
    )


def _source_context(path: str, lineno: int, context: int = 7) -> str:
    if not path or not os.path.isfile(path):
        return ""
    start = max(1, lineno - context)
    out = []
    for i in range(start, lineno + context + 1):
        raw = linecache.getline(path, i)
        if not raw:
            break
        marker = ">>>" if i == lineno else "   "
        out.append(f"{marker} {i:4d} | {raw.rstrip()}")
    return "\n".join(out)


def _innermost_frame(record: logging.LogRecord) -> tuple[str, int]:
    if record.exc_info and record.exc_info[2]:
        tb = record.exc_info[2]
        while tb.tb_next:
            tb = tb.tb_next
        return tb.tb_frame.f_code.co_filename, tb.tb_lineno
    return record.pathname, record.lineno


def _frame_locals(record: logging.LogRecord) -> dict[str, str]:
    if not record.exc_info or not record.exc_info[2]:
        return {}
    tb = record.exc_info[2]
    while tb.tb_next:
        tb = tb.tb_next
    return {k: _redact(repr(v), key=k) for k, v in list(tb.tb_frame.f_locals.items())[:50]}


def _issue_fingerprint(record: logging.LogRecord) -> str:
    exc_type = record.exc_info[0].__name__ if record.exc_info and record.exc_info[0] else ""
    crash_file, crash_line = _innermost_frame(record)
    raw = f"{exc_type}:{crash_file}:{crash_line}"
    return hashlib.sha1(raw.encode()).hexdigest()[:10].upper()


# ── LLM classification (Gravity, two-stage) ──────────────────────────────────


def _classification_cache_key(record: logging.LogRecord) -> str:
    msg_digest = hashlib.sha1(record.getMessage().encode(errors="replace")).hexdigest()[:12]
    return f"{_issue_fingerprint(record)}:{msg_digest}"


def _classify_with_windsurf_uncached(record: logging.LogRecord) -> dict[str, Any] | None:
    """Two-stage Gravity classify: summary model (default Windsurf) then remediation model (default cursor/auto)."""
    bundle = _event_bundle_for_classification(record)
    prompt1 = _CLASSIFICATION_PROMPT_STAGE1_SUMMARY.format(**bundle)

    summary_model = os.getenv("SCD_ISSUES_SUMMARY_MODEL", "windsurf/swe-1-6-fast").strip()
    summary_timeout = float(os.getenv("SCD_ISSUES_SUMMARY_TIMEOUT_SEC", "12"))

    stage1 = _sync_gravity_chat_json(
        model=summary_model,
        prompt=prompt1,
        timeout_sec=summary_timeout,
    )
    if not stage1:
        return None

    skip_r2 = os.getenv("SCD_ISSUES_REMEDIATION_SKIP", "").lower() in ("1", "true", "yes")
    merged: dict[str, Any] = dict(stage1)
    merged.update(_gravity_v2_runtime_metadata())

    if not skip_r2:
        backend = str(merged.get("issues_remediation_backend") or "gravity").lower()
        stage2: dict[str, Any] | None = None
        if backend == "openclaw":
            stage2 = _run_openclaw_stage2(record=record, stage1=stage1, bundle=bundle)
        else:
            remediation_model = os.getenv("SCD_ISSUES_REMEDIATION_MODEL", "cursor/auto").strip()
            remediation_timeout = float(os.getenv("SCD_ISSUES_REMEDIATION_TIMEOUT_SEC", "45"))
            stage1_compact = json.dumps(
                {
                    k: stage1.get(k)
                    for k in ("summary", "severity", "components", "type", "is_noise")
                    if k in stage1
                },
                default=str,
            )
            prompt2 = _CLASSIFICATION_PROMPT_STAGE2_REMEDIATION.format(
                stage1_json=stage1_compact[:4000],
                **bundle,
            )
            stage2 = _sync_gravity_chat_json(
                model=remediation_model,
                prompt=prompt2,
                timeout_sec=remediation_timeout,
            )
        if stage2:
            for key in (
                "remediation_markdown",
                "verification",
                "root_cause_hypothesis",
                "trigger_conditions",
                "fix_summary",
                "handling_summary",
                "pr_title",
                "pr_body_markdown",
                "pr_url",
            ):
                if key in stage2 and stage2[key] is not None:
                    merged[key] = stage2[key]

    return merged


def _classify_with_windsurf(record: logging.LogRecord) -> dict[str, Any] | None:
    ttl = float(os.getenv("SCD_ISSUES_CLASSIFICATION_CACHE_TTL", "300"))
    key = _classification_cache_key(record)
    now = time.monotonic()
    with _classification_cache_lock:
        hit = _classification_cache.get(key)
        if hit and now - hit[0] < ttl:
            return hit[1]
    result = _classify_with_windsurf_uncached(record)
    with _classification_cache_lock:
        _classification_cache[key] = (now, result)
        stale = [k for k, (t, _) in _classification_cache.items() if now - t > ttl]
        for k in stale[:100]:
            _classification_cache.pop(k, None)
        max_entries = int(os.getenv("SCD_ISSUES_CLASSIFICATION_CACHE_MAX", "256"))
        if max_entries > 0 and len(_classification_cache) > max_entries:
            overflow = sorted(_classification_cache.items(), key=lambda item: item[1][0])[
                : len(_classification_cache) - max_entries
            ]
            for stale_key, _ in overflow:
                _classification_cache.pop(stale_key, None)
    return result


# ── Body builder ─────────────────────────────────────────────────────────────


# Messages that indicate expected graceful degradation — never worth a GitHub issue.
_NOISE_SUBSTRINGS: tuple[str, ...] = (
    "kms store degraded due to runtime auth/pool failure",
    "kms entering degraded cooldown",
    "memory search degraded due to kms auth/pool failure",
    "returning empty results due to kms error",
    "kms transient db error during query",
    "timeouterror: memory search failed in kms 3.0",
    "timeouterror: failed to add memory via kms 3.0",
    "kms auth recovery also failed",
    "gravity fallback engaged",
    "bridge closed cleanly runtime",
    "gemini api-key call returned 404 on vertex endpoint",
    "retrying (githubretry",  # urllib3 retry noise
    "filtered non-structured fallback models",  # only fires when models still available
    "kms 3.0 not installed",  # local dev env issue, not prod code bug
    'form data requires "python-multipart"',  # local env issue
    "proactive ai timeout after",  # handled gracefully by skipping tick
    "proactive ai returned degraded payload",  # downstream of JSON parse, now fixed
    "orchestrator heartbeat proactive check failed",  # downstream of JSON parse, now fixed
    "failed to store seeded memory",  # pool saturation write failure
    "upsert skipped",  # pool saturation, already WARNING in kms
    "[cron] ⚠ skipped fact promotion",  # pool saturation in promoter, WARNING
    "background re-caching failed: 429",  # GCP quota — expected under load
    "unexpected connection_lost() call",  # asyncio transient on reconnect
    "rate limit exceeded on gcp:",  # GCP rate-limit; circuit breaker handles recovery
    "gravity key term extraction failed",  # falls back to word-split; graceful
    "gcp key term extraction failed",  # same fallback path
    "kms query model construction failed, falling back",  # graceful fallback on query build
    "memory search failed in kms 3.0 (schema mismatch",  # old stored data mismatch, not actionable
    "heartbeatloop proactive sweep timed out",  # dropped tick, not a crash
    "requeued 1 stale intent lease",  # background requeue, informational
    "dating session attempt",  # retry with fallback; recovers automatically
    "ai decision engine attempt 1 failed",  # retry in same session; self-heals
    "heartbeatloop stop_async timeout",  # force-cancel on stop; not a crash
    "no healthy worker heartbeat loop",  # startup race; transient
    "reclaimed 1 stale worker",  # housekeeping, not actionable
    "dropped tool call",  # proactive arbitration filter; correct behavior
    "dropped proactive tool",  # same arbitration filter
    "could not access kms redis:",  # startup race; redis not yet connected
    "curl: (28)",  # curl DNS/connect timeout; network infra issue
    "curl: (35)",  # curl TLS error; network infra issue
    "failed to resolve",  # DNS failure; infra issue, not code
    "legacy jwt auth used",  # informational; old client, not a bug
    "firebase token verification failed: invalidid",  # client-side malformed token
    "reclaimed 1 stale queue",  # worker queue housekeeping
    "reclaimed 1 stale message queue",  # same
    "[workerqueue] reclaimed",  # same
    "bridge fabric disconnected",  # transient WS reconnect, expected
    "ws_handshake_fail",  # client connecting without valid token; not a code bug
    "aif_ws_bridge disconnected",  # transient reconnect, not a crash
    "ws heartbeat stale",  # connection evicted by heartbeat; expected behavior
    "timed out draining",  # graceful shutdown timeout; non-critical
    "authentication error",  # model auth failure; fallbacks handle it
    "unavailable after",  # model exhausted retries but gracefully returns null
    "reflector analysis skipped",  # evolution engine validation skip; non-critical
    "stranger-vulnerability surgical edit unavailable",  # model unavailable, graceful
)


def _is_noise_record(record: logging.LogRecord) -> bool:
    msg_lower = record.getMessage().lower()
    return any(s in msg_lower for s in _NOISE_SUBSTRINGS)


def _slug_logger_component(name: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9_.-]+", "_", (name or "").strip())
    return (s or "logger")[:72]


def _default_remediation_boilerplate(record: logging.LogRecord) -> str:
    crash_file, crash_line = _innermost_frame(record)
    return (
        "- Inspect the culprit frame and recent breadcrumbs below.\n"
        "- Reproduce in staging with the same `logger` / `issue_fingerprint` filter.\n"
        "- Add or extend a targeted regression test under `scd/tests/` for the failing module.\n"
        f"- Primary code reference: `{crash_file}:{crash_line}`."
    )


def _default_verification_boilerplate() -> str:
    return (
        "Run the smallest scoped pytest slice for the touched subsystem; smoke-test "
        "the affected API path; confirm error rate / logs drop for this fingerprint."
    )


def _append_optional_section(parts: list[str], title: str, value: object) -> None:
    text = str(value or "").strip()
    if text:
        parts.extend([title, text, ""])


def _build_markdown_export_document(
    record: logging.LogRecord,
    fp: str,
    classification: dict[str, Any] | None,
    *,
    service: str,
) -> str:
    crash_file, crash_line = _innermost_frame(record)
    branch, commit = _git_info()
    env = os.getenv("ENVIRONMENT", "production")
    release = os.getenv("VERSION", "unknown")
    now = datetime.now(timezone.utc)
    exported_at = now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    cls = classification or {}
    fm_lines = [
        "---",
        'schema_version: "scd-issue-export/1.1"',
        f'service: "{service}"',
        f"log_level: {record.levelname}",
        f"issue_fingerprint: {fp}",
        f'exported_at_utc: "{exported_at}"',
        f'logger: "{record.name}"',
        f'culprit: "{crash_file}:{crash_line}"',
        f'pathname: "{record.pathname}:{record.lineno}"',
        f'environment: "{env}"',
        f'release: "{release}"',
        f'git_branch: "{branch}"',
        f'git_commit: "{commit}"',
    ]
    if cls.get("severity"):
        fm_lines.append(f'classification_severity: "{cls.get("severity")}"')
    if cls.get("type"):
        fm_lines.append(f'classification_type: "{cls.get("type")}"')
    if cls.get("regions"):
        fm_lines.append(
            f'classification_regions: "{",".join(str(part) for part in cls.get("regions", []))}"'
        )
    if "is_noise" in cls:
        fm_lines.append(f"classification_is_noise: {str(bool(cls.get('is_noise'))).lower()}")
    for key in (
        "issues_summary_model",
        "issues_remediation_backend",
        "issues_remediation_model",
        "gravity_v2_accounts_source",
    ):
        value = cls.get(key)
        if value:
            fm_lines.append(f'{key}: "{value}"')
    fm_lines.append("---")

    hub = GitHubIssueHandler.__new__(GitHubIssueHandler)
    hub._service = service
    hub._repo = None
    hub._gh = None
    hub._cache = {}
    diagnostic = GitHubIssueHandler._build_body(
        hub, record, fp, classification, include_remediation_sections=False
    )

    remediation = (cls.get("remediation_markdown") or "").strip()
    if not remediation:
        remediation = _default_remediation_boilerplate(record)

    verification = (cls.get("verification") or "").strip()
    if not verification:
        verification = _default_verification_boilerplate()

    hypothesis = (cls.get("root_cause_hypothesis") or "").strip()

    parts: list[str] = [
        "\n".join(fm_lines),
        "",
        f"# SCD automated export (`{service}`)",
        "",
        "## How to fix",
        remediation,
        "",
        "## Verification",
        verification,
        "",
    ]
    if hypothesis:
        parts.extend(["## Root cause hypothesis", hypothesis, ""])
    _append_optional_section(parts, "## Trigger conditions", cls.get("trigger_conditions"))
    _append_optional_section(parts, "## Fix summary", cls.get("fix_summary"))
    _append_optional_section(parts, "## Handling summary", cls.get("handling_summary"))
    _append_optional_section(
        parts, "## Affected regions", ", ".join(str(part) for part in cls.get("regions", []))
    )
    _append_optional_section(parts, "## Proposed PR title", cls.get("pr_title"))
    _append_optional_section(parts, "## Proposed PR body", cls.get("pr_body_markdown"))
    _append_optional_section(parts, "## Proposed PR URL", cls.get("pr_url"))
    parts.extend(["## Diagnostic report", "", diagnostic, ""])
    return "\n".join(parts)


def _push_markdown_to_github(
    *,
    token: str,
    repo_full_name: str,
    repo_relative_path: str,
    content: str,
    commit_message: str,
) -> None:
    if not (_GH_AVAILABLE and Github is not None and Auth is not None):
        return
    retry = GithubRetry(total=2, backoff_factor=0.5) if GithubRetry else None
    gh_kwargs: dict[str, Any] = {"auth": Auth.Token(token)}
    if retry is not None:
        gh_kwargs["retry"] = retry
    gh = Github(**gh_kwargs)
    try:
        repo = gh.get_repo(repo_full_name)
        branch = os.getenv("SCD_ISSUES_MD_GITHUB_BRANCH", "main")
        path = repo_relative_path.replace("\\", "/")
        try:
            repo.create_file(
                path=path,
                message=commit_message,
                content=content,
                branch=branch,
            )
        except GithubException:
            existing = repo.get_contents(path, ref=branch)
            if isinstance(existing, list):
                return
            repo.update_file(
                path=path,
                message=commit_message,
                content=content,
                sha=existing.sha,
                branch=branch,
            )
    except Exception as exc:
        logging.getLogger(__name__).warning(
            "Markdown issue GitHub push failed path=%s repo=%s: %s",
            repo_relative_path,
            repo_full_name,
            exc,
        )


class MarkdownIssueExportHandler(logging.Handler):
    """Writes Markdown exports under Warn/, Error/, Debug/, INFO/ (see Issues/docs/TEMPLATE.md)."""

    def __init__(
        self,
        *,
        root: Path,
        service: str,
        level: int = logging.DEBUG,
        github_repo: str | None = None,
        github_token: str = "",
        github_push: bool = False,
    ) -> None:
        super().__init__(level)
        self._root = Path(root)
        self._service = service
        self._github_repo = (github_repo or "").strip()
        self._github_token = github_token.strip()
        self._github_push = bool(
            github_push and self._github_repo and self._github_token and _GH_AVAILABLE
        )
        self._queue: queue.Queue[logging.LogRecord | None] = queue.Queue(
            maxsize=int(os.getenv("SCD_ISSUES_MD_QUEUE_SIZE", "128"))
        )
        self._write_lock = threading.Lock()
        self._worker = threading.Thread(
            target=self._worker_loop,
            daemon=True,
            name=f"{service}-markdown-issue-worker",
        )
        self._worker.start()

    def _worker_loop(self) -> None:
        while True:
            record = self._queue.get()
            if record is None:
                return
            try:
                self._emit_now(record)
            finally:
                self._queue.task_done()

    def _emit_now(self, record: logging.LogRecord) -> None:
        fp = _issue_fingerprint(record)

        classification = None
        skip_ai = os.getenv("SCD_ISSUES_MD_SKIP_AI", "").lower() in ("1", "true", "yes")
        classify_debug = os.getenv("SCD_ISSUES_MD_CLASSIFY_DEBUG", "").lower() in (
            "1",
            "true",
            "yes",
        )
        should_classify = False
        if not skip_ai:
            should_classify = (
                record.levelno >= logging.WARNING and not _is_noise_record(record)
            ) or (record.levelno == logging.DEBUG and classify_debug)
        if should_classify:
            classification = _classify_with_windsurf(record)

        try:
            with self._write_lock:
                written = _write_markdown_exports(
                    root=self._root,
                    record=record,
                    fp=fp,
                    classification=classification,
                    service=self._service,
                )
        except OSError as exc:
            logging.getLogger(__name__).warning(
                "Markdown issue export write failed fingerprint=%s: %s", fp, exc
            )
            return

        doc = _build_markdown_export_document(record, fp, classification, service=self._service)
        _push_markdown_entries_to_github(doc=doc, entries=written)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self._queue.put_nowait(record)
        except queue.Full:
            return


class GitHubIssueHandler(logging.Handler):
    DEDUP_TTL = 3600

    def __init__(self, token: str, repo: str, service: str, level: int = logging.ERROR) -> None:
        super().__init__(level)
        self._service = service
        self._token = token
        self._cache: dict[str, float] = {}
        self._queue: queue.Queue[logging.LogRecord | None] = queue.Queue(
            maxsize=int(os.getenv("GITHUB_ISSUE_QUEUE_SIZE", "64"))
        )
        self._worker = threading.Thread(
            target=self._worker_loop, daemon=True, name=f"{service}-issue-worker"
        )
        self._worker.start()
        if _GH_AVAILABLE and token:
            # Hard-cap retries: GithubRetry default=10 with SSL EOF → blocks thread 2+ hours.
            _retry = GithubRetry(total=2, backoff_factor=0.5) if GithubRetry else None
            _gh_kwargs: dict = {"auth": Auth.Token(token)}
            if _retry is not None:
                _gh_kwargs["retry"] = _retry
            self._gh = Github(**_gh_kwargs)
            self._repo = self._gh.get_repo(repo)
        else:
            self._gh = None
            self._repo = None

    def _fingerprint(self, record: logging.LogRecord) -> str:
        return _issue_fingerprint(record)

    def _is_duplicate(self, fp: str) -> bool:
        now = time.monotonic()
        if self._cache.get(fp, 0) + self.DEDUP_TTL > now:
            return True
        self._cache[fp] = now
        self._cache = {k: v for k, v in self._cache.items() if now - v < self.DEDUP_TTL}
        return False

    def _build_body(
        self,
        record: logging.LogRecord,
        fp: str,
        classification: dict[str, Any] | None,
        *,
        include_remediation_sections: bool = True,
    ) -> str:
        env = os.getenv("ENVIRONMENT", "production")
        server = os.getenv("SERVER_NAME", os.uname().nodename)
        release = os.getenv("VERSION", "unknown")
        branch, commit = _git_info()
        now = datetime.now(timezone.utc)
        timestamp = now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

        crash_file, crash_line = _innermost_frame(record)
        tb_text = "No stack trace available"
        if record.exc_info:
            tb_text = "".join(traceback.format_exception(*record.exc_info)).rstrip()

        src_ctx = _source_context(crash_file, crash_line)
        f_locals = _frame_locals(record)
        crumbs = [r for r in _breadcrumbs if r is not record][-20:]

        sections: list[str] = []

        # ── AI Summary ────────────────────────────────────────────────────
        if classification and classification.get("summary"):
            sev = classification.get("severity", "?")
            is_noise = classification.get("is_noise", False)
            noise_badge = " ⚠️ _classified as noise_" if is_noise else ""
            sections.append(
                f"## Summary{noise_badge}\n\n> {classification['summary']}\n\n"
                f"**Severity:** `{sev}` &nbsp;|&nbsp; "
                f"**Type:** `{classification.get('type', '?')}` &nbsp;|&nbsp; "
                f"**Components:** {', '.join(f'`{c}`' for c in classification.get('components', [])) or '_unknown_'}"
            )
            if include_remediation_sections:
                if classification.get("remediation_markdown"):
                    sections.append(
                        "## How to fix (recommended)\n\n"
                        + str(classification["remediation_markdown"]).strip()
                    )
                if classification.get("verification"):
                    sections.append(
                        "## Verification\n\n" + str(classification["verification"]).strip()
                    )
                if classification.get("root_cause_hypothesis"):
                    sections.append(
                        "## Root cause hypothesis\n\n"
                        + str(classification["root_cause_hypothesis"]).strip()
                    )
                if classification.get("trigger_conditions"):
                    sections.append(
                        "## Trigger conditions\n\n"
                        + str(classification["trigger_conditions"]).strip()
                    )
                if classification.get("fix_summary"):
                    sections.append(
                        "## Fix summary\n\n" + str(classification["fix_summary"]).strip()
                    )
                if classification.get("handling_summary"):
                    sections.append(
                        "## Handling summary\n\n" + str(classification["handling_summary"]).strip()
                    )
                if classification.get("pr_title"):
                    sections.append(
                        "## Proposed PR title\n\n" + str(classification["pr_title"]).strip()
                    )
                if classification.get("pr_body_markdown"):
                    sections.append(
                        "## Proposed PR body\n\n" + str(classification["pr_body_markdown"]).strip()
                    )
                if classification.get("pr_url"):
                    sections.append(
                        "## Proposed PR URL\n\n" + str(classification["pr_url"]).strip()
                    )

        # ── Header table ──────────────────────────────────────────────────
        sections.append(
            "\n".join(
                [
                    "| Field | Value |",
                    "|---|---|",
                    f"| **Issue ID** | `{self._service.upper()}-{fp}` |",
                    f"| **Level** | `{record.levelname.lower()}` |",
                    f"| **First Seen** | `{timestamp}` |",
                    f"| **Environment** | `{env}` |",
                    f"| **Release** | `{release}` |",
                    f"| **Branch** | `{branch}` |",
                    f"| **Commit** | `{commit}` |",
                    f"| **Server** | `{server}` |",
                    f"| **Logger** | `{record.name}` |",
                    f"| **Culprit** | `{crash_file}:{crash_line}` |",
                    f"| **Log site** | `{record.pathname}:{record.lineno}` in `{record.funcName}` |",
                ]
            )
        )

        # ── Stack trace ───────────────────────────────────────────────────
        sections.append("## Stack Trace\n\n```python\n" + tb_text + "\n```")

        # ── Source context ────────────────────────────────────────────────
        if src_ctx:
            sections.append(
                f"## Source Context\n`{crash_file}` around line {crash_line}\n\n"
                f"```python\n{src_ctx}\n```"
            )

        # ── Local variables ───────────────────────────────────────────────
        if f_locals:
            vars_block = "\n".join(f"{k} = {v}" for k, v in f_locals.items())
            sections.append(f"## Local Variables at Crash\n\n```python\n{vars_block}\n```")

        # ── Breadcrumbs ───────────────────────────────────────────────────
        if crumbs:
            lines = ["## Breadcrumbs (Recent Activity)", ""]
            for r in crumbs:
                ts = (
                    datetime.fromtimestamp(r.created, tz=timezone.utc).strftime(
                        "%Y-%m-%dT%H:%M:%S.%f"
                    )[:-3]
                    + "Z"
                )
                lines.append(
                    f"`{ts}` **[{r.levelname.lower()}]** `{r.name}`: {_redact(r.getMessage())}"
                )
            sections.append("\n".join(lines))

        # ── Tags ──────────────────────────────────────────────────────────
        sections.append(
            "\n".join(
                [
                    "## Tags",
                    "",
                    "| Tag | Value |",
                    "|---|---|",
                    f"| environment | `{env}` |",
                    f"| level | `{record.levelname.lower()}` |",
                    f"| logger | `{record.name}` |",
                    f"| release | `{release}` |",
                    f"| branch | `{branch}` |",
                    f"| commit | `{commit}` |",
                    f"| server_name | `{server}` |",
                    f"| issues_summary_model | `{classification.get('issues_summary_model', 'unknown') if classification else 'unknown'}` |",
                    f"| issues_remediation_backend | `{classification.get('issues_remediation_backend', 'gravity') if classification else 'gravity'}` |",
                    f"| issues_remediation_model | `{classification.get('issues_remediation_model', 'n/a') if classification else 'n/a'}` |",
                    f"| gravity_v2_accounts_source | `{classification.get('gravity_v2_accounts_source', 'auto-discovery') if classification else 'auto-discovery'}` |",
                ]
            )
        )

        sections.append("---\n_Reported automatically by `issue.py` — not a manual report._")
        return "\n\n".join(sections)

    def _build_labels(
        self, record: logging.LogRecord, env: str, classification: dict[str, Any] | None
    ) -> list[str]:
        labels = ["auto-reported", f"env/{env}"]

        if classification:
            sev = classification.get("severity", "high")
            labels.append(
                f"severity/{sev}"
                if sev in ("critical", "high", "medium", "low", "noise")
                else "severity/high"
            )

            issue_type = classification.get("type", "")
            if issue_type:
                labels.append(f"type/{issue_type}")

            for comp in classification.get("components", []):
                labels.append(f"comp/{comp}")
            for region in classification.get("regions", []):
                labels.append(f"region/{region}")

            if not classification.get("is_noise", False):
                labels.append("bug")
        else:
            # Fallback hardcoded labels when classification unavailable
            labels.append(
                "severity/critical" if record.levelno >= logging.CRITICAL else "severity/high"
            )
            labels.append("bug")

        return labels

    def _ensure_labels(self, names: list[str]) -> None:
        if self._repo is None:
            return
        self._ensure_labels_on_repo(self._repo, names)

    def _ensure_labels_on_repo(self, repo: Any, names: list[str]) -> None:
        try:
            existing = {lbl.name for lbl in repo.get_labels()}
        except Exception:
            return
        for name in names:
            if name not in existing:
                color, desc = _LABEL_META.get(name, ("cccccc", ""))
                with contextlib.suppress(Exception):
                    repo.create_label(name=name, color=color, description=desc)

    def _maybe_create_upstream_issue(
        self,
        *,
        record: logging.LogRecord,
        fp: str,
        classification: dict[str, Any] | None,
        labels: list[str],
    ) -> str | None:
        msg = record.getMessage().lower()
        components = set(classification.get("components", []) if classification else [])
        if "kms-memory" not in components and "kms" not in msg:
            return None
        if not _GH_AVAILABLE or not self._token:
            return None
        with contextlib.suppress(Exception):
            upstream = Github(auth=Auth.Token(self._token)).get_repo("Personhood-Social/KMS")
            exc_name = (
                record.exc_info[0].__name__ if record.exc_info and record.exc_info[0] else None
            )
            title = f"[KMS-{fp}] {exc_name + ': ' if exc_name else ''}{record.getMessage()[:100]}"
            issue = upstream.create_issue(
                title=title,
                body=self._build_body(record, fp, classification),
                labels=[
                    label
                    for label in labels
                    if not label.startswith("comp/") or label == "comp/kms-memory"
                ],
            )
            return getattr(issue, "html_url", None)
        return None

    def _maybe_create_issues_repo_issue(
        self,
        *,
        title: str,
        record: logging.LogRecord,
        fp: str,
        classification: dict[str, Any] | None,
        markdown_exports: list[dict[str, str]],
        source_issue_url: str | None,
    ) -> str | None:
        if not _GH_AVAILABLE or not self._token:
            return None
        repo_name = _issues_repo_name()
        if not repo_name or (self._repo and repo_name == getattr(self._repo, "full_name", "")):
            return None
        try:
            issues_repo = Github(auth=Auth.Token(self._token)).get_repo(repo_name)
            self._ensure_labels_on_repo(
                issues_repo,
                [
                    "status/unresolved",
                    "source/scd",
                ],
            )
            issue = issues_repo.create_issue(
                title=title,
                body=self._build_issues_repo_issue_body(
                    record=record,
                    fp=fp,
                    classification=classification,
                    markdown_exports=markdown_exports,
                    source_issue_url=source_issue_url,
                ),
                labels=["source/scd", "status/unresolved"],
            )
            return getattr(issue, "html_url", None)
        except Exception as exc:
            logging.getLogger(__name__).warning(
                "Issues repo issue creation failed repo=%s fingerprint=%s: %s",
                repo_name,
                fp,
                exc,
            )
            return None

    def _build_issues_repo_issue_body(
        self,
        *,
        record: logging.LogRecord,
        fp: str,
        classification: dict[str, Any] | None,
        markdown_exports: list[dict[str, str]],
        source_issue_url: str | None,
    ) -> str:
        markdown_lines = []
        for item in markdown_exports:
            markdown_lines.append(f"- `{item.get('relative_path', '')}`")
        body_parts = [
            "## Source issue",
            source_issue_url or "_not created_",
            "",
            "## Markdown artifacts",
            "\n".join(markdown_lines) or "_none_",
            "",
            self._build_body(record, fp, classification),
        ]
        return "\n".join(body_parts)

    def _worker_loop(self) -> None:
        while True:
            record = self._queue.get()
            if record is None:
                return
            try:
                self._emit_now(record)
            finally:
                self._queue.task_done()

    def _emit_now(self, record: logging.LogRecord) -> None:
        if self._repo is None:
            return
        try:
            if _is_noise_record(record):
                return

            fp = self._fingerprint(record)
            if self._is_duplicate(fp):
                return

            # AI classification (best-effort, 12s timeout)
            classification = _classify_with_windsurf(record)

            env = os.getenv("ENVIRONMENT", "production")
            msg = record.getMessage()[:120]
            exc_name = (
                record.exc_info[0].__name__ if record.exc_info and record.exc_info[0] else None
            )
            title = f"[{self._service.upper()}-{fp}] {exc_name + ': ' if exc_name else ''}{msg}"

            labels = self._build_labels(record, env, classification)
            self._ensure_labels(labels)
            upstream_url = self._maybe_create_upstream_issue(
                record=record,
                fp=fp,
                classification=classification,
                labels=labels,
            )
            body = self._build_body(record, fp, classification)
            if upstream_url:
                body = f"## Upstream Component Issue\n\nKMS issue: {upstream_url}\n\n" + body
            markdown_doc = ""
            markdown_exports: list[dict[str, str]] = []
            if record.levelno >= logging.WARNING:
                markdown_doc, markdown_exports = _render_markdown_export_entries(
                    record=record,
                    fp=fp,
                    classification=classification,
                    service=self._service,
                )
                if _markdown_export_runtime_root is not None:
                    try:
                        markdown_exports = _write_markdown_exports(
                            root=_markdown_export_runtime_root,
                            record=record,
                            fp=fp,
                            classification=classification,
                            service=self._service,
                        )
                    except OSError as exc:
                        logging.getLogger(__name__).warning(
                            "Synchronous markdown issue export write failed fingerprint=%s: %s",
                            fp,
                            exc,
                        )
                    else:
                        _push_markdown_entries_to_github(
                            doc=markdown_doc,
                            entries=markdown_exports,
                        )
                else:
                    _push_markdown_entries_to_github(doc=markdown_doc, entries=markdown_exports)
            created_issue = self._repo.create_issue(
                title=title,
                body=body,
                labels=labels,
            )
            issues_repo_issue_url = self._maybe_create_issues_repo_issue(
                title=title,
                record=record,
                fp=fp,
                classification=classification,
                markdown_exports=markdown_exports,
                source_issue_url=getattr(created_issue, "html_url", None),
            )
            _dispatch_openclaw_webhook(
                record=record,
                fp=fp,
                classification=classification,
                service=self._service,
                github_issue_url=getattr(created_issue, "html_url", None),
                markdown_exports=markdown_exports,
            )
            _dispatch_index_webhook(
                record=record,
                fp=fp,
                classification=classification,
                service=self._service,
                github_issue_url=issues_repo_issue_url or getattr(created_issue, "html_url", None),
                markdown_exports=markdown_exports,
            )
        except Exception:
            self.handleError(record)

    def emit(self, record: logging.LogRecord) -> None:
        if self._repo is None:
            return
        try:
            self._queue.put_nowait(record)
        except queue.Full:
            # Never block the application path on issue publication/classification.
            return


def init_issue_tracking(
    *,
    github_repo: str | None = None,
    github_token: str | None = None,
    github_issue_level: int = logging.WARNING,
    markdown_export_root: str | Path | None = None,
    markdown_export_level: int = logging.DEBUG,
    markdown_github_repo: str | None = None,
    markdown_github_token: str | None = None,
    markdown_github_push: bool = False,
    service: str = "scd",
) -> dict[str, bool]:
    """Wire logging handlers for incidents and optional rolling Markdown export.

    Attaches (when configured):

    - A breadcrumb ring-buffer handler on the root logger.
    - ``GitHubIssueHandler`` when ``github_repo`` and a token resolve — opens owning-repo issues for
      qualifying records, renders Issue-repo Markdown, pushes when env push is enabled, may open the
      secondary Issues-repo issue, and dispatches OpenClaw/index webhooks.
    - ``MarkdownIssueExportHandler`` only when ``markdown_export_root`` is set — continuous export at
      ``markdown_export_level`` (e.g. DEBUG/INFO into ``Debug/`` / ``INFO/``). Omitting
      ``markdown_export_root`` does **not** disable incident Markdown push from the GitHub handler;
      that path uses in-memory render + Contents API when a GitHub token is available (set
      ``SCD_ISSUES_MD_GITHUB_PUSH=0`` to disable). If ``SCD_ISSUES_MD_GITHUB_PUSH`` is unset, push
      defaults **on** when any PAT used for Issues-repo API is present.

    Idempotent per subsystem. Returns flags ``breadcrumb`` / ``github`` / ``markdown``. No-ops under
    ``PYTEST_CURRENT_TEST``. Tokens must come from the environment or explicit args — never hardcoded.
    """
    global _breadcrumb_handler_installed
    global _github_issue_handler_installed
    global _markdown_export_handler_installed
    global _markdown_export_runtime_root

    result = {"breadcrumb": False, "github": False, "markdown": False}
    issue_log = logging.getLogger(__name__)
    _log_gravity_v2_init_once(issue_log)

    if os.getenv("PYTEST_CURRENT_TEST"):
        return result

    # Hard opt-in gate (2026-06 spam remediation): the GitHub-issue firehose is OFF by
    # default. Filing one GitHub issue per log record caused org-wide duplicate-issue spam;
    # errors now go to Sentry and work tracking to Linear. Set ENABLE_GITHUB_ISSUE_LOGGING=true
    # to re-enable (and only with durable, GitHub-backed dedup).
    if os.getenv("ENABLE_GITHUB_ISSUE_LOGGING", "false").strip().lower() != "true":
        issue_log.info(
            "personhood_issue_tracker: GitHub issue logging disabled "
            "(set ENABLE_GITHUB_ISSUE_LOGGING=true to enable)"
        )
        return result

    root_log = logging.getLogger()

    if not _breadcrumb_handler_installed:
        root_log.addHandler(_BreadcrumbHandler(logging.DEBUG))
        _breadcrumb_handler_installed = True
        result["breadcrumb"] = True

    gh_repo = (github_repo or "").strip()
    gh_token = (
        (github_token or "").strip()
        or os.getenv("AGENT_INTAKE_GITHUB_TOKEN", "").strip()
        or os.getenv("GITHUB_TOKEN", "").strip()
        or os.getenv("GITHUB_ISSUE_TOKEN", "").strip()
    )

    if gh_repo and not _github_issue_handler_installed:
        if not _GH_AVAILABLE:
            issue_log.warning("GitHub issue logging unavailable: PyGithub not installed")
        elif gh_token:
            gh_handler = GitHubIssueHandler(
                token=gh_token, repo=gh_repo, service=service, level=github_issue_level
            )
            gh_handler.setLevel(github_issue_level)
            root_log.addHandler(gh_handler)
            _github_issue_handler_installed = True
            result["github"] = True
        else:
            issue_log.warning(
                "GitHub issue logging skipped for repo=%s: no token "
                "(AGENT_INTAKE_GITHUB_TOKEN / GITHUB_TOKEN / GITHUB_ISSUE_TOKEN)",
                gh_repo,
            )

    md_raw = markdown_export_root
    if md_raw and not _markdown_export_handler_installed:
        md_root = Path(md_raw)
        _ensure_markdown_repo_layout(md_root)
        _markdown_export_runtime_root = md_root
        try:
            for sub in (_MD_FOLDER_WARN, _MD_FOLDER_ERROR, _MD_FOLDER_DEBUG, _MD_FOLDER_INFO):
                (md_root / sub).mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            issue_log.warning("Markdown issue export disabled: cannot mkdir %s: %s", md_root, exc)
        else:
            md_push_token = (
                (markdown_github_token or "").strip()
                or gh_token
                or os.getenv("SCD_ISSUES_MD_GITHUB_TOKEN", "").strip()
            )
            md_repo = (markdown_github_repo or "").strip()
            md_handler = MarkdownIssueExportHandler(
                root=md_root,
                service=service,
                level=markdown_export_level,
                github_repo=md_repo or None,
                github_token=md_push_token,
                github_push=markdown_github_push,
            )
            md_handler.setLevel(markdown_export_level)
            root_log.addHandler(md_handler)
            _markdown_export_handler_installed = True
            result["markdown"] = True

    md_token_for_runtime = (
        (markdown_github_token or "").strip()
        or gh_token
        or os.getenv("SCD_ISSUES_MD_GITHUB_TOKEN", "").strip()
    )
    _record_issues_md_runtime(
        markdown_github_repo=markdown_github_repo,
        issues_md_token_effective=md_token_for_runtime,
        markdown_github_push=markdown_github_push,
    )

    return result


def init_github_logging(
    *,
    token: str | None = None,
    repo: str | None = None,
    service: str = "scd",
    level: int = logging.WARNING,
) -> bool:
    """Backward-compatible wrapper: calls init_issue_tracking with env-based Markdown options."""
    md_root = os.getenv("SCD_ISSUES_MD_ROOT", "").strip()
    md_repo = os.getenv("SCD_ISSUES_MD_GITHUB_REPO", "Personhood-Social/Issues").strip()
    md_push = os.getenv("SCD_ISSUES_MD_GITHUB_PUSH", "").lower() in ("1", "true", "yes")
    md_level_name = os.getenv("SCD_ISSUES_MD_LOG_LEVEL", "DEBUG").upper()
    md_level = getattr(logging, md_level_name, logging.DEBUG)

    out = init_issue_tracking(
        github_repo=repo or "",
        github_token=token,
        github_issue_level=level,
        markdown_export_root=md_root or None,
        markdown_export_level=md_level,
        markdown_github_repo=md_repo or None,
        markdown_github_push=md_push,
        service=service,
    )
    return out["github"]
