"""Markdown export builder unit tests (no network)."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

import personhood_issue_tracker.issue as issue_module

GitHubIssueHandler = issue_module.GitHubIssueHandler
_build_openclaw_webhook_payload = issue_module._build_openclaw_webhook_payload
_build_markdown_export_document = issue_module._build_markdown_export_document
_load_openclaw_template = issue_module._load_openclaw_template
_markdown_export_filename = issue_module._markdown_export_filename
_markdown_export_targets = issue_module._markdown_export_targets
_render_markdown_export_entries = issue_module._render_markdown_export_entries
_dispatch_index_webhook = issue_module._dispatch_index_webhook


def test_markdown_export_contains_core_sections():
    logger = logging.getLogger("unit.test")
    record = logger.makeRecord(
        name="unit.test",
        level=logging.ERROR,
        fn="sample.py",
        lno=10,
        msg="something failed",
        args=(),
        exc_info=None,
    )
    record.pathname = "sample.py"
    record.funcName = "foo"

    fp = "ABCDEF0123"
    md = _build_markdown_export_document(record, fp, None, service="scd")

    assert "---" in md
    assert "issue_fingerprint: ABCDEF0123" in md
    assert "## How to fix" in md
    assert "## Verification" in md
    assert "## Diagnostic report" in md
    assert "SCD-ABCDEF0123" in md or "ABCDEF0123" in md


def test_build_body_accepts_include_remediation_sections_kwarg():
    hub = GitHubIssueHandler.__new__(GitHubIssueHandler)
    hub._service = "scd"
    hub._repo = None
    hub._gh = None
    hub._cache = {}

    logger = logging.getLogger("unit.test")
    record = logger.makeRecord(
        name="unit.test",
        level=logging.ERROR,
        fn="sample.py",
        lno=10,
        msg="failure",
        args=(),
        exc_info=None,
    )
    record.pathname = "sample.py"
    record.funcName = "foo"

    cls = {
        "summary": "unit test",
        "severity": "low",
        "components": [],
        "type": "crash",
        "is_noise": False,
        "remediation_markdown": "- fix thing",
        "verification": "run pytest",
    }
    with_sections = GitHubIssueHandler._build_body(hub, record, "FP1", cls)
    assert "## How to fix (recommended)" in with_sections

    without = GitHubIssueHandler._build_body(
        hub, record, "FP1", cls, include_remediation_sections=False
    )
    assert "## How to fix (recommended)" not in without


def test_openclaw_templates_are_repo_local():
    pr_template = _load_openclaw_template("OPENCLAW_PR_TEMPLATE.md")
    issue_template = _load_openclaw_template("OPENCLAW_ISSUE_EXECUTION_TEMPLATE.md")

    assert "## Summary" in pr_template
    assert "Required Output Fields" in issue_template


def test_build_body_includes_openclaw_sections_when_present():
    hub = GitHubIssueHandler.__new__(GitHubIssueHandler)
    hub._service = "scd"
    hub._repo = None
    hub._gh = None
    hub._cache = {}

    logger = logging.getLogger("unit.test")
    record = logger.makeRecord(
        name="unit.test",
        level=logging.ERROR,
        fn="sample.py",
        lno=10,
        msg="failure",
        args=(),
        exc_info=None,
    )
    record.pathname = "sample.py"
    record.funcName = "foo"

    cls = {
        "summary": "unit test",
        "severity": "low",
        "components": [],
        "type": "crash",
        "is_noise": False,
        "trigger_conditions": "A specific runtime state triggers the failure.",
        "fix_summary": "The fix adds a guard and better state handling.",
        "handling_summary": "The path now degrades explicitly.",
        "pr_title": "Fix runtime state handling",
        "pr_body_markdown": "## Summary\n\n- patched",
        "pr_url": "https://example.invalid/pr/1",
    }
    body = GitHubIssueHandler._build_body(hub, record, "FP2", cls)
    assert "## Trigger conditions" in body
    assert "## Fix summary" in body
    assert "## Handling summary" in body
    assert "## Proposed PR title" in body
    assert "## Proposed PR body" in body
    assert "## Proposed PR URL" in body


def test_openclaw_webhook_payload_includes_templates_and_issue_contract():
    logger = logging.getLogger("unit.test")
    record = logger.makeRecord(
        name="unit.test",
        level=logging.ERROR,
        fn="sample.py",
        lno=10,
        msg="failure",
        args=(),
        exc_info=None,
    )
    record.pathname = "sample.py"
    record.funcName = "foo"

    cls = {
        "summary": "worker crashed after invalid state transition",
        "root_cause_hypothesis": "state was missing a guard",
        "trigger_conditions": "a deferred task resumed twice",
        "fix_summary": "added an idempotency guard",
        "handling_summary": "the second resume is now rejected explicitly",
        "verification": "pytest scd/tests/unit/test_issue_markdown_document.py -q",
    }
    payload = _build_openclaw_webhook_payload(
        record=record,
        fp="FP3",
        classification=cls,
        service="scd",
        github_issue_url="https://github.com/example/repo/issues/1",
    )

    assert payload["github_issue_url"] == "https://github.com/example/repo/issues/1"
    assert payload["templates"]["execution"]
    assert payload["templates"]["pull_request"]
    assert payload["issue_contract"]["what_happened"] == cls["summary"]
    assert payload["issue_contract"]["why_it_happened"] == cls["root_cause_hypothesis"]
    assert payload["issue_contract"]["what_triggers_it"] == cls["trigger_conditions"]
    assert payload["issue_contract"]["how_to_fix_it"] == cls["fix_summary"]
    assert payload["issue_contract"]["how_to_handle_it"] == cls["handling_summary"]


def test_markdown_export_filename_matches_contract_without_fingerprint_suffix():
    logger = logging.getLogger("unit.test")
    record = logger.makeRecord(
        name="unit.test",
        level=logging.ERROR,
        fn="sample.py",
        lno=10,
        msg="failure",
        args=(),
        exc_info=None,
    )
    record.created = 1778013986

    name = _markdown_export_filename(
        record, "IGNOREDFP", "feature/test-branch", "Personhood-Social/SCD"
    )
    assert name == "ERROR_1778013986_feature-test-branch_Personhood-Social-SCD.md"


def test_markdown_export_targets_use_lifecycle_and_severity_paths(tmp_path: Path):
    logger = logging.getLogger("unit.test")
    record = logger.makeRecord(
        name="unit.test",
        level=logging.ERROR,
        fn="sample.py",
        lno=10,
        msg="failure",
        args=(),
        exc_info=None,
    )
    cls = {"severity": "critical"}
    targets = _markdown_export_targets(tmp_path, record, "FPX", cls)
    rel_paths = {path.relative_to(tmp_path).as_posix() for _, path in targets}
    assert any(path.startswith("Debug/") for path in rel_paths)
    assert any(path.startswith("Error/Unresolved/critical/") for path in rel_paths)


def test_issues_repo_issue_body_lists_source_issue_and_markdown_paths():
    hub = GitHubIssueHandler.__new__(GitHubIssueHandler)
    hub._service = "scd"
    hub._repo = None
    hub._gh = None
    hub._cache = {}

    logger = logging.getLogger("unit.test")
    record = logger.makeRecord(
        name="unit.test",
        level=logging.ERROR,
        fn="sample.py",
        lno=10,
        msg="failure",
        args=(),
        exc_info=None,
    )
    record.pathname = "sample.py"
    record.funcName = "foo"

    body = GitHubIssueHandler._build_issues_repo_issue_body(
        hub,
        record=record,
        fp="FP4",
        classification={"summary": "unit test", "severity": "low", "type": "crash"},
        markdown_exports=[
            {"relative_path": "Error/Unresolved/low/2026-05-05/ERROR_1_main_repo.md"},
            {"relative_path": "Debug/2026-05-05/ERROR_1_main_repo.md"},
        ],
        source_issue_url="https://github.com/example/repo/issues/1",
    )

    assert "## Source issue" in body
    assert "https://github.com/example/repo/issues/1" in body
    assert "Error/Unresolved/low/2026-05-05/ERROR_1_main_repo.md" in body
    assert "## Stack Trace" in body


def test_render_markdown_export_entries_supports_github_only_paths():
    logger = logging.getLogger("unit.test")
    record = logger.makeRecord(
        name="unit.test",
        level=logging.WARNING,
        fn="sample.py",
        lno=10,
        msg="warning failure",
        args=(),
        exc_info=None,
    )
    record.pathname = "sample.py"
    record.funcName = "foo"
    doc, entries = _render_markdown_export_entries(
        record=record,
        fp="FP5",
        classification={"severity": "medium"},
        service="scd",
    )

    assert "# SCD automated export" in doc
    assert any(item["relative_path"].startswith("Warn/Unresolved/medium/") for item in entries)


def test_index_payload_contract_carries_lifecycle_and_related_issue_hints(
    monkeypatch: pytest.MonkeyPatch,
):
    logger = logging.getLogger("unit.test")
    record = logger.makeRecord(
        name="unit.test",
        level=logging.ERROR,
        fn="sample.py",
        lno=10,
        msg="failure",
        args=(),
        exc_info=None,
    )
    captured: dict[str, object] = {}

    def fake_dispatch_json_webhook(**kwargs):
        captured.update(kwargs)

    monkeypatch.setenv("SCD_ISSUES_INDEX_WEBHOOK_URL", "https://example.invalid/index")
    monkeypatch.setattr(issue_module, "_dispatch_json_webhook", fake_dispatch_json_webhook)

    _dispatch_index_webhook(
        record=record,
        fp="FP6",
        classification={"summary": "unit test", "severity": "high"},
        service="scd",
        github_issue_url="https://github.com/example/repo/issues/1",
        markdown_exports=[
            {"relative_path": "Error/Unresolved/high/2026-05-06/ERROR_1_main_repo.md"}
        ],
    )

    payload = captured["payload"]
    assert payload["index_contract"]["issues_repo"] == "Personhood-Social/Issues"
    assert payload["index_contract"]["initial_status"] == "unresolved"
    assert payload["index_contract"]["supports_related_issue_lookup"] is True
    assert payload["index_contract"]["semantic_similarity_source"] == "windsurf-embeddings"


def test_github_issue_handler_pushes_markdown_to_issues_repo_even_with_local_runtime_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    logger = logging.getLogger("unit.test")
    record = logger.makeRecord(
        name="unit.test",
        level=logging.ERROR,
        fn="sample.py",
        lno=10,
        msg="failure",
        args=(),
        exc_info=None,
    )
    record.pathname = "sample.py"
    record.funcName = "foo"

    class _FakeRepo:
        full_name = "Personhood-Social/SCD"

        def get_labels(self):
            return []

        def create_issue(self, **kwargs):
            return type("_Issue", (), {"html_url": "https://github.com/example/repo/issues/1"})()

    pushed: dict[str, object] = {}

    hub = GitHubIssueHandler.__new__(GitHubIssueHandler)
    hub._service = "scd"
    hub._token = "token"
    hub._repo = _FakeRepo()
    hub._gh = None
    hub._cache = {}

    monkeypatch.setattr(issue_module, "_markdown_export_runtime_root", tmp_path)
    monkeypatch.setattr(issue_module, "_is_noise_record", lambda _record: False)
    monkeypatch.setattr(
        issue_module,
        "_classify_with_windsurf",
        lambda _record: {"severity": "high", "type": "crash", "is_noise": False},
    )
    monkeypatch.setattr(
        issue_module,
        "_write_markdown_exports",
        lambda **kwargs: [
            {
                "folder": "Error",
                "path": str(tmp_path / "Error.md"),
                "relative_path": "Error/Unresolved/high/2026-05-06/ERROR_1_main_repo.md",
            }
        ],
    )
    monkeypatch.setattr(
        issue_module,
        "_push_markdown_entries_to_github",
        lambda **kwargs: pushed.update(kwargs),
    )
    monkeypatch.setattr(issue_module, "_dispatch_openclaw_webhook", lambda **kwargs: None)
    monkeypatch.setattr(issue_module, "_dispatch_index_webhook", lambda **kwargs: None)
    monkeypatch.setattr(
        GitHubIssueHandler,
        "_ensure_labels_on_repo",
        lambda self, repo, names: None,
    )
    monkeypatch.setattr(
        GitHubIssueHandler,
        "_maybe_create_issues_repo_issue",
        lambda self, **kwargs: "https://github.com/Personhood-Social/Issues/issues/1",
    )

    GitHubIssueHandler._emit_now(hub, record)

    assert pushed["doc"]
    assert pushed["entries"][0]["relative_path"].startswith("Error/Unresolved/high/")


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
