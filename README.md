# Issue-Tracker (`personhood-issue-tracker`)

Standalone Python package for the Personhood **incident pipeline**: GitHub Issues, `Personhood-Social/Issues` Markdown exports, OpenClaw and index webhooks, Gravity-backed classification.

**This is not part of the SCD application repo.** SCD (and other services) depend on this package via pip.

## Repository

- GitHub: **Personhood-Social/Issue-Tracker** (publish this directory as that repo).
- Package import name: `personhood_issue_tracker`

## Install

From the repo root:

```bash
pip install -e .
```

From GitHub (after you push):

```bash
pip install "personhood-issue-tracker @ git+https://github.com/Personhood-Social/Issue-Tracker.git@main"
```

## Publishing as its own repo (one-time)

While this folder lives inside the SCD monorepo for development, publish it separately:

```bash
cd Issue-Tracker
git init
git add -A
git commit -m "chore: initial Issue-Tracker extraction"
git branch -M main
git remote add origin https://github.com/Personhood-Social/Issue-Tracker.git
git push -u origin main
```

Then in **SCD**, replace the embedded path dependency with the git URL in `scd/pyproject.toml`, or add a **git submodule** at `Issue-Tracker/` pointing at this repository.

## Contract

See [docs/INCIDENT_CONTRACT.md](docs/INCIDENT_CONTRACT.md).

## Tests

```bash
pip install -e ".[dev]"
pytest -q
```
