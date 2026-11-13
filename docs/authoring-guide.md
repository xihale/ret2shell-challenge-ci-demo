# Challenge Authoring & Review Guide

This document defines the standardized challenge directory format, Ret2Shell configuration schemas, naming rules, and PR-to-Production workflows.

## 1. Naming Rules

1. **Challenge directory slug**: Must match `^[a-z]+_[a-z0-9_]+$` (lowercase category prefix, underscore, lowercase alphanumeric/underscore slug, e.g. `web_hello_world`, `pwn_ez_stack`).
   - `_template` is reserved for the skeleton template and skipped during sync.
2. **Container image names & tarballs**:
   - `[[images]].name` and the repository segment before `:tag` in `[[images]].tag` **must NOT contain dots (`.`)**.
   - Why: Ret2Shell's registry uploader (`crates/cluster/src/registry.rs`) derives the image repository name via `name.split('.').next()`, so `my.app.tar.zst` would truncate to `my`!
   - Example: `name = "web-hello-world"` -> tarball `web-hello-world.tar.zst` -> tag `{{REGISTRY}}/{{GAME_BUCKET}}/web-hello-world:latest`.

## 2. Challenge Directory Structure

```text
game/challenges/<category>_<slug>/
├── config.toml          # Required: challenge metadata, tags, dynamic score_rule
├── README.md            # Required: player-facing description (NO `# ` H1 heading)
├── env.toml.tmpl        # Required if containerized: environment & image template
├── hints.toml           # Required: `[[hints]]` entries or `hints = []`
├── answer.md            # Required: internal writeup for reviewers/archive
├── checker/
│   └── main.rx          # Required: Rune checker script (`check` and `environ`)
├── static/
│   └── .gitkeep         # Attachments distributed to players (DO NOT add README.md!)
├── mapped/
│   └── .gitkeep         # Per-team mapped files (DO NOT add README.md!)
├── src/
│   ├── .gitkeep         # Container build context (Containerfile/Dockerfile + app)
│   └── Containerfile
└── solve/
    ├── meta.json        # Solver metadata (`entrypoint`, `timeout_sec`, `flag_regex`)
    └── exp.py           # Automated exploit / verification script
```

> [!IMPORTANT]
> Never leave `static/README.md` or `mapped/README.md` inside `static/` or `mapped/`. Ret2Shell reads all non-dot files in `static/` and `mapped/` as challenge attachments/mapped files (`ChallengeBucket::get_static_files` / `get_mapped_files` only skip files starting with `.`). Use `.gitkeep` instead.

## 3. File Schemas

### `config.toml` (`ChallengeConfig`)

Validated against `crates/bucket/src/challenge.rs` and `crates/server/src/utility/validation.rs`:

```toml
name = "Web Hello World"
tag = [
  { name = "Web", primary = true },
  { name = "Easy", primary = false },
]

[score_rule]
initial = 1000   # integer in 0..=1500
minimum = 100    # integer in 0..=1500, must be <= initial
decay = 25       # integer in 1..=50
```

- `name` must be non-empty.
- `tag` must be non-empty, with at least one `primary = true`.

### `README.md`

- Must be non-empty.
- Must **NOT** contain a level-1 Markdown heading (`# ...`); Ret2Shell renders the challenge title from `config.toml`.

### `env.toml.tmpl` (`ChallengeEnv` + `ChallengeImage`)

Validated against `crates/config/src/cluster.rs` and `crates/server/src/routes/game/repo_sync.rs`:

```toml
internet = false
restricted = true

[[images]]
name = "web-hello-world"
tag = "{{REGISTRY}}/{{GAME_BUCKET}}/web-hello-world:latest"
port = 8080
protocol = "tcp"       # "tcp" | "stcp" | "udp"
app_protocol = "http"  # "http" | "raw"
restricted = true      # runs with non-root / dropped capabilities
cpu = 0.25
cpu_req = 0.01
mem = "64Mi"
mem_req = "32Mi"
storage = "1Gi"
storage_req = "64Mi"
```

- Use `{{REGISTRY}}` and `{{GAME_BUCKET}}` placeholders in `tag` so staging and production deployments resolve to their respective registries and game buckets.
- Use `protocol` and `app_protocol` instead of the deprecated `service_type`.
- `internet` must be `false` (unless explicitly approved) and `restricted = true` must be set. Ensure your container runs as a non-root user (e.g., `USER 1000:1000`).
- Every exposed `port` must be an integer in `1..=65535` and unique across all `[[images]]` in the challenge.

### `hints.toml` (`Hints`)

- Must be valid TOML containing `[[hints]]` entries (`content: string`, `cost: int >= 0`) or `hints = []`.
- An empty file without `hints = []` fails Rust deserialization (`Hints` requires the `hints` key).
- Note: When syncing an existing challenge via Git, Ret2Shell only allows **appending** new hints (`repo_sync.rs`); editing/removing existing hints must be done in the web UI.

### `checker/main.rx` (Rune Checker)

Validated against `crates/checker/src/lib.rs`:

- Must define `pub async fn check(bucket, user, team, submission)` and `pub async fn environ(bucket, user, team)`.
- `RuneUser`, `RuneTeam`, and `RuneSubmission` expose **fields** via `#[rune(get)]` — use attribute access (`team.id`, `team.name`, `user.id`, `submission.content`), **NOT** map methods like `team.get("id")` or `user.get("id")`.
- Set a **globally unique** `key` and `template` per challenge so dynamic flags cannot collide across challenges.

### `solve/meta.json` & `solve/exp.py`

- `solve/meta.json` records `entrypoint` (default `"exp.py"`), `timeout_sec`, and `flag_regex`.
- `solve/exp.py` should accept target connection details (`--url` / `--host` / `--port` or `TARGET_URL`), exploit the challenge, verify expected behavior, and print the captured flag cleanly to stdout.
- `solve/` is excluded when syncing into the production Ret2Shell game repository.

## 4. Workflows

### PR Validation (`pr-validate.yml`)

Triggered on `pull_request` (`opened`, `synchronize`, `reopened`):
1. Runs `scripts/validate.py --changed-files ...` to verify PR scope (only a single `game/challenges/<slug>/` may be modified unless shared infra PR) and all schema/lint rules.
2. Runs `scripts/deploy.py build-and-test` to build the container image (if `src/Containerfile` or `src/Dockerfile` exists) and run `solve/exp.py` against a local container with a test `FLAG`.

### Staging Review Deployment (`pr-stage-deploy.yml`)

1. A maintainer/reviewer (`OWNER`, `MEMBER`, or `COLLABORATOR`) comments `/deploy` (or `/stage`) on the PR.
2. The workflow checks out the PR head, runs `scripts/validate.py`, and executes `scripts/deploy.py stage-pr`.
3. `stage-pr` uploads built images, creates/updates the challenge in `RET2SHELL_STAGING_GAME_ID` via the Ret2Shell API, starts a real container instance, runs `solve/exp.py`, submits the extracted flag to `POST .../submit`, polls until `solved == true`, tears down the instance, and posts a Markdown verification report back on the PR.

### PR Cleanup (`pr-cleanup.yml`)

Triggered when a PR is closed/merged: removes the temporary challenge from `RET2SHELL_STAGING_GAME_ID` via `scripts/deploy.py cleanup-pr`.

### Production Sync (`prod-deploy.yml`)

Triggered manually via `workflow_dispatch` on `main` (protected by the `production` GitHub environment):
- Runs `scripts/validate.py --all`.
- Runs `scripts/deploy.py prod-sync` to clone the production game repository, ensure `hidden = true`, upload challenge images, render `env.toml.tmpl` -> `env.toml`, overlay challenges (excluding `_template`, `solve/`, and `*.tmpl`), and push to the production game repository (preserving production `config.toml` unless `--sync-game-config` is explicitly requested).
