# Ret2Shell Challenge CI Repository

Standardized challenge authoring repository for [Ret2Shell](https://github.com/ret2shell), supporting automated PR validation, on-demand staging deployment verification (`/deploy`), automatic PR cleanup, and production game synchronization.

## Repository Layout

```text
.
├── .github/
│   ├── PULL_REQUEST_TEMPLATE.md
│   └── workflows/
│       ├── pr-validate.yml       # Schema validation + local container build & smoke test
│       ├── pr-stage-deploy.yml   # Comment `/deploy` on a PR to verify on staging Ret2Shell
│       ├── pr-cleanup.yml        # Cleans up staging challenge when PR closes
│       └── prod-deploy.yml       # Manual dispatch on `main` to sync into production game
├── docs/
│   └── authoring-guide.md        # Detailed authoring spec, schemas, and CI/CD workflow
├── game/
│   ├── config.toml               # GameConfig payload root
│   ├── README.md                 # Game introduction (no H1 heading)
│   └── challenges/
│       ├── _template/            # Standard challenge skeleton
│       └── <category>_<slug>/    # Individual challenges (e.g. web_hello_world)
└── scripts/
    ├── validate.py               # Zero-dependency Python 3 schema & PR scope validator
    └── deploy.py                 # Ret2Shell staging/prod API + git-sync CLI
```

## Quick Start for Challenge Authors

1. Branch from `main` (e.g., `chal/web-hello-world`).
2. Copy `game/challenges/_template/` to `game/challenges/<category>_<slug>/` matching `^[a-z]+_[a-z0-9_]+$`.
3. Fill in `config.toml`, `README.md`, `env.toml.tmpl`, `hints.toml`, `answer.md`, `checker/main.rx`, `src/`, and `solve/`.
4. Run local validation:
   ```bash
   python3 scripts/validate.py --root . --challenge <category>_<slug>
   ```
5. Run local container build & exploit smoke test (optional if Docker/Podman is available):
   ```bash
   python3 scripts/deploy.py build-and-test --root . --challenge <category>_<slug>
   ```
6. Open a Pull Request modifying only `game/challenges/<category>_<slug>/`. See [docs/authoring-guide.md](docs/authoring-guide.md) for the complete specification and review workflow.
