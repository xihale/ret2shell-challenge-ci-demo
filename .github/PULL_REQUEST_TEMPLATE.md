## Challenge Summary

- **Challenge Slug**: `<!-- e.g. web_hello_world -->`
- **Category & Difficulty**: `<!-- e.g. Web / Easy -->`
- **Maintainer**: `@username`

## Author Checklist

- [ ] Challenge directory under `game/challenges/<category>_<slug>/` matches `^[a-z]+_[a-z0-9_]+$`
- [ ] PR only modifies files inside a single `game/challenges/<slug>/` directory
- [ ] `config.toml` has valid name, primary/secondary tags, and `score_rule` (`initial`/`minimum` in `0..=1500`, `minimum <= initial`, `decay` in `1..=50`)
- [ ] `README.md` is non-empty and does **not** contain a level-1 `# ` heading
- [ ] `env.toml.tmpl` uses `{{REGISTRY}}` and `{{GAME_BUCKET}}` placeholders, `protocol`/`app_protocol` (not `service_type`), `restricted = true`, `internet = false`, unique non-empty ports, and no `.` in image name before `:tag`
- [ ] `hints.toml` (`[[hints]]` or `hints = []`) and `answer.md` are present and non-empty
- [ ] No leftover `static/README.md` or `mapped/README.md` (use `.gitkeep` instead)
- [ ] `checker/main.rx` defines `pub async fn check` and `pub async fn environ`, uses unique `key` & `template`, and accesses `team.id` / `user.id` directly (never `team.get(` or `user.get(`)
- [ ] Container runs as non-root (`restricted = true` compatible) and `solve/exp.py` passes locally
- [ ] `python3 scripts/validate.py --root . --challenge <slug>` passes locally

## Reviewer Checklist

- [ ] `pr-validate` workflow passed
- [ ] Commented `/deploy` and verified staging deployment report passed end-to-end
- [ ] Writeup (`answer.md`), hints, and scoring rule reviewed
