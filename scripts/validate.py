#!/usr/bin/env python3
"""Standardized Ret2Shell challenge repository validator (Python 3 stdlib only)."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

CHALLENGE_SLUG_RE = re.compile(r"^[a-z]+_[a-z0-9_]+$")
H1_RE = re.compile(r"^#\s+\S")
FENCE_RE = re.compile(r"^\s*(```|~~~)")
PLACEHOLDER_RE = re.compile(r"\{\{([A-Z0-9_]+)\}\}")
CHECK_FN_RE = re.compile(r"\bpub\s+async\s+fn\s+check\s*\(")
ENVIRON_FN_RE = re.compile(r"\bpub\s+async\s+fn\s+environ\s*\(")
BAD_GET_RE = re.compile(r"\b(team|user)\.get\s*\(")

VALID_PROTOCOLS = {"tcp", "stcp", "udp"}
VALID_APP_PROTOCOLS = {"raw", "http"}
KNOWN_ENV_PLACEHOLDERS = {
    "REGISTRY": "registry.example.com",
    "GAME_BUCKET": "example_game",
}


def is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def is_num(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def parse_toml(text: str, path: Path, errors: list[str]) -> dict[str, Any] | None:
    if tomllib is None:
        errors.append(
            f"{path}: Python >= 3.11 is required for stdlib tomllib parsing "
            f"(detected {sys.version.split()[0]})"
        )
        return None
    try:
        data = tomllib.loads(text)
    except Exception as exc:
        errors.append(f"{path}: invalid TOML ({exc})")
        return None
    if not isinstance(data, dict):
        errors.append(f"{path}: TOML root must be a table")
        return None
    return data


def has_h1_heading(markdown_text: str) -> int | None:
    """Return 1-based line number of the first H1 heading outside fenced code blocks."""
    in_fence = False
    fence_marker = ""
    for lineno, line in enumerate(markdown_text.splitlines(), start=1):
        fence_match = FENCE_RE.match(line)
        if fence_match:
            marker = fence_match.group(1)
            if not in_fence:
                in_fence = True
                fence_marker = marker
            elif marker == fence_marker:
                in_fence = False
                fence_marker = ""
            continue
        if not in_fence and H1_RE.match(line):
            return lineno
    return None


def validate_markdown_no_h1(path: Path, label: str, errors: list[str]) -> None:
    if not path.is_file():
        errors.append(f"{path}: missing {label}")
        return
    content = path.read_text(encoding="utf-8", errors="replace")
    if not content.strip():
        errors.append(f"{path}: {label} must not be empty")
        return
    h1_line = has_h1_heading(content)
    if h1_line is not None:
        errors.append(
            f"{path}:{h1_line}: {label} must not contain a level-1 heading ('# ...'); "
            "the title is rendered from config.toml"
        )


def validate_game_dir(root: Path, errors: list[str]) -> None:
    game_dir = root / "game"
    config_path = game_dir / "config.toml"
    if not config_path.is_file():
        errors.append(f"{config_path}: missing game config.toml")
    else:
        data = parse_toml(config_path.read_text(encoding="utf-8"), config_path, errors)
        if data is not None:
            for field in ("name", "brief"):
                val = data.get(field)
                if not isinstance(val, str) or not val.strip():
                    errors.append(f"{config_path}: '{field}' must be a non-empty string")
            for ts_field in ("updated_at", "register_at", "start_at", "end_at", "archive_at"):
                if not is_int(data.get(ts_field)):
                    errors.append(f"{config_path}: '{ts_field}' must be an integer Unix timestamp")
            if all(
                is_int(data.get(k)) for k in ("register_at", "start_at", "end_at", "archive_at")
            ):
                if data["register_at"] > data["start_at"]:
                    errors.append(f"{config_path}: register_at must be <= start_at")
                if data["start_at"] >= data["end_at"]:
                    errors.append(f"{config_path}: start_at must be < end_at")
                if data["end_at"] > data["archive_at"]:
                    errors.append(f"{config_path}: end_at must be <= archive_at")

            host_type = data.get("host_type")
            if host_type not in (0, 1) or isinstance(host_type, bool):
                errors.append(f"{config_path}: 'host_type' must be 0 (Training) or 1 (Game)")
            team_size = data.get("team_size")
            if not is_int(team_size) or (host_type == 1 and not (1 <= team_size <= 99)):
                errors.append(f"{config_path}: 'team_size' must be an integer in 1..=99 for CTFGame")
            if not isinstance(data.get("can_register_after_started"), bool):
                errors.append(f"{config_path}: 'can_register_after_started' must be a boolean")
            award_rate = data.get("award_rate")
            if not is_int(award_rate) or not (0 <= award_rate <= 100):
                errors.append(f"{config_path}: 'award_rate' must be an integer in 0..=100")
            if not is_int(data.get("weight")):
                errors.append(f"{config_path}: 'weight' must be an integer")
            access_policy = data.get("access_policy")
            if not isinstance(access_policy, dict) or not is_int(access_policy.get("sync")):
                errors.append(f"{config_path}: 'access_policy.sync' must be an integer")

    validate_markdown_no_h1(game_dir / "README.md", "game README.md", errors)


def validate_env_file(env_path: Path, is_template: bool, has_containerfile: bool, errors: list[str]) -> None:
    raw_text = env_path.read_text(encoding="utf-8", errors="replace")
    rendered = raw_text
    if is_template:
        for key, sample_val in KNOWN_ENV_PLACEHOLDERS.items():
            rendered = rendered.replace(f"{{{{{key}}}}}", sample_val)
    leftover = PLACEHOLDER_RE.findall(rendered)
    if leftover:
        errors.append(
            f"{env_path}: unrendered/unknown template placeholder(s): "
            + ", ".join(sorted(set(leftover)))
        )

    data = parse_toml(rendered, env_path, errors)
    if data is None:
        return

    internet = data.get("internet")
    if not isinstance(internet, bool):
        errors.append(f"{env_path}: 'internet' must be present and a boolean")

    images = data.get("images")
    if not isinstance(images, list):
        errors.append(f"{env_path}: 'images' must be an array of tables ([[images]])")
        return

    if has_containerfile and len(images) == 0:
        errors.append(f"{env_path}: Containerfile/Dockerfile exists in src/ but 'images' is empty")

    top_restricted = data.get("restricted")
    if top_restricted is not None and not isinstance(top_restricted, bool):
        errors.append(f"{env_path}: top-level 'restricted' must be a boolean")

    if len(images) == 0 and not isinstance(top_restricted, bool):
        errors.append(f"{env_path}: 'restricted' boolean must be present")

    seen_ports: dict[int, str] = {}
    for idx, image in enumerate(images, start=1):
        prefix = f"{env_path} images[{idx}]"
        if not isinstance(image, dict):
            errors.append(f"{prefix}: entry must be a table")
            continue

        img_name = image.get("name")
        if not isinstance(img_name, str) or not img_name.strip():
            errors.append(f"{prefix}: 'name' must be a non-empty string")
        else:
            if "." in img_name:
                errors.append(
                    f"{prefix}: image 'name' ({img_name!r}) must not contain '.' "
                    "(ret2shell registry splits tar names on '.')"
                )
            if any(ch.isspace() or ch in "/:\\" for ch in img_name):
                errors.append(f"{prefix}: image 'name' ({img_name!r}) contains invalid characters")

        img_tag = image.get("tag")
        if not isinstance(img_tag, str) or not img_tag.strip():
            errors.append(f"{prefix}: 'tag' must be a non-empty string")
        else:
            last_segment = img_tag.rsplit("/", 1)[-1]
            repo_part = last_segment.split(":", 1)[0]
            if "." in repo_part:
                errors.append(
                    f"{prefix}: image repository in 'tag' ({repo_part!r}) must not contain '.' before ':tag'"
                )

        if not is_num(image.get("cpu")) or image["cpu"] <= 0:
            errors.append(f"{prefix}: 'cpu' must be a positive number")
        mem = image.get("mem")
        if not isinstance(mem, str) or not mem.strip():
            errors.append(f"{prefix}: 'mem' must be a non-empty string (e.g. '128Mi')")

        img_restricted = image.get("restricted")
        if img_restricted is not None and not isinstance(img_restricted, bool):
            errors.append(f"{prefix}: 'restricted' must be a boolean")
        if not isinstance(top_restricted, bool) and not isinstance(img_restricted, bool):
            errors.append(
                f"{prefix}: 'restricted' must be set either at top-level or on each [[images]] entry"
            )

        if "port" in image:
            port = image["port"]
            if not is_int(port) or not (1 <= port <= 65535):
                errors.append(f"{prefix}: 'port' must be a non-empty integer in 1..=65535 (got {port!r})")
            elif port in seen_ports:
                errors.append(
                    f"{prefix}: duplicate port {port} (already used by {seen_ports[port]})"
                )
            else:
                seen_ports[port] = img_name or f"images[{idx}]"

        if "service_type" in image:
            errors.append(
                f"{prefix}: 'service_type' is deprecated; use 'protocol' and 'app_protocol' instead"
            )

        protocol = image.get("protocol")
        if protocol is not None and protocol not in VALID_PROTOCOLS:
            errors.append(
                f"{prefix}: 'protocol' must be one of {sorted(VALID_PROTOCOLS)} (got {protocol!r})"
            )

        app_protocol = image.get("app_protocol")
        if app_protocol is not None and app_protocol not in VALID_APP_PROTOCOLS:
            errors.append(
                f"{prefix}: 'app_protocol' must be one of {sorted(VALID_APP_PROTOCOLS)} "
                f"(got {app_protocol!r})"
            )


def validate_challenge_dir(chal_dir: Path, slug: str, errors: list[str], *, check_slug: bool = True) -> None:
    if not chal_dir.is_dir():
        errors.append(f"{chal_dir}: challenge directory does not exist")
        return

    if check_slug and not CHALLENGE_SLUG_RE.match(slug):
        errors.append(
            f"{chal_dir}: challenge directory name {slug!r} must match ^[a-z]+_[a-z0-9_]+$"
        )

    # 1. config.toml
    config_path = chal_dir / "config.toml"
    if not config_path.is_file():
        errors.append(f"{config_path}: missing config.toml")
    else:
        cfg = parse_toml(config_path.read_text(encoding="utf-8"), config_path, errors)
        if cfg is not None:
            name = cfg.get("name")
            if not isinstance(name, str) or not name.strip():
                errors.append(f"{config_path}: 'name' must be a non-empty string")

            tags = cfg.get("tag")
            if not isinstance(tags, list) or len(tags) == 0:
                errors.append(f"{config_path}: 'tag' must be a non-empty array of tables")
            else:
                has_primary = False
                for idx, tag in enumerate(tags, start=1):
                    if not isinstance(tag, dict):
                        errors.append(f"{config_path}: tag[{idx}] must be a table")
                        continue
                    t_name = tag.get("name")
                    t_primary = tag.get("primary")
                    if not isinstance(t_name, str) or not t_name.strip():
                        errors.append(f"{config_path}: tag[{idx}].name must be a non-empty string")
                    if not isinstance(t_primary, bool):
                        errors.append(f"{config_path}: tag[{idx}].primary must be a boolean")
                    elif t_primary:
                        has_primary = True
                if not has_primary:
                    errors.append(f"{config_path}: at least one tag must have primary = true")

            score_rule = cfg.get("score_rule")
            if not isinstance(score_rule, dict):
                errors.append(f"{config_path}: missing [score_rule] table")
            else:
                initial = score_rule.get("initial")
                minimum = score_rule.get("minimum")
                decay = score_rule.get("decay")
                if not is_int(initial) or not (0 <= initial <= 1500):
                    errors.append(f"{config_path}: score_rule.initial must be an integer in 0..=1500")
                if not is_int(minimum) or not (0 <= minimum <= 1500):
                    errors.append(f"{config_path}: score_rule.minimum must be an integer in 0..=1500")
                if not is_int(decay) or not (1 <= decay <= 50):
                    errors.append(f"{config_path}: score_rule.decay must be an integer in 1..=50")
                if is_int(initial) and is_int(minimum) and minimum > initial:
                    errors.append(f"{config_path}: score_rule.minimum ({minimum}) must not exceed initial ({initial})")

    # 2. README.md
    validate_markdown_no_h1(chal_dir / "README.md", "challenge README.md", errors)

    # 3. env.toml.tmpl / env.toml
    env_tmpl = chal_dir / "env.toml.tmpl"
    env_rendered = chal_dir / "env.toml"
    has_containerfile = any(
        (chal_dir / "src" / fname).is_file() for fname in ("Containerfile", "Dockerfile")
    )
    if env_tmpl.is_file():
        validate_env_file(env_tmpl, is_template=True, has_containerfile=has_containerfile, errors=errors)
    if env_rendered.is_file():
        validate_env_file(env_rendered, is_template=False, has_containerfile=has_containerfile, errors=errors)
    if has_containerfile and not env_tmpl.is_file() and not env_rendered.is_file():
        errors.append(
            f"{chal_dir}: src/Containerfile or src/Dockerfile exists, but env.toml.tmpl is missing"
        )

    # 4. hints.toml
    hints_path = chal_dir / "hints.toml"
    if not hints_path.is_file():
        errors.append(f"{hints_path}: missing hints.toml")
    else:
        hints_data = parse_toml(hints_path.read_text(encoding="utf-8"), hints_path, errors)
        if hints_data is not None:
            hints = hints_data.get("hints")
            if not isinstance(hints, list):
                errors.append(
                    f"{hints_path}: 'hints' key must be a list (use 'hints = []' for zero hints)"
                )
            else:
                for idx, hint in enumerate(hints, start=1):
                    if not isinstance(hint, dict):
                        errors.append(f"{hints_path}: hints[{idx}] must be a table")
                        continue
                    content = hint.get("content")
                    cost = hint.get("cost")
                    if not isinstance(content, str) or not content.strip():
                        errors.append(f"{hints_path}: hints[{idx}].content must be a non-empty string")
                    if not is_int(cost) or cost < 0:
                        errors.append(f"{hints_path}: hints[{idx}].cost must be a non-negative integer")

    # 5. answer.md
    answer_path = chal_dir / "answer.md"
    if not answer_path.is_file():
        errors.append(f"{answer_path}: missing answer.md")
    elif not answer_path.read_text(encoding="utf-8", errors="replace").strip():
        errors.append(f"{answer_path}: answer.md must not be empty")

    # 6. No leftover static/README.md or mapped/README.md
    for forbidden_dir in ("static", "mapped"):
        bad_readme = chal_dir / forbidden_dir / "README.md"
        if bad_readme.exists():
            errors.append(
                f"{bad_readme}: leftover {forbidden_dir}/README.md is not allowed "
                "(ret2shell treats non-dot files in static/ and mapped/ as challenge files); use .gitkeep"
            )

    # 7. checker/main.rx
    checker_path = chal_dir / "checker" / "main.rx"
    if not checker_path.is_file():
        errors.append(f"{checker_path}: missing checker/main.rx")
    else:
        script = checker_path.read_text(encoding="utf-8", errors="replace")
        if not CHECK_FN_RE.search(script):
            errors.append(f"{checker_path}: must define 'pub async fn check(...)'")
        if not ENVIRON_FN_RE.search(script):
            errors.append(f"{checker_path}: must define 'pub async fn environ(...)'")
        bad_get = BAD_GET_RE.search(script)
        if bad_get:
            errors.append(
                f"{checker_path}: forbidden '{bad_get.group(0)}' call; "
                "use direct attribute access like 'team.id' or 'user.id'"
            )


def normalize_rel_path(raw: str) -> str:
    norm = raw.replace("\\", "/").strip()
    while norm.startswith("./"):
        norm = norm[2:]
    return norm


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate Ret2Shell challenge repository files.")
    parser.add_argument("--root", default=".", help="Repository root directory (default: .)")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--challenge", help="Validate a single challenge slug under game/challenges/")
    mode.add_argument("--all", action="store_true", help="Validate game config and all challenges")
    mode.add_argument(
        "--changed-files",
        nargs="+",
        help="Validate changed files for PR scope and affected challenge(s)",
    )
    parser.add_argument(
        "--allow-shared",
        action="store_true",
        help="With --changed-files, allow changes outside a single game/challenges/<slug>/",
    )

    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    errors: list[str] = []
    validated_targets: list[str] = []

    if args.challenge:
        slug = args.challenge
        chal_dir = root / "game" / "challenges" / slug
        validate_challenge_dir(chal_dir, slug, errors, check_slug=(slug != "_template"))
        validated_targets.append(f"challenge:{slug}")

    elif args.all:
        validate_game_dir(root, errors)
        validated_targets.append("game")
        challenges_root = root / "game" / "challenges"
        if not challenges_root.is_dir():
            errors.append(f"{challenges_root}: missing game/challenges directory")
        else:
            for entry in sorted(challenges_root.iterdir()):
                if not entry.is_dir():
                    continue
                if entry.name.startswith(".") or entry.name == "_template":
                    continue
                validate_challenge_dir(entry, entry.name, errors)
                validated_targets.append(f"challenge:{entry.name}")

    elif args.changed_files:
        touched_challenges: set[str] = set()
        outside_files: list[str] = []
        game_root_touched = False

        for raw_file in args.changed_files:
            rel = normalize_rel_path(raw_file)
            if not rel:
                continue
            parts = rel.split("/")
            if len(parts) >= 4 and parts[0] == "game" and parts[1] == "challenges":
                slug = parts[2]
                if slug == "_template" or slug.startswith("."):
                    outside_files.append(rel)
                else:
                    touched_challenges.add(slug)
            else:
                outside_files.append(rel)
                if rel in ("game/config.toml", "game/README.md"):
                    game_root_touched = True

        if not args.allow_shared:
            if outside_files:
                errors.append(
                    "PR scope error: modified files outside game/challenges/<single_chal>/ "
                    "(pass --allow-shared for infra PRs): " + ", ".join(outside_files)
                )
            if len(touched_challenges) == 0:
                errors.append(
                    "PR scope error: no challenge files modified under game/challenges/<slug>/"
                )
            elif len(touched_challenges) > 1:
                errors.append(
                    "PR scope error: PR must modify only a single challenge, but touched: "
                    + ", ".join(sorted(touched_challenges))
                )

        if game_root_touched:
            validate_game_dir(root, errors)
            validated_targets.append("game")

        for slug in sorted(touched_challenges):
            chal_dir = root / "game" / "challenges" / slug
            validate_challenge_dir(chal_dir, slug, errors)
            validated_targets.append(f"challenge:{slug}")

    if errors:
        print(f"VALIDATION FAILED ({len(errors)} error(s)):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    summary = ", ".join(validated_targets) if validated_targets else "no targets"
    print(f"VALIDATION PASSED ({summary})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
