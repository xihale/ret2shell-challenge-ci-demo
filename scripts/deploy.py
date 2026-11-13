#!/usr/bin/env python3
"""CI/CD deployment and verification CLI for ret2shell challenge repositories.

Uses Python 3 standard library only (zero external pip dependencies).
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass, field
import gzip
import http.client
import http.cookiejar
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import uuid

DEFAULT_REGISTRY = "1.14.133.242:30310"
LOCAL_SMOKE_FLAG = "flag{ci_local_smoke_test_123456}"
FLAG_PATTERNS = (
    re.compile(r"flag\{[^}\r\n]+\}"),
    re.compile(r"[A-Za-z0-9_-]+\{[^}\r\n]+\}"),
)
IMAGE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
SKIP_COPY_DIRS = {"solve", "__pycache__", ".pytest_cache", ".git"}
SAFE_EXP_ENV_KEYS = (
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "TERM",
    "TMPDIR",
    "TEMP",
    "TMP",
    "PYTHONIOENCODING",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "TZ",
)


def sanitized_build_env() -> dict[str, str]:
    """Return environment for container build with CI/platform secrets stripped."""
    return {
        k: v
        for k, v in os.environ.items()
        if not k.startswith("RET2SHELL_") and k not in {"GH_TOKEN", "GITHUB_TOKEN"}
    }


def safe_exploit_env(host: str, port: int, url: str) -> dict[str, str]:
    """Return a minimal allowlisted environment for running untrusted solve/exp.py."""
    env = {k: os.environ[k] for k in SAFE_EXP_ENV_KEYS if k in os.environ}
    env["TARGET_HOST"] = host
    env["TARGET_PORT"] = str(port)
    env["TARGET_URL"] = url
    return env


class DeployError(RuntimeError):
    """Domain error for deployment, build, or verification failures."""


@dataclass
class HttpResponse:
    """Normalized HTTP response returned by Ret2ShellClient."""

    status: int
    headers: dict[str, str]
    body: bytes

    def json(self) -> object:
        """Decode response body as JSON."""
        if not self.body:
            return None
        return json.loads(self.body.decode("utf-8"))

    def text(self) -> str:
        """Decode response body as UTF-8 text."""
        return self.body.decode("utf-8", errors="replace")


class Ret2ShellApiError(DeployError):
    """HTTP error raised when a ret2shell API request fails."""

    def __init__(self, method: str, url: str, status: int, body: str) -> None:
        self.method = method
        self.url = url
        self.status = status
        self.body = body
        super().__init__(f"{method} {url} failed with HTTP {status}: {body}")


def normalize_base_url(base_url: str) -> tuple[str, str]:
    """Return (origin, api_base) from a base ret2shell URL."""
    cleaned = base_url.strip().rstrip("/")
    if not cleaned:
        raise DeployError("RET2SHELL_URL must not be empty")
    parsed = urllib.parse.urlsplit(cleaned)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise DeployError(f"Invalid RET2SHELL_URL: {base_url!r}")
    path = parsed.path.rstrip("/")
    if path.endswith("/api"):
        path = path[:-4]
    origin = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))
    api_base = f"{origin}/api"
    return origin, api_base


def build_multipart_body(
    field_name: str,
    filename: str,
    file_bytes: bytes,
    content_type: str = "application/octet-stream",
    boundary: str | None = None,
) -> tuple[bytes, str]:
    """Construct a multipart/form-data payload and its Content-Type header."""
    if boundary is None:
        boundary = f"----ret2shell-{uuid.uuid4().hex}"
    safe_filename = Path(filename).name.replace('"', "")
    header = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field_name}"; filename="{safe_filename}"\r\n'
        f"Content-Type: {content_type}\r\n\r\n"
    ).encode("utf-8")
    footer = f"\r\n--{boundary}--\r\n".encode("utf-8")
    body = header + file_bytes + footer
    return body, f"multipart/form-data; boundary={boundary}"


class Ret2ShellClient:
    """Minimal stdlib HTTP client for ret2shell API v3."""

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        timeout: float = 60.0,
    ) -> None:
        self.origin, self.api_base = normalize_base_url(base_url)
        self.username = username
        self.password = password
        self.timeout = timeout
        self.bearer_token: str | None = None
        self.cookie_jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookie_jar)
        )

    def _auth_header(self) -> str:
        if self.bearer_token:
            return f"Bearer {self.bearer_token}"
        raw = f"{self.username}:{self.password}".encode("utf-8")
        return "Basic " + base64.b64encode(raw).decode("ascii")

    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: object | None = None,
        raw_body: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        retry_on_401: bool = True,
    ) -> HttpResponse:
        """Send an authenticated request to the ret2shell API."""
        url = path if path.startswith("http") else f"{self.api_base}{path}"
        req_headers: dict[str, str] = {
            "Accept": "application/json",
            "Authorization": self._auth_header(),
            "User-Agent": "ret2shell-ci-deploy/1.0",
        }
        data: bytes | None = raw_body
        if json_body is not None:
            data = json.dumps(json_body).encode("utf-8")
            req_headers["Content-Type"] = "application/json"
        if headers:
            req_headers.update(headers)

        req = urllib.request.Request(url, data=data, headers=req_headers, method=method.upper())
        try:
            with self.opener.open(req, timeout=timeout or self.timeout) as resp:
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                set_token = resp_headers.get("set-token")
                if set_token:
                    self.bearer_token = set_token.strip()
                return HttpResponse(
                    status=resp.status,
                    headers=resp_headers,
                    body=resp.read(),
                )
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            if exc.code == 401 and retry_on_401 and self.bearer_token is not None:
                self.bearer_token = None
                return self.request(
                    method,
                    path,
                    json_body=json_body,
                    raw_body=raw_body,
                    headers=headers,
                    timeout=timeout,
                    retry_on_401=False,
                )
            raise Ret2ShellApiError(method.upper(), url, exc.code, err_body) from exc
        except urllib.error.URLError as exc:
            raise DeployError(f"{method.upper()} {url} network error: {exc.reason}") from exc

    def get_game(self, game_id: int) -> dict:
        resp = self.request("GET", f"/game/{game_id}")
        data = resp.json()
        if not isinstance(data, dict):
            raise DeployError(f"Unexpected game response: {data!r}")
        return data

    def update_game(self, game_id: int, game_model: dict) -> dict:
        resp = self.request("PATCH", f"/game/{game_id}", json_body=game_model)
        data = resp.json()
        if not isinstance(data, dict):
            raise DeployError(f"Unexpected update_game response: {data!r}")
        return data

    def upload_image(self, game_id: int, archive_path: Path) -> None:
        file_bytes = archive_path.read_bytes()
        body, content_type = build_multipart_body("file", archive_path.name, file_bytes)
        self.request(
            "POST",
            f"/game/{game_id}/registry",
            raw_body=body,
            headers={"Content-Type": content_type},
            timeout=600.0,
        )

    def list_challenges(self, game_id: int) -> list[dict]:
        resp = self.request("GET", f"/game/{game_id}/challenge")
        data = resp.json()
        if isinstance(data, list) and len(data) == 2 and isinstance(data[0], list):
            return data[0]
        if isinstance(data, list):
            return data
        raise DeployError(f"Unexpected challenge list response: {data!r}")

    def get_challenge(self, game_id: int, challenge_id: int) -> dict:
        resp = self.request("GET", f"/game/{game_id}/challenge/{challenge_id}")
        data = resp.json()
        if not isinstance(data, dict):
            raise DeployError(f"Unexpected challenge detail response: {data!r}")
        return data

    def find_challenge_by_bucket(
        self, game_id: int, slug: str, preferred_name: str | None = None
    ) -> dict | None:
        """Find a challenge in a game by its bucket slug.

        Note: GET /api/game/{id}/challenge omits `bucket` (`None`) in list queries,
        so we inspect GET /api/game/{id}/challenge/{cid} for candidate entries.
        """
        items = self.list_challenges(game_id)
        for item in items:
            if item.get("bucket") == slug:
                return item

        ordered = sorted(
            items,
            key=lambda c: 0 if preferred_name and c.get("name") == preferred_name else 1,
        )
        for item in ordered:
            cid = item.get("id")
            if cid is None:
                continue
            detail = self.get_challenge(game_id, int(cid))
            if detail.get("bucket") == slug:
                return detail
        return None

    def delete_challenge(self, game_id: int, challenge_id: int) -> None:
        self.request("DELETE", f"/game/{game_id}/challenge/{challenge_id}")

    def get_self_instances(self, game_id: int) -> list[dict]:
        resp = self.request("GET", f"/game/{game_id}/instance")
        data = resp.json()
        if not isinstance(data, list):
            raise DeployError(f"Unexpected instances response: {data!r}")
        return data

    def start_instance(self, game_id: int, challenge_id: int) -> None:
        self.request("POST", f"/game/{game_id}/challenge/{challenge_id}/instance")

    def stop_instance(self, game_id: int, challenge_id: int) -> None:
        self.request("DELETE", f"/game/{game_id}/challenge/{challenge_id}/instance")

    def submit_flag(self, game_id: int, challenge_id: int, flag: str) -> dict:
        resp = self.request(
            "POST",
            f"/game/{game_id}/challenge/{challenge_id}/submit",
            json_body={"content": flag},
        )
        data = resp.json()
        if not isinstance(data, dict):
            raise DeployError(f"Unexpected submit response: {data!r}")
        return data

    def get_submission_status(self, game_id: int, challenge_id: int, submission_id: int) -> dict:
        resp = self.request(
            "GET",
            f"/game/{game_id}/challenge/{challenge_id}/submit?id={submission_id}",
        )
        data = resp.json()
        if not isinstance(data, dict):
            raise DeployError(f"Unexpected submission status response: {data!r}")
        return data

    def get_challenge_submissions(self, game_id: int, challenge_id: int) -> list[dict]:
        resp = self.request(
            "GET",
            f"/game/{game_id}/challenge/{challenge_id}/submission?page=1&page_size=20",
        )
        data = resp.json()
        if isinstance(data, list) and len(data) == 2 and isinstance(data[0], list):
            return data[0]
        raise DeployError(f"Unexpected submissions response: {data!r}")


def render_env_toml(template_text: str, registry: str, game_bucket: str) -> str:
    """Render env.toml.tmpl placeholders and validate the resulting TOML."""
    rendered = template_text.replace("{{REGISTRY}}", registry).replace(
        "{{GAME_BUCKET}}", game_bucket
    )
    if "{{" in rendered or "}}" in rendered:
        raise DeployError(
            "Rendered env.toml still contains unresolved template placeholders"
        )
    try:
        tomllib.loads(rendered)
    except tomllib.TOMLDecodeError as exc:
        raise DeployError(f"Rendered env.toml is not valid TOML: {exc}") from exc
    return rendered


def parse_env_config(chal_dir: Path, registry: str = DEFAULT_REGISTRY, game_bucket: str = "ci") -> dict | None:
    """Load and parse env.toml.tmpl or env.toml from a challenge directory."""
    tmpl_path = chal_dir / "env.toml.tmpl"
    env_path = chal_dir / "env.toml"
    if tmpl_path.is_file():
        rendered = render_env_toml(tmpl_path.read_text(encoding="utf-8"), registry, game_bucket)
        return tomllib.loads(rendered)
    if env_path.is_file():
        return tomllib.loads(env_path.read_text(encoding="utf-8"))
    return None


def detect_changed_challenges(changed_files: list[str]) -> list[str]:
    """Extract sorted unique challenge slugs from changed repository paths."""
    slugs: set[str] = set()
    for raw_path in changed_files:
        norm = raw_path.strip().replace("\\", "/").lstrip("./")
        parts = norm.split("/")
        if len(parts) >= 3 and parts[0] == "game" and parts[1] == "challenges":
            slug = parts[2]
            if slug and slug != "_template" and not slug.startswith("."):
                slugs.add(slug)
    return sorted(slugs)


def find_challenge_dir(root: Path, slug: str) -> Path:
    """Resolve a challenge directory under <root>/game/challenges/<slug> (or fallbacks)."""
    candidates = [
        root / "game" / "challenges" / slug,
        root / "challenges" / slug,
        root / slug,
    ]
    for candidate in candidates:
        if candidate.is_dir() and (candidate / "config.toml").is_file():
            return candidate
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    raise DeployError(
        f"Challenge directory for {slug!r} not found under {root / 'game' / 'challenges'}"
    )


def discover_all_challenges(root: Path) -> list[tuple[str, Path]]:
    """Return sorted (slug, path) pairs under <root>/game/challenges/."""
    challenges_root = root / "game" / "challenges"
    if not challenges_root.is_dir():
        raise DeployError(f"Challenges directory not found: {challenges_root}")
    result: list[tuple[str, Path]] = []
    for entry in sorted(challenges_root.iterdir(), key=lambda p: p.name):
        if not entry.is_dir():
            continue
        if entry.name == "_template" or entry.name.startswith("."):
            continue
        result.append((entry.name, entry))
    return result


def detect_container_runtime() -> str:
    """Detect a working container runtime (`docker` or `podman`)."""
    override = os.environ.get("RET2SHELL_CONTAINER_RUNTIME", "").strip()
    if override:
        if shutil.which(override):
            return override
        raise DeployError(f"Configured container runtime {override!r} not found in PATH")

    candidates = [rt for rt in ("docker", "podman") if shutil.which(rt)]
    for rt in candidates:
        probe = subprocess.run(
            [rt, "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=15,
        )
        if probe.returncode == 0:
            return rt
    if candidates:
        return candidates[0]
    raise DeployError("Neither 'docker' nor 'podman' is available in PATH")


def find_containerfile(src_dir: Path, image_name: str, total_images: int) -> Path | None:
    """Locate Containerfile or Dockerfile for an image inside src/."""
    candidates = [
        src_dir / image_name / "Containerfile",
        src_dir / image_name / "Dockerfile",
    ]
    if total_images == 1:
        candidates.extend([src_dir / "Containerfile", src_dir / "Dockerfile"])
    for path in candidates:
        if path.is_file():
            return path
    return None


def image_archive_filename(image_name: str, use_zstd: bool) -> str:
    """Return archive filename without extra dots before extension."""
    if not IMAGE_NAME_RE.match(image_name):
        raise DeployError(
            f"Invalid image name {image_name!r}: must match {IMAGE_NAME_RE.pattern} (no dots allowed)"
        )
    ext = ".tar.zst" if use_zstd else ".tar.gz"
    return f"{image_name}{ext}"


@dataclass
class BuiltImage:
    """Metadata for a built container image and its exported archive."""

    name: str
    local_tag: str
    archive_path: Path
    config: dict


def build_challenge_images(
    chal_dir: Path,
    out_dir: Path,
    *,
    registry: str = DEFAULT_REGISTRY,
    game_bucket: str = "ci",
    runtime: str | None = None,
) -> list[BuiltImage]:
    """Build and archive all buildable images declared in env.toml(.tmpl)."""
    env_data = parse_env_config(chal_dir, registry=registry, game_bucket=game_bucket)
    if not env_data:
        return []
    images = env_data.get("images") or []
    src_dir = chal_dir / "src"
    if not images or not src_dir.is_dir():
        return []

    build_specs: list[tuple[dict, Path]] = []
    for image_cfg in images:
        image_name = str(image_cfg.get("name", "")).strip()
        if not image_name:
            raise DeployError(f"Image entry missing 'name' in {chal_dir}")
        cfile = find_containerfile(src_dir, image_name, len(images))
        if cfile is not None:
            build_specs.append((image_cfg, cfile))

    if not build_specs:
        return []

    rt = runtime or detect_container_runtime()
    has_zstd = shutil.which("zstd") is not None
    out_dir.mkdir(parents=True, exist_ok=True)
    built: list[BuiltImage] = []

    for image_cfg, cfile in build_specs:
        image_name = str(image_cfg["name"]).strip()
        local_tag = f"localhost/{image_name}:ci-build"
        print(f"[build] Building {image_name} with {rt} from {cfile}...")
        subprocess.run(
            [rt, "build", "-f", str(cfile), "-t", local_tag, str(cfile.parent)],
            env=sanitized_build_env(),
            check=True,
        )

        archive_name = image_archive_filename(image_name, has_zstd)
        archive_path = out_dir / archive_name
        raw_tar = out_dir / f"{image_name}.raw.tar"
        try:
            subprocess.run([rt, "save", "-o", str(raw_tar), local_tag], check=True)
            if has_zstd:
                subprocess.run(
                    ["zstd", "-f", "-q", "-19", str(raw_tar), "-o", str(archive_path)],
                    check=True,
                )
            else:
                with raw_tar.open("rb") as src_f, gzip.open(archive_path, "wb", compresslevel=6) as dst_f:
                    shutil.copyfileobj(src_f, dst_f)
        finally:
            raw_tar.unlink(missing_ok=True)

        print(f"[build] Exported {archive_path} ({archive_path.stat().st_size} bytes)")
        built.append(
            BuiltImage(
                name=image_name,
                local_tag=local_tag,
                archive_path=archive_path,
                config=image_cfg,
            )
        )
    return built


def allocate_free_port() -> int:
    """Allocate an ephemeral local TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for_service_ready(
    host: str,
    port: int,
    *,
    app_protocol: str = "raw",
    timeout: float = 30.0,
    on_poll: object | None = None,
) -> None:
    """Wait until the service behind host:port actually accepts/serves requests.

    Rootless podman (pasta/slirp4netns) binds the host port before the container
    process starts listening, causing an immediate TCP connect followed by RST.
    Probing HTTP or peeking the TCP socket avoids racing container startup.
    """
    deadline = time.monotonic() + timeout
    last_err: Exception | None = None
    proto = (app_protocol or "raw").strip().lower()

    while time.monotonic() < deadline:
        if callable(on_poll):
            on_poll()
        if proto == "http":
            req = urllib.request.Request(f"http://{host}:{port}/", method="GET")
            try:
                with urllib.request.urlopen(req, timeout=2.0):
                    return
            except urllib.error.HTTPError:
                # Any valid HTTP status (including 404/403/500) proves the HTTP server is up.
                return
            except (urllib.error.URLError, http.client.HTTPException, OSError) as exc:
                last_err = exc
        else:
            try:
                with socket.create_connection((host, port), timeout=1.5) as sock:
                    sock.settimeout(0.25)
                    try:
                        peeked = sock.recv(1, socket.MSG_PEEK)
                        if peeked:
                            return
                        # Empty recv (EOF) indicates the proxy closed immediately (backend not ready).
                        last_err = ConnectionResetError("EOF on initial TCP peek")
                    except TimeoutError:
                        # Server kept the TCP connection open waiting for input.
                        return
            except OSError as exc:
                last_err = exc
        time.sleep(0.25)

    raise DeployError(f"Timed out waiting for {host}:{port} ({proto}) to become ready ({last_err})")


def run_exploit_script(
    exp_path: Path, host: str, port: int, url: str, timeout: float = 60.0
) -> subprocess.CompletedProcess[str]:
    """Execute solve/exp.py with standard CLI flags and an allowlisted environment."""
    env = safe_exploit_env(host, port, url)
    cmd = [
        sys.executable,
        str(exp_path),
        "--host",
        host,
        "--port",
        str(port),
        "--url",
        url,
    ]
    return subprocess.run(
        cmd,
        cwd=str(exp_path.parent.parent),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def extract_flag_from_output(output: str) -> str:
    """Extract flag string from exploit stdout."""
    custom_pattern = os.environ.get("RET2SHELL_FLAG_PATTERN", "").strip()
    if custom_pattern:
        m = re.search(custom_pattern, output)
        if m:
            return m.group(0)
    for pattern in FLAG_PATTERNS:
        m = pattern.search(output)
        if m:
            return m.group(0)
    raise DeployError(f"Could not extract flag from exp.py output:\n{output}")


def parse_exposed_target(instance: dict) -> tuple[str, int, str]:
    """Resolve (host, port, url) from a ret2shell Instance response."""
    exposed = instance.get("exposed_ports") or []
    if not exposed:
        raise DeployError(
            "Instance has no exposed_ports (cluster/game may be configured for wsrx-only without NodePort traffic script)"
        )
    address = str(exposed[0].get("address", "")).strip()
    if not address:
        raise DeployError(f"Empty address in exposed_ports: {exposed!r}")

    if "://" in address:
        parsed = urllib.parse.urlsplit(address)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if not host:
            raise DeployError(f"Invalid exposed URL: {address!r}")
        return host, port, address

    if address.startswith("[") and "]:" in address:
        host_part, port_str = address.rsplit(":", 1)
        host = host_part.strip("[]")
    elif ":" in address:
        host, port_str = address.rsplit(":", 1)
    else:
        raise DeployError(f"Cannot parse host:port from exposed address {address!r}")

    port = int(port_str)
    url = f"http://{host}:{port}"
    return host, port, url


def run_local_smoke_test(chal_dir: Path, built_images: list[BuiltImage], runtime: str) -> str:
    """Run container locally and verify solve/exp.py captures injected FLAG."""
    exp_path = chal_dir / "solve" / "exp.py"
    if not exp_path.is_file():
        print("[test] No solve/exp.py found; skipping local exploit smoke test.")
        return "skipped (no solve/exp.py)"

    target_image = next((img for img in built_images if img.config.get("port")), None)
    if target_image is None:
        raise DeployError("solve/exp.py exists but no built image exposes a port in env.toml(.tmpl)")

    container_port = int(target_image.config["port"])
    host_port = allocate_free_port()
    container_name = f"r2s-ci-{chal_dir.name}-{uuid.uuid4().hex[:8]}"
    target_url = f"http://127.0.0.1:{host_port}"

    print(
        f"[test] Starting container {container_name} ({target_image.local_tag}) "
        f"on 127.0.0.1:{host_port}->{container_port}..."
    )
    subprocess.run(
        [
            runtime,
            "run",
            "-d",
            "--name",
            container_name,
            "-e",
            f"FLAG={LOCAL_SMOKE_FLAG}",
            "-p",
            f"127.0.0.1:{host_port}:{container_port}",
            target_image.local_tag,
        ],
        check=True,
    )
    try:
        app_protocol = str(target_image.config.get("app_protocol") or "raw")

        def _ensure_container_running() -> None:
            inspect = subprocess.run(
                [runtime, "inspect", "-f", "{{.State.Running}}", container_name],
                capture_output=True,
                text=True,
                check=False,
            )
            if inspect.returncode == 0 and inspect.stdout.strip() == "false":
                logs = subprocess.run(
                    [runtime, "logs", container_name],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                raise DeployError(
                    f"Container exited prematurely before port {host_port} became ready.\n"
                    f"Logs:\n{logs.stdout}\n{logs.stderr}"
                )

        try:
            wait_for_service_ready(
                "127.0.0.1",
                host_port,
                app_protocol=app_protocol,
                timeout=30.0,
                on_poll=_ensure_container_running,
            )
        except DeployError as exc:
            logs = subprocess.run(
                [runtime, "logs", container_name],
                capture_output=True,
                text=True,
                check=False,
            )
            raise DeployError(f"{exc}\nLogs:\n{logs.stdout}\n{logs.stderr}") from exc

        result = run_exploit_script(exp_path, "127.0.0.1", host_port, target_url)
        if result.returncode != 0:
            logs = subprocess.run(
                [runtime, "logs", container_name],
                capture_output=True,
                text=True,
                check=False,
            )
            raise DeployError(
                f"solve/exp.py failed with exit code {result.returncode}.\n"
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}\n"
                f"container logs:\n{logs.stdout}\n{logs.stderr}"
            )
        if LOCAL_SMOKE_FLAG not in result.stdout:
            raise DeployError(
                f"solve/exp.py did not output expected FLAG {LOCAL_SMOKE_FLAG!r}.\n"
                f"stdout:\n{result.stdout}"
            )
        print(f"[test] Local smoke test PASSED: captured {LOCAL_SMOKE_FLAG}")
        return f"passed ({LOCAL_SMOKE_FLAG})"
    finally:
        subprocess.run(
            [runtime, "rm", "-f", container_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )


def create_git_askpass_env(tmp_dir: Path, username: str, password: str) -> dict[str, str]:
    """Create a temporary GIT_ASKPASS helper so credentials never appear in URLs or logs."""
    askpass = tmp_dir / "git-askpass.sh"
    askpass.write_text(
        "#!/bin/sh\n"
        'case "$1" in\n'
        '  *Username*|*username*) printf "%s\\n" "$RET2SHELL_ASKPASS_USER" ;;\n'
        '  *Password*|*password*) printf "%s\\n" "$RET2SHELL_ASKPASS_PASS" ;;\n'
        '  *) printf "\\n" ;;\n'
        "esac\n",
        encoding="utf-8",
    )
    askpass.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    env = os.environ.copy()
    env["GIT_ASKPASS"] = str(askpass)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["RET2SHELL_ASKPASS_USER"] = username
    env["RET2SHELL_ASKPASS_PASS"] = password
    return env


def run_git(
    args: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    """Execute a git command and capture output."""
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd) if cwd else None,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def overlay_challenge_dir(
    src_chal_dir: Path,
    dest_chal_dir: Path,
    *,
    registry: str,
    game_bucket: str,
) -> None:
    """Copy a challenge directory into a ret2shell bucket repo, rendering env.toml.tmpl."""
    if dest_chal_dir.exists():
        shutil.rmtree(dest_chal_dir)
    dest_chal_dir.mkdir(parents=True, exist_ok=True)

    for root, dirs, files in os.walk(src_chal_dir):
        rel_root = Path(root).relative_to(src_chal_dir)
        dirs[:] = sorted(d for d in dirs if d not in SKIP_COPY_DIRS)
        target_dir = dest_chal_dir / rel_root
        target_dir.mkdir(parents=True, exist_ok=True)

        for fname in sorted(files):
            if fname.endswith(".tmpl"):
                continue
            src_file = Path(root) / fname
            shutil.copy2(src_file, target_dir / fname)

    tmpl_path = src_chal_dir / "env.toml.tmpl"
    if tmpl_path.is_file():
        rendered = render_env_toml(
            tmpl_path.read_text(encoding="utf-8"),
            registry=registry,
            game_bucket=game_bucket,
        )
        (dest_chal_dir / "env.toml").write_text(rendered, encoding="utf-8")


def commit_and_push_repo(
    repo_dir: Path, commit_message: str, git_env: dict[str, str]
) -> tuple[bool, str]:
    """Stage, commit (if changed), and fast-forward push a cloned bucket repository."""
    author_name = os.environ.get("RET2SHELL_GIT_AUTHOR_NAME", "ret2shell-ci")
    author_email = os.environ.get("RET2SHELL_GIT_AUTHOR_EMAIL", "ci@ret2shell.local")
    for cfg in (
        ["config", "user.name", author_name],
        ["config", "user.email", author_email],
    ):
        res = run_git(cfg, cwd=repo_dir, env=git_env)
        if res.returncode != 0:
            raise DeployError(f"git {' '.join(cfg)} failed: {res.stderr}")

    add_res = run_git(["add", "-A"], cwd=repo_dir, env=git_env)
    if add_res.returncode != 0:
        raise DeployError(f"git add failed: {add_res.stderr}")

    status_res = run_git(["status", "--porcelain"], cwd=repo_dir, env=git_env)
    if status_res.returncode != 0:
        raise DeployError(f"git status failed: {status_res.stderr}")
    if not status_res.stdout.strip():
        return False, "No changes to push"

    commit_res = run_git(["commit", "-m", commit_message], cwd=repo_dir, env=git_env)
    if commit_res.returncode != 0:
        raise DeployError(f"git commit failed: {commit_res.stdout}\n{commit_res.stderr}")

    push_res = run_git(["push", "origin", "HEAD"], cwd=repo_dir, env=git_env)
    output = (push_res.stdout + "\n" + push_res.stderr).strip()
    if push_res.returncode != 0:
        raise DeployError(f"git push failed:\n{output}")
    return True, output


def is_hints_conflict_error(message: str) -> bool:
    """Detect ret2shell post-receive rejection caused by non-append-only hints.toml edits."""
    return "Hints" in message and "can only be appended in Git" in message


def require_env(name: str) -> str:
    """Read a required environment variable."""
    value = os.environ.get(name, "").strip()
    if not value:
        raise DeployError(f"Required environment variable {name} is not set")
    return value


@dataclass
class StageReport:
    """Structured report for staging deployment & verification."""

    pr_number: str
    slug: str
    game_id: int
    game_bucket: str
    challenge_id: int | None = None
    images_uploaded: list[str] = field(default_factory=list)
    git_status: str = "pending"
    instance_endpoint: str = "not started"
    exp_status: str = "not run"
    submission_status: str = "not submitted"
    cleanup_status: str = "not needed"
    error: str | None = None

    def to_markdown(self) -> str:
        verdict = "FAILED" if self.error else "PASSED"
        icon = "❌" if self.error else "✅"
        lines = [
            f"### {icon} Ret2Shell Staging Verification ({verdict})",
            "",
            "| Field | Value |",
            "| :--- | :--- |",
            f"| **PR** | `#{self.pr_number}` |",
            f"| **Challenge Slug** | `{self.slug}` |",
            f"| **Staging Game** | `id={self.game_id}` (`{self.game_bucket}`) |",
            f"| **Challenge ID** | `{self.challenge_id if self.challenge_id is not None else 'N/A'}` |",
            f"| **Images Uploaded** | {', '.join(f'`{x}`' for x in self.images_uploaded) if self.images_uploaded else 'none'} |",
            f"| **Git Sync** | {self.git_status} |",
            f"| **Instance Endpoint** | `{self.instance_endpoint}` |",
            f"| **Exploit (`solve/exp.py`)** | {self.exp_status} |",
            f"| **Flag Submission** | {self.submission_status} |",
            f"| **Instance Cleanup** | {self.cleanup_status} |",
        ]
        if self.error:
            lines.extend(["", "**Error Details:**", "```text", self.error.strip(), "```"])
        return "\n".join(lines) + "\n"


def cmd_build_and_test(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    chal_dir = find_challenge_dir(root, args.challenge)
    out_dir = Path(args.out_dir).resolve()

    runtime = detect_container_runtime() if (chal_dir / "src").is_dir() else None
    built = build_challenge_images(chal_dir, out_dir, runtime=runtime)
    if built and runtime:
        run_local_smoke_test(chal_dir, built, runtime)
    elif (chal_dir / "solve" / "exp.py").is_file():
        print("[test] No container image built; skipping local container smoke test.")
    return 0


def start_instance_with_retry(
    client: Ret2ShellClient, game_id: int, challenge_id: int, max_wait: float = 80.0
) -> None:
    """Start a challenge instance, stopping lingering instances and retrying 60s cooldowns."""
    existing = client.get_self_instances(game_id)
    for inst in existing:
        other_cid = int(inst.get("challenge_id", 0))
        if other_cid > 0:
            print(f"[stage] Stopping lingering instance for challenge {other_cid}...")
            try:
                client.stop_instance(game_id, other_cid)
            except Ret2ShellApiError:
                pass
    if existing:
        time.sleep(3.0)

    deadline = time.monotonic() + max_wait
    while True:
        try:
            client.start_instance(game_id, challenge_id)
            return
        except Ret2ShellApiError as exc:
            if exc.status == 412 and "rebuilding cargo crates" in exc.body and time.monotonic() < deadline:
                print("[stage] Hit 60s instance start cooldown (412); waiting 10s to retry...")
                time.sleep(10.0)
                continue
            if exc.status == 409:
                print("[stage] Instance already exists (409); stopping and retrying...")
                client.stop_instance(game_id, challenge_id)
                time.sleep(3.0)
                continue
            raise


def wait_for_running_instance(
    client: Ret2ShellClient,
    game_id: int,
    challenge_id: int,
    timeout: float = 120.0,
    exposed_grace: float = 12.0,
) -> dict:
    """Poll GET /api/game/{id}/instance until Running (with grace period for exposed_ports)."""
    deadline = time.monotonic() + timeout
    running_since: float | None = None
    last_state = "NotFound"
    while time.monotonic() < deadline:
        instances = client.get_self_instances(game_id)
        for inst in instances:
            if int(inst.get("challenge_id", -1)) == challenge_id:
                last_state = str(inst.get("state", "Unknown"))
                if last_state == "Running":
                    if inst.get("exposed_ports"):
                        return inst
                    if running_since is None:
                        running_since = time.monotonic()
                    if time.monotonic() - running_since >= exposed_grace:
                        return inst
                elif last_state in {"Failed", "Succeeded"}:
                    raise DeployError(f"Instance entered terminal state {last_state!r}: {inst!r}")
        time.sleep(3.0)
    raise DeployError(
        f"Timed out waiting for challenge {challenge_id} instance to become Running (last state: {last_state})"
    )


def wait_for_submission_result(
    client: Ret2ShellClient,
    game_id: int,
    challenge_id: int,
    submission_id: int,
    timeout: float = 30.0,
) -> dict:
    """Poll submission status until checker populates `solved`."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            sub = client.get_submission_status(game_id, challenge_id, submission_id)
        except Ret2ShellApiError:
            subs = client.get_challenge_submissions(game_id, challenge_id)
            sub = next((s for s in subs if int(s.get("id", -1)) == submission_id), {})
        if sub.get("solved") is not None:
            return sub
        time.sleep(1.5)
    raise DeployError(f"Timed out waiting for checker result on submission {submission_id}")


def push_challenge_to_game_repo(
    client: Ret2ShellClient,
    game_id: int,
    game_bucket: str,
    slug: str,
    chal_dir: Path,
    registry: str,
    commit_message: str,
    *,
    recreate_on_conflict: bool = False,
) -> str:
    """Clone game repo, overlay a single challenge, commit, and push."""
    repo_url = f"{client.api_base}/game/{game_id}/repo/{game_bucket}.git"

    def _clone_overlay_push() -> tuple[bool, str]:
        with tempfile.TemporaryDirectory(prefix="r2s-git-") as tmp_str:
            tmp_dir = Path(tmp_str)
            git_env = create_git_askpass_env(tmp_dir, client.username, client.password)
            repo_dir = tmp_dir / "repo"
            clone_res = run_git(["clone", repo_url, str(repo_dir)], env=git_env)
            if clone_res.returncode != 0:
                raise DeployError(
                    f"git clone {repo_url} failed:\n{clone_res.stdout}\n{clone_res.stderr}"
                )
            overlay_challenge_dir(
                chal_dir,
                repo_dir / "challenges" / slug,
                registry=registry,
                game_bucket=game_bucket,
            )
            return commit_and_push_repo(repo_dir, commit_message, git_env)

    try:
        pushed, output = _clone_overlay_push()
        return "pushed" if pushed else f"up-to-date ({output})"
    except DeployError as exc:
        if recreate_on_conflict and is_hints_conflict_error(str(exc)):
            print("[stage] Detected hints.toml non-append-only conflict; deleting and recreating challenge...")
            cfg = tomllib.loads((chal_dir / "config.toml").read_text(encoding="utf-8"))
            old = client.find_challenge_by_bucket(game_id, slug, preferred_name=cfg.get("name"))
            if old and old.get("id") is not None:
                client.delete_challenge(game_id, int(old["id"]))
                time.sleep(1.0)
            pushed, output = _clone_overlay_push()
            return "recreated and pushed" if pushed else f"recreated ({output})"
        raise


def cmd_stage_pr(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    slug = args.challenge
    chal_dir = find_challenge_dir(root, slug)
    base_url = require_env("RET2SHELL_URL")
    user = require_env("RET2SHELL_USER")
    password = require_env("RET2SHELL_PASS")
    game_id = int(require_env("RET2SHELL_STAGING_GAME_ID"))
    registry = os.environ.get("RET2SHELL_REGISTRY", DEFAULT_REGISTRY).strip() or DEFAULT_REGISTRY

    client = Ret2ShellClient(base_url, user, password)
    game = client.get_game(game_id)
    game_bucket = game.get("bucket")
    if not game_bucket:
        raise DeployError(f"Staging game {game_id} has no bucket")
    if not game.get("hidden"):
        raise DeployError(
            f"Staging game {game_id} ({game.get('name')}) must have hidden=true to accept git pushes"
        )

    report = StageReport(
        pr_number=str(args.pr),
        slug=slug,
        game_id=game_id,
        game_bucket=str(game_bucket),
    )

    try:
        with tempfile.TemporaryDirectory(prefix="r2s-stage-build-") as build_tmp:
            built = build_challenge_images(
                chal_dir,
                Path(build_tmp),
                registry=registry,
                game_bucket=str(game_bucket),
            )
            for img in built:
                print(f"[stage] Uploading {img.archive_path.name} to game {game_id}...")
                client.upload_image(game_id, img.archive_path)
                report.images_uploaded.append(img.archive_path.name)

        report.git_status = push_challenge_to_game_repo(
            client,
            game_id,
            str(game_bucket),
            slug,
            chal_dir,
            registry,
            f"ci(pr-{args.pr}): stage {slug}",
            recreate_on_conflict=args.recreate_on_conflict,
        )

        cfg = tomllib.loads((chal_dir / "config.toml").read_text(encoding="utf-8"))
        challenge = client.find_challenge_by_bucket(
            game_id, slug, preferred_name=cfg.get("name")
        )
        if not challenge or challenge.get("id") is None:
            raise DeployError(
                f"Challenge with bucket {slug!r} not found in staging game {game_id} after push"
            )
        cid = int(challenge["id"])
        report.challenge_id = cid

        env_data = parse_env_config(chal_dir, registry=registry, game_bucket=str(game_bucket))
        if env_data and env_data.get("images"):
            print(f"[stage] Starting instance for challenge {cid}...")
            start_instance_with_retry(client, game_id, cid)
            try:
                inst = wait_for_running_instance(client, game_id, cid)
                exp_path = chal_dir / "solve" / "exp.py"
                if inst.get("exposed_ports"):
                    host, port, url = parse_exposed_target(inst)
                    report.instance_endpoint = url
                    if exp_path.is_file():
                        print(f"[stage] Running {exp_path} against {url}...")
                        exp_res = run_exploit_script(exp_path, host, port, url)
                        if exp_res.returncode != 0:
                            raise DeployError(
                                f"solve/exp.py failed (exit {exp_res.returncode}):\n"
                                f"{exp_res.stdout}\n{exp_res.stderr}"
                            )
                        flag = extract_flag_from_output(exp_res.stdout)
                        report.exp_status = f"passed (`{flag}`)"

                        sub = client.submit_flag(game_id, cid, flag)
                        sub_id = int(sub["id"])
                        checked = wait_for_submission_result(client, game_id, cid, sub_id)
                        solved = checked.get("solved")
                        res_msg = checked.get("result") or ""
                        if solved is not True:
                            raise DeployError(
                                f"Flag submission {sub_id} rejected: solved={solved}, result={res_msg!r}"
                            )
                        report.submission_status = f"solved=true (`id={sub_id}`, `{res_msg}`)"
                    else:
                        report.exp_status = "skipped (no solve/exp.py)"
                else:
                    report.instance_endpoint = (
                        f"Running (wsrx-only, traffic={inst.get('traffic')}, ports={inst.get('ports')})"
                    )
                    report.exp_status = "skipped (no exposed_ports)"
            finally:
                try:
                    client.stop_instance(game_id, cid)
                    report.cleanup_status = "stopped"
                except Exception as stop_exc:  # noqa: BLE001
                    report.cleanup_status = f"warning: {stop_exc}"
        else:
            report.instance_endpoint = "no container env"
            report.exp_status = "skipped (static challenge)"
    except Exception as exc:  # noqa: BLE001
        report.error = str(exc)

    md = report.to_markdown()
    print(md)
    if args.report_file:
        report_path = Path(args.report_file)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(md, encoding="utf-8")

    return 1 if report.error else 0


def cmd_cleanup_pr(args: argparse.Namespace) -> int:
    slug = args.challenge
    base_url = require_env("RET2SHELL_URL")
    user = require_env("RET2SHELL_USER")
    password = require_env("RET2SHELL_PASS")
    game_id = int(require_env("RET2SHELL_STAGING_GAME_ID"))

    client = Ret2ShellClient(base_url, user, password)
    challenge = client.find_challenge_by_bucket(game_id, slug)
    if not challenge or challenge.get("id") is None:
        print(f"[cleanup] Challenge {slug!r} not found in staging game {game_id}; nothing to clean up.")
        return 0

    cid = int(challenge["id"])
    print(f"[cleanup] Stopping any running instance for challenge {cid} ({slug})...")
    try:
        client.stop_instance(game_id, cid)
    except Ret2ShellApiError as exc:
        if exc.status not in {404, 412}:
            raise

    print(f"[cleanup] Deleting challenge {cid} ({slug}) from staging game {game_id}...")
    client.delete_challenge(game_id, cid)
    print(f"[cleanup] Deleted challenge {cid} ({slug}).")
    return 0


def cmd_prod_sync(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    base_url = require_env("RET2SHELL_URL")
    user = require_env("RET2SHELL_USER")
    password = require_env("RET2SHELL_PASS")
    game_id = int(require_env("RET2SHELL_PROD_GAME_ID"))
    registry = os.environ.get("RET2SHELL_REGISTRY", DEFAULT_REGISTRY).strip() or DEFAULT_REGISTRY

    client = Ret2ShellClient(base_url, user, password)
    game = client.get_game(game_id)
    game_bucket = game.get("bucket")
    if not game_bucket:
        raise DeployError(f"Production game {game_id} has no bucket")

    if not game.get("hidden"):
        print(f"[prod] Setting hidden=true on production game {game_id} before git sync...")
        game["hidden"] = True
        game = client.update_game(game_id, game)
        if not game.get("hidden"):
            raise DeployError(f"Failed to set hidden=true on production game {game_id}")

    challenges = discover_all_challenges(root)
    if not challenges:
        print("[prod] No challenges found under game/challenges/; nothing to sync.")
        return 0

    with tempfile.TemporaryDirectory(prefix="r2s-prod-build-") as build_tmp:
        build_dir = Path(build_tmp)
        for slug, chal_dir in challenges:
            built = build_challenge_images(
                chal_dir,
                build_dir / slug,
                registry=registry,
                game_bucket=str(game_bucket),
            )
            for img in built:
                print(f"[prod] Uploading {img.archive_path.name} for {slug}...")
                client.upload_image(game_id, img.archive_path)

    repo_url = f"{client.api_base}/game/{game_id}/repo/{game_bucket}.git"
    with tempfile.TemporaryDirectory(prefix="r2s-prod-git-") as tmp_str:
        tmp_dir = Path(tmp_str)
        git_env = create_git_askpass_env(tmp_dir, user, password)
        repo_dir = tmp_dir / "repo"
        clone_res = run_git(["clone", repo_url, str(repo_dir)], env=git_env)
        if clone_res.returncode != 0:
            raise DeployError(
                f"git clone {repo_url} failed:\n{clone_res.stdout}\n{clone_res.stderr}"
            )

        if args.sync_game_config:
            game_cfg = root / "game" / "config.toml"
            if not game_cfg.is_file():
                raise DeployError(f"--sync-game-config specified, but {game_cfg} does not exist")
            shutil.copy2(game_cfg, repo_dir / "config.toml")

        for slug, chal_dir in challenges:
            overlay_challenge_dir(
                chal_dir,
                repo_dir / "challenges" / slug,
                registry=registry,
                game_bucket=str(game_bucket),
            )

        pushed, output = commit_and_push_repo(
            repo_dir,
            f"ci(prod): sync {len(challenges)} challenge(s)",
            git_env,
        )
        if pushed:
            print(f"[prod] Synced {len(challenges)} challenge(s):\n{output}")
        else:
            print("[prod] Production repository already up to date.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build, smoke-test, stage, cleanup, and sync ret2shell challenges."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_build = sub.add_parser("build-and-test", help="Build container image and run local exp.py smoke test")
    p_build.add_argument("--root", default=".", help="Repository root directory")
    p_build.add_argument("--challenge", required=True, help="Challenge directory slug")
    p_build.add_argument("--out-dir", default="/tmp/r2s-build", help="Directory for exported image archives")
    p_build.set_defaults(func=cmd_build_and_test)

    p_stage = sub.add_parser("stage-pr", help="Deploy a PR challenge to staging and verify end-to-end")
    p_stage.add_argument("--root", default=".", help="Repository root directory")
    p_stage.add_argument("--challenge", required=True, help="Challenge directory slug")
    p_stage.add_argument("--pr", required=True, help="Pull Request number")
    p_stage.add_argument(
        "--recreate-on-conflict",
        action="store_true",
        help="Delete and recreate staging challenge if hints.toml fails non-append-only check",
    )
    p_stage.add_argument("--report-file", default="", help="Optional path to write Markdown report")
    p_stage.set_defaults(func=cmd_stage_pr)

    p_cleanup = sub.add_parser("cleanup-pr", help="Delete a PR challenge from the staging game")
    p_cleanup.add_argument("--challenge", required=True, help="Challenge directory slug")
    p_cleanup.set_defaults(func=cmd_cleanup_pr)

    p_prod = sub.add_parser("prod-sync", help="Sync all challenges to the production game repository")
    p_prod.add_argument("--root", default=".", help="Repository root directory")
    p_prod.add_argument(
        "--sync-game-config",
        action="store_true",
        help="Overwrite production game config.toml with game/config.toml",
    )
    p_prod.set_defaults(func=cmd_prod_sync)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except DeployError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as exc:
        print(f"ERROR: Command failed ({exc.returncode}): {exc.cmd}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
