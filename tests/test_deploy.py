#!/usr/bin/env python3
"""Unit tests for scripts/deploy.py (no external network calls)."""

from __future__ import annotations

import base64
import http.server
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import deploy  # noqa: E402


class TestPureHelpers(unittest.TestCase):
    def test_normalize_base_url(self) -> None:
        self.assertEqual(
            deploy.normalize_base_url("https://ctf.xeed.ink/"),
            ("https://ctf.xeed.ink", "https://ctf.xeed.ink/api"),
        )
        self.assertEqual(
            deploy.normalize_base_url("https://ctf.xeed.ink/api/"),
            ("https://ctf.xeed.ink", "https://ctf.xeed.ink/api"),
        )
        with self.assertRaises(deploy.DeployError):
            deploy.normalize_base_url("ftp://ctf.xeed.ink")

    def test_render_env_toml(self) -> None:
        tmpl = (
            "internet = false\n"
            "[[images]]\n"
            'name = "web-hello-world"\n'
            "port = 8080\n"
            'tag = "{{REGISTRY}}/{{GAME_BUCKET}}/web-hello-world:latest"\n'
        )
        rendered = deploy.render_env_toml(tmpl, "1.14.133.242:30310", "staging_6a")
        self.assertIn(
            'tag = "1.14.133.242:30310/staging_6a/web-hello-world:latest"',
            rendered,
        )

        with self.assertRaises(deploy.DeployError):
            deploy.render_env_toml('tag = "{{OTHER}}"', "r", "b")

        with self.assertRaises(deploy.DeployError):
            deploy.render_env_toml("not = [valid toml", "r", "b")

    def test_detect_changed_challenges(self) -> None:
        files = [
            "game/challenges/web_hello/README.md",
            "game/challenges/web_hello/src/server.py",
            "game/challenges/_template/config.toml",
            "game/challenges/.hidden/config.toml",
            "game/challenges/pwn_echo/env.toml.tmpl",
            "docs/authoring-guide.md",
        ]
        self.assertEqual(
            deploy.detect_changed_challenges(files),
            ["pwn_echo", "web_hello"],
        )

    def test_image_archive_filename(self) -> None:
        self.assertEqual(
            deploy.image_archive_filename("web-hello-world", True),
            "web-hello-world.tar.zst",
        )
        self.assertEqual(
            deploy.image_archive_filename("web-hello-world", False),
            "web-hello-world.tar.gz",
        )
        with self.assertRaises(deploy.DeployError):
            deploy.image_archive_filename("web.hello", True)

    def test_parse_exposed_target(self) -> None:
        self.assertEqual(
            deploy.parse_exposed_target(
                {"exposed_ports": [{"name": "web", "address": "134.175.144.66:31234"}]}
            ),
            ("134.175.144.66", 31234, "http://134.175.144.66:31234"),
        )
        self.assertEqual(
            deploy.parse_exposed_target(
                {"exposed_ports": [{"name": "web", "address": "https://chal.example.com:8443"}]}
            ),
            ("chal.example.com", 8443, "https://chal.example.com:8443"),
        )
        with self.assertRaises(deploy.DeployError):
            deploy.parse_exposed_target({"exposed_ports": []})

    def test_extract_flag_from_output(self) -> None:
        self.assertEqual(
            deploy.extract_flag_from_output("noise\nflag{ok_123}\nmore"),
            "flag{ok_123}",
        )
        self.assertEqual(
            deploy.extract_flag_from_output("CTF{custom_flag_42}"),
            "CTF{custom_flag_42}",
        )
        with self.assertRaises(deploy.DeployError):
            deploy.extract_flag_from_output("no flag here")

    def test_is_hints_conflict_error(self) -> None:
        self.assertTrue(
            deploy.is_hints_conflict_error(
                "Hints for challenge `Hello` can only be appended in Git."
            )
        )
        self.assertFalse(deploy.is_hints_conflict_error("other error"))

    def test_build_multipart_body(self) -> None:
        body, ctype = deploy.build_multipart_body(
            "file", "/tmp/dir/web-hello.tar.zst", b"PAYLOAD", boundary="B123"
        )
        self.assertEqual(ctype, "multipart/form-data; boundary=B123")
        self.assertIn(b'name="file"; filename="web-hello.tar.zst"', body)
        self.assertIn(b"PAYLOAD", body)

    def test_stage_report_markdown(self) -> None:
        report = deploy.StageReport(
            pr_number="7",
            slug="web_hello_world",
            game_id=2,
            game_bucket="staging_1234",
            challenge_id=9,
            images_uploaded=["web-hello-world.tar.zst"],
            git_status="pushed",
            instance_endpoint="http://134.175.144.66:30123",
            exp_status="passed (`flag{abc}`)",
            submission_status="solved=true (`id=55`, `Correct`)",
            cleanup_status="stopped",
        )
        md = report.to_markdown()
        self.assertIn("PASSED", md)
        self.assertIn("web_hello_world", md)
        self.assertIn("`id=55`", md)


class TestOverlayAndAskpass(unittest.TestCase):
    def test_overlay_challenge_dir_renders_and_filters(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            src = tmp / "src_chal"
            (src / "src").mkdir(parents=True)
            (src / "solve").mkdir()
            (src / "checker").mkdir()
            (src / "config.toml").write_text('name = "Hello"\n', encoding="utf-8")
            (src / "README.md").write_text("desc\n", encoding="utf-8")
            (src / "env.toml.tmpl").write_text(
                'internet = false\n[[images]]\nname = "hello"\n'
                'tag = "{{REGISTRY}}/{{GAME_BUCKET}}/hello:latest"\n',
                encoding="utf-8",
            )
            (src / "solve" / "exp.py").write_text("print('secret')\n", encoding="utf-8")
            (src / "src" / "server.py").write_text("pass\n", encoding="utf-8")
            (src / "checker" / "main.rx").write_text("// rx\n", encoding="utf-8")

            dst = tmp / "bucket" / "challenges" / "web_hello"
            (dst / "stale").mkdir(parents=True)
            (dst / "stale" / "old.txt").write_text("old", encoding="utf-8")

            deploy.overlay_challenge_dir(
                src, dst, registry="1.14.133.242:30310", game_bucket="test_bkt"
            )

            self.assertFalse((dst / "stale").exists())
            self.assertFalse((dst / "solve").exists())
            self.assertFalse((dst / "env.toml.tmpl").exists())
            self.assertTrue((dst / "env.toml").is_file())
            self.assertIn(
                "1.14.133.242:30310/test_bkt/hello:latest",
                (dst / "env.toml").read_text(encoding="utf-8"),
            )
            self.assertTrue((dst / "src" / "server.py").is_file())
            self.assertTrue((dst / "checker" / "main.rx").is_file())

    def test_create_git_askpass_env(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            env = deploy.create_git_askpass_env(tmp, "alice", "s3cr3t!")
            askpass = Path(env["GIT_ASKPASS"])
            self.assertTrue(askpass.is_file())
            # Secret must not be hardcoded in script content.
            self.assertNotIn("s3cr3t!", askpass.read_text(encoding="utf-8"))

            u_out = subprocess.check_output(
                [str(askpass), "Username for 'https://ctf.xeed.ink':"],
                env=env,
                text=True,
            )
            p_out = subprocess.check_output(
                [str(askpass), "Password for 'https://alice@ctf.xeed.ink':"],
                env=env,
                text=True,
            )
            self.assertEqual(u_out.strip(), "alice")
            self.assertEqual(p_out.strip(), "s3cr3t!")

    def test_sanitized_env_strips_secrets(self) -> None:
        with mock.patch.dict(
            "os.environ",
            {
                "PATH": "/usr/bin",
                "RET2SHELL_USER": "admin",
                "RET2SHELL_PASS": "hunter2",
                "GH_TOKEN": "ghp_secret",
                "GITHUB_TOKEN": "ghs_secret",
            },
            clear=False,
        ):
            build_env = deploy.sanitized_build_env()
            self.assertIn("PATH", build_env)
            self.assertNotIn("RET2SHELL_USER", build_env)
            self.assertNotIn("RET2SHELL_PASS", build_env)
            self.assertNotIn("GH_TOKEN", build_env)
            self.assertNotIn("GITHUB_TOKEN", build_env)

            exp_env = deploy.safe_exploit_env("127.0.0.1", 8080, "http://127.0.0.1:8080")
            self.assertEqual(exp_env["TARGET_HOST"], "127.0.0.1")
            self.assertEqual(exp_env["TARGET_PORT"], "8080")
            self.assertEqual(exp_env["TARGET_URL"], "http://127.0.0.1:8080")
            self.assertNotIn("RET2SHELL_USER", exp_env)
            self.assertNotIn("RET2SHELL_PASS", exp_env)
            self.assertNotIn("GH_TOKEN", exp_env)
            self.assertNotIn("GITHUB_TOKEN", exp_env)

    def test_wait_for_service_ready_http(self) -> None:
        class OkHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                return

            def do_GET(self) -> None:  # noqa: N802
                self.send_response(404)
                self.end_headers()

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), OkHandler)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            _, port = srv.server_address
            deploy.wait_for_service_ready("127.0.0.1", port, app_protocol="http", timeout=2.0)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_wait_for_running_instance_grace_for_exposed_ports(self) -> None:
        fake_client = mock.MagicMock()
        fake_client.get_self_instances.side_effect = [
            [{"challenge_id": 7, "state": "Running", "exposed_ports": None}],
            [{"challenge_id": 7, "state": "Running", "exposed_ports": [{"name": "web", "address": "1.2.3.4:30001"}]}],
        ]
        with mock.patch("deploy.time.sleep", return_value=None):
            inst = deploy.wait_for_running_instance(fake_client, 2, 7, timeout=10.0, exposed_grace=5.0)
        self.assertEqual(inst["exposed_ports"][0]["address"], "1.2.3.4:30001")


class _MockState:
    def __init__(self) -> None:
        self.requests: list[tuple[str, str, dict[str, str], bytes]] = []
        self.issue_bearer = True
        self.bearer_token = "tok-123"
        self.game = {
            "id": 2,
            "name": "Staging",
            "bucket": "staging_6a",
            "hidden": True,
        }


class TestRet2ShellClientHTTP(unittest.TestCase):
    def setUp(self) -> None:
        self.state = _MockState()
        state = self.state

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                return

            def _read_body(self) -> bytes:
                length = int(self.headers.get("Content-Length", "0"))
                return self.rfile.read(length) if length > 0 else b""

            def _send_json(self, code: int, obj: object, extra_headers: dict[str, str] | None = None) -> None:
                raw = json.dumps(obj).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                if extra_headers:
                    for k, v in extra_headers.items():
                        self.send_header(k, v)
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self) -> None:  # noqa: N802
                body = self._read_body()
                state.requests.append(("GET", self.path, dict(self.headers), body))
                if self.path == "/api/game/2":
                    extra = {"Set-Token": state.bearer_token} if state.issue_bearer else {}
                    self._send_json(200, state.game, extra)
                elif self.path == "/api/game/2/challenge":
                    # Mirrors ret2shell challenge::get_list which omits `bucket`
                    self._send_json(
                        200,
                        [
                            [
                                {"id": 10, "name": "Other", "bucket": None},
                                {"id": 11, "name": "Web Hello World", "bucket": None},
                            ],
                            1,
                        ],
                    )
                elif self.path == "/api/game/2/challenge/11":
                    self._send_json(
                        200,
                        {"id": 11, "name": "Web Hello World", "bucket": "web_hello_world"},
                    )
                elif self.path == "/api/game/2/challenge/11/submit?id=99":
                    self._send_json(
                        200,
                        {"id": 99, "solved": True, "result": "Correct"},
                    )
                else:
                    self._send_json(404, {"error": "not found"})

            def do_POST(self) -> None:  # noqa: N802
                body = self._read_body()
                state.requests.append(("POST", self.path, dict(self.headers), body))
                if self.path == "/api/game/2/registry":
                    self._send_json(200, None)
                elif self.path == "/api/game/2/challenge/11/submit":
                    self._send_json(200, {"id": 99, "solved": None, "result": None})
                else:
                    self._send_json(404, {"error": "not found"})

            def do_PATCH(self) -> None:  # noqa: N802
                body = self._read_body()
                state.requests.append(("PATCH", self.path, dict(self.headers), body))
                if self.path == "/api/game/2":
                    payload = json.loads(body.decode("utf-8"))
                    state.game = payload
                    self._send_json(200, payload)
                else:
                    self._send_json(404, {"error": "not found"})

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.client = deploy.Ret2ShellClient(f"http://{host}:{port}", "ci_bot", "ci_pass")

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def test_auth_basic_then_set_token_bearer(self) -> None:
        game = self.client.get_game(2)
        self.assertEqual(game["bucket"], "staging_6a")
        first_auth = self.state.requests[0][2]["Authorization"]
        expected_basic = "Basic " + base64.b64encode(b"ci_bot:ci_pass").decode("ascii")
        self.assertEqual(first_auth, expected_basic)

        found = self.client.find_challenge_by_bucket(
            2, "web_hello_world", preferred_name="Web Hello World"
        )
        self.assertIsNotNone(found)
        assert found is not None
        self.assertEqual(found["id"], 11)
        second_auth = self.state.requests[1][2]["Authorization"]
        self.assertEqual(second_auth, "Bearer tok-123")

    def test_submit_and_poll(self) -> None:
        sub = self.client.submit_flag(2, 11, "flag{hello}")
        self.assertEqual(sub["id"], 99)
        self.assertEqual(
            json.loads(self.state.requests[-1][3].decode("utf-8")),
            {"content": "flag{hello}"},
        )
        status = self.client.get_submission_status(2, 11, 99)
        self.assertTrue(status["solved"])

    def test_upload_image_multipart(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            tar_path = Path(tmp_str) / "web-hello-world.tar.zst"
            tar_path.write_bytes(b"ZSTD_BYTES")
            self.client.upload_image(2, tar_path)

        method, path, headers, body = self.state.requests[-1]
        self.assertEqual(method, "POST")
        self.assertEqual(path, "/api/game/2/registry")
        self.assertTrue(headers["Content-Type"].startswith("multipart/form-data; boundary="))
        self.assertIn(b'filename="web-hello-world.tar.zst"', body)
        self.assertIn(b"ZSTD_BYTES", body)


class TestGitSyncWorkflows(unittest.TestCase):
    def test_prod_sync_preserves_game_config_unless_requested(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            bare_repo = tmp / "bare.git"
            seed_repo = tmp / "seed"
            subprocess.run(["git", "init", "--bare", str(bare_repo)], check=True, stdout=subprocess.DEVNULL)
            subprocess.run(["git", "clone", str(bare_repo), str(seed_repo)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            (seed_repo / "config.toml").write_text('name = "Prod Game"\n', encoding="utf-8")
            (seed_repo / "challenges" / "existing_chal").mkdir(parents=True)
            (seed_repo / "challenges" / "existing_chal" / "config.toml").write_text('name = "Keep"\n', encoding="utf-8")
            subprocess.run(["git", "-C", str(seed_repo), "config", "user.name", "t"], check=True)
            subprocess.run(["git", "-C", str(seed_repo), "config", "user.email", "t@t"], check=True)
            subprocess.run(["git", "-C", str(seed_repo), "add", "-A"], check=True)
            subprocess.run(["git", "-C", str(seed_repo), "commit", "-m", "init"], check=True, stdout=subprocess.DEVNULL)
            subprocess.run(["git", "-C", str(seed_repo), "push", "origin", "HEAD"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            workspace = tmp / "ws"
            (workspace / "game" / "challenges" / "web_a").mkdir(parents=True)
            (workspace / "game" / "config.toml").write_text('name = "Template Game"\n', encoding="utf-8")
            (workspace / "game" / "challenges" / "web_a" / "config.toml").write_text('name = "Web A"\n', encoding="utf-8")
            (workspace / "game" / "challenges" / "web_a" / "README.md").write_text("hi\n", encoding="utf-8")

            fake_client = mock.MagicMock()
            fake_client.api_base = "https://mock"
            fake_client.username = "u"
            fake_client.password = "p"
            fake_client.get_game.return_value = {"id": 9, "bucket": "prod_bkt", "hidden": True}

            def fake_run_git(args: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None):
                if args and args[0] == "clone":
                    args = ["clone", str(bare_repo), args[2]]
                return subprocess.run(
                    ["git", *args],
                    cwd=str(cwd) if cwd else None,
                    env=env,
                    capture_output=True,
                    text=True,
                    check=False,
                )

            env_patch = {
                "RET2SHELL_URL": "https://ctf.xeed.ink",
                "RET2SHELL_USER": "u",
                "RET2SHELL_PASS": "p",
                "RET2SHELL_PROD_GAME_ID": "9",
            }
            with (
                mock.patch.dict("os.environ", env_patch, clear=False),
                mock.patch.object(deploy, "Ret2ShellClient", return_value=fake_client),
                mock.patch.object(deploy, "run_git", side_effect=fake_run_git),
            ):
                rc = deploy.main(["prod-sync", "--root", str(workspace)])
                self.assertEqual(rc, 0)

            verify_clone = tmp / "verify"
            subprocess.run(["git", "clone", str(bare_repo), str(verify_clone)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.assertEqual((verify_clone / "config.toml").read_text(encoding="utf-8"), 'name = "Prod Game"\n')
            self.assertTrue((verify_clone / "challenges" / "existing_chal" / "config.toml").is_file())
            self.assertTrue((verify_clone / "challenges" / "web_a" / "config.toml").is_file())

    def test_recreate_on_hints_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            chal_dir = tmp / "web_a"
            chal_dir.mkdir()
            (chal_dir / "config.toml").write_text('name = "Web A"\n', encoding="utf-8")

            fake_client = mock.MagicMock()
            fake_client.api_base = "https://ctf.xeed.ink/api"
            fake_client.username = "u"
            fake_client.password = "p"
            fake_client.find_challenge_by_bucket.return_value = {"id": 42, "bucket": "web_a"}

            def fake_run_git(args: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None):
                if args and args[0] == "clone":
                    Path(args[2]).mkdir(parents=True, exist_ok=True)
                return subprocess.CompletedProcess(["git", *args], 0, stdout="", stderr="")

            with (
                mock.patch.object(deploy, "run_git", side_effect=fake_run_git),
                mock.patch.object(
                    deploy,
                    "commit_and_push_repo",
                    side_effect=[
                        deploy.DeployError(
                            "Hints for challenge `Web A` can only be appended in Git."
                        ),
                        (True, "ok"),
                    ],
                ),
            ):
                status = deploy.push_challenge_to_game_repo(
                    fake_client,
                    2,
                    "stg_bkt",
                    "web_a",
                    chal_dir,
                    "1.14.133.242:30310",
                    "msg",
                    recreate_on_conflict=True,
                )
            self.assertEqual(status, "recreated and pushed")
            fake_client.delete_challenge.assert_called_once_with(2, 42)


if __name__ == "__main__":
    unittest.main()
