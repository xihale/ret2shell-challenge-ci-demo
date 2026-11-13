#!/usr/bin/env python3
"""Automated exploit/smoke-test script for Web Hello World."""

import argparse
import os
import re
import sys
import urllib.error
import urllib.request


def resolve_base_url(args: argparse.Namespace) -> str:
    """Resolve target base URL from CLI arguments or environment variables."""
    if args.url:
        return args.url.rstrip("/")
    env_url = os.environ.get("TARGET_URL", "").strip()
    if env_url:
        return env_url.rstrip("/")

    host = args.host or os.environ.get("TARGET_HOST") or "127.0.0.1"
    port = args.port or int(os.environ.get("TARGET_PORT") or "8080")
    return f"http://{host}:{port}"


def fetch_text(url: str, timeout: float = 10.0) -> str:
    """Fetch UTF-8 response body from a URL."""
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status != 200:
            raise RuntimeError(f"Unexpected HTTP status {resp.status} for {url}")
        return resp.read().decode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify Web Hello World and retrieve flag.")
    parser.add_argument("--url", help="Target base URL (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--host", help="Target hostname/IP (default: TARGET_HOST or 127.0.0.1)")
    parser.add_argument("--port", type=int, help="Target port (default: TARGET_PORT or 8080)")
    args = parser.parse_args()

    base_url = resolve_base_url(args)

    index_body = fetch_text(f"{base_url}/")
    if "Hello" not in index_body:
        raise AssertionError(f"Expected 'Hello' in / response, got: {index_body!r}")

    flag_body = fetch_text(f"{base_url}/flag").strip()
    match = re.search(r"flag\{[^}\s]+\}", flag_body)
    flag = match.group(0) if match else flag_body
    if not flag:
        raise AssertionError("Empty flag returned from /flag")

    print(flag)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, RuntimeError, urllib.error.URLError) as exc:
        sys.stderr.write(f"Exploit failed: {exc}\n")
        raise SystemExit(1)
