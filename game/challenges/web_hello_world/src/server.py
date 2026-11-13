#!/usr/bin/env python3
"""Minimal HTTP server for the Web Hello World Ret2Shell sample challenge."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
import signal
import sys
from urllib.parse import urlsplit

INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Web Hello World</title>
</head>
<body>
  <h1>Hello, Ret2Shell World!</h1>
  <p>Inspect <a href="/flag">/flag</a> to retrieve your instance flag.</p>
</body>
</html>
"""


class HelloHandler(BaseHTTPRequestHandler):
    """Serve the greeting page on / and the injected FLAG on /flag."""

    def _send(self, status: int, content_type: str, body: str) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/":
            self._send(200, "text/html; charset=utf-8", INDEX_HTML)
        elif path in ("/flag", "/flag.txt"):
            flag = os.environ.get("FLAG", "flag{missing}")
            self._send(200, "text/plain; charset=utf-8", f"{flag}\n")
        else:
            self._send(404, "text/plain; charset=utf-8", "Not Found\n")

    def log_message(self, format: str, *args: object) -> None:
        sys.stderr.write(f"[http] {self.address_string()} - {format % args}\n")


def main() -> None:
    port = int(os.environ.get("PORT", "8080"))
    server = ThreadingHTTPServer(("0.0.0.0", port), HelloHandler)

    def shutdown_handler(_signum: int, _frame: object) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
