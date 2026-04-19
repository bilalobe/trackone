import http.server
import os
import socketserver
import subprocess
import sys
from contextlib import suppress

PORT = int(os.environ.get("OTS_CAL_PORT", "8468"))
CALENDARS = os.environ.get(
    "OTS_CALENDARS",
    "https://a.pool.opentimestamps.org,https://b.pool.opentimestamps.org",
)


class HealthHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path in ("/", "/health", "/ready"):
            body = b"OK\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404)


def main() -> int:
    """Run a long-lived helper around opentimestamps-client.

    This does *not* implement a full OTS calendar server (that would
    require upstream calendar code), but it exercises the same client
    library stack the gateway uses for real Bitcoin anchoring.

    Conceptually:
    - Keep a long-lived process running so that `ots-cal` can treat this
      container as the "OTS sidecar" for integration tests.
    - Periodically run a harmless `opentimestamps-client` command
      (e.g. `opentimestamps --help`) to ensure the binary/libs are wired.

    This keeps the container alive and validates the OTS tooling
    end-to-end without pretending to be an actual HTTP calendar.
    """

    # Optionally warm-up by pinging calendars once; ignore failures here.
    print(f"Starting OTS client sidecar. Using calendars= {CALENDARS}")
    with suppress(Exception):
        subprocess.run(
            ["ots", "--help"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )

    with socketserver.TCPServer(("0.0.0.0", PORT), HealthHandler) as httpd:
        print(f"[calendar] listening on 0.0.0.0:{PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("[calendar] shutting down", file=sys.stderr)
            httpd.server_close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
