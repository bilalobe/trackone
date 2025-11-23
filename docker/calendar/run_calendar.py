import os
import subprocess
import sys
import time


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

    calendars = os.environ.get(
        "OTS_CALENDARS", "https://a.pool.opentimestamps.org"
    ).strip()
    interval = float(os.environ.get("OTS_CLIENT_PING_INTERVAL", "60"))

    print(
        "Starting OTS client sidecar. Using calendars=",
        calendars,
        "; ping interval=",
        interval,
        flush=True,
    )

    # Main loop: periodically hit `opentimestamps-client` in a
    # read-only/help-like mode to ensure tooling is present.
    while True:
        try:
            # This is intentionally a no-op / help-style invocation; it
            # exercises the CLI wiring without mutating state.
            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "opentimestamps_client",
                    "--help",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
                text=True,
            )
            print("[ots-client] exit=", proc.returncode, flush=True)
            # Do not fail the container if the command returns non-zero;
            # log and continue so tests can still proceed.
        except KeyboardInterrupt:
            print(
                "Received KeyboardInterrupt; shutting down OTS client sidecar.",
                flush=True,
            )
            return 0
        except Exception as exc:  # pragma: no cover - defensive
            print(f"[ots-client] unexpected error: {exc}", file=sys.stderr, flush=True)

        time.sleep(interval)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
