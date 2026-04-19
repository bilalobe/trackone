import os

import uvicorn
from fastapi import FastAPI
from fastapi.responses import PlainTextResponse

# Import the Rust extension module built by crates/trackone-gateway.
# The public import is `trackone_core` (native module lives at `trackone_core._native`).
import trackone_core  # noqa: F401

app = FastAPI()


@app.get("/health", response_class=PlainTextResponse)
def health() -> str:
    return "ok"


def main() -> None:
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8080"))
    uvicorn.run(app, host=host, port=port, log_level=os.getenv("LOG_LEVEL", "info"))


if __name__ == "__main__":
    main()
