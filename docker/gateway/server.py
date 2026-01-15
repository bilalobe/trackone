import os

# Import the Rust extension module built by crates/trackone-gateway.
# The module name is `trackone_core` (see #[pymodule] fn trackone_core in Rust).
import trackone_core  # noqa: F401
import uvicorn
from fastapi import FastAPI
from fastapi.responses import PlainTextResponse

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
