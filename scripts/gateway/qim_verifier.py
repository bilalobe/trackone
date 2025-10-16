"""
QIM Verifier - Gateway Integration Module

Integrates QIM-A watermark verification into the framed ingest pipeline.
Parses time-series windows from fact files and performs watermark detection.

Integration Points:
- frame_verifier.py: Extracts facts from encrypted frames
- qim/detect.py: Performs watermark detection
- Output: {qim_verified: bool, confidence: float, score: float}

References:
- ADR-007: QIM-A Watermarking Architecture
- ADR-002: Telemetry Framing (for fact format)

Note: This is a STUB implementation for M#4 infrastructure setup.
      Full implementation will be added in subsequent milestones.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import numpy as np

if TYPE_CHECKING:
    from numpy.typing import NDArray


def parse_timeseries_from_fact(fact_data: dict[str, Any]) -> NDArray[np.float64]:
    """
    Extract time-series data from a fact dictionary.

    Facts follow the schema defined in toolset/unified/schemas/fact.schema.json.
    Time-series data is expected in the 'values' field (for numeric readings)
    or can be extracted from other payload fields.

    Args:
        fact_data: Fact dictionary loaded from JSON

    Returns:
        Time-series data as 1D numpy array

    Raises:
        ValueError: If fact format is invalid or no time-series found

    Example:
        >>> fact = {
        ...     "pod_id": "pod-003",
        ...     "msg_type": "biometric",
        ...     "timestamp_ms": 1234567890,
        ...     "values": [1.2, 1.3, 1.1, 1.4, 1.2]
        ... }
        >>> ts = parse_timeseries_from_fact(fact)
        >>> assert ts.shape == (5,)
    """
    # Stub implementation: try to extract numeric data from common fields
    # TODO(M#5): Implement proper parsing based on fact schema and msg_type

    # Try 'values' field first (common for numeric time-series)
    if "values" in fact_data:
        values = fact_data["values"]
        if isinstance(values, list) and len(values) > 0:
            return np.array(values, dtype=np.float64)

    # Try 'payload' field (nested data)
    if "payload" in fact_data:
        payload = fact_data["payload"]
        if isinstance(payload, dict):
            # Recursively search for numeric arrays
            for _key, val in payload.items():
                if isinstance(val, list) and len(val) > 0:
                    # Check if all elements are numeric
                    try:
                        return np.array(val, dtype=np.float64)
                    except (ValueError, TypeError):
                        continue

    raise ValueError("No valid time-series data found in fact")


def verify_qim_from_fact(
    fact_path: Path,
    expected_bits: NDArray[np.uint8] | None = None,
) -> dict[str, float | bool]:
    """
    Verify QIM watermark from a fact file.

    Loads fact, extracts time-series, performs QIM detection, and returns
    verification result.

    Args:
        fact_path: Path to fact JSON file
        expected_bits: Expected watermark bits (optional, for validation)

    Returns:
        Dictionary with keys:
            - qim_verified: bool (True if watermark verified)
            - confidence: float [0, 1] (detection confidence)
            - score: float [0, 1] (correlation score)
            - ber: float [0, 1] (bit error rate, if expected_bits provided)

    Raises:
        FileNotFoundError: If fact file not found
        ValueError: If fact format is invalid

    Example:
        >>> from pathlib import Path
        >>> result = verify_qim_from_fact(Path("out/facts/fact_001.json"))
        >>> assert "qim_verified" in result
        >>> assert "confidence" in result

    References:
        - ADR-007 Section 4 (Gateway Integration)
    """
    # Load fact from file
    if not fact_path.exists():
        raise FileNotFoundError(f"Fact file not found: {fact_path}")

    with fact_path.open("r", encoding="utf-8") as f:
        _fact_data = json.load(f)  # Stub: will be used in M#5

    # Extract time-series
    # signal = parse_timeseries_from_fact(_fact_data)  # Stub: will be used in M#5

    # Stub: return default verification result
    # TODO(M#5): Implement actual QIM detection using qim/detect.py
    result = {
        "qim_verified": False,  # Stub: always unverified
        "confidence": 0.0,  # Stub: zero confidence
        "score": 0.0,  # Stub: zero score
        "ber": 1.0 if expected_bits is not None else None,  # Stub: 100% error
    }

    return result


def verify_qim_batch(
    facts_dir: Path,
    expected_bits: NDArray[np.uint8] | None = None,
) -> list[dict[str, Any]]:
    """
    Verify QIM watermarks for all facts in a directory.

    Processes all *.json files in facts_dir and performs QIM verification
    on each. Returns list of results with fact metadata.

    Args:
        facts_dir: Directory containing fact JSON files
        expected_bits: Expected watermark bits (optional, for validation)

    Returns:
        List of dictionaries, each with:
            - fact_file: str (fact filename)
            - qim_verified: bool
            - confidence: float
            - score: float
            - ber: float (if expected_bits provided)

    Example:
        >>> from pathlib import Path
        >>> results = verify_qim_batch(Path("out/facts"))
        >>> verified_count = sum(1 for r in results if r["qim_verified"])
        >>> print(f"Verified: {verified_count}/{len(results)}")

    References:
        - ADR-007 Section 4 (Batch Processing)
    """
    if not facts_dir.exists():
        raise FileNotFoundError(f"Facts directory not found: {facts_dir}")

    results = []
    fact_files = sorted(facts_dir.glob("*.json"))

    for fact_file in fact_files:
        try:
            verification = verify_qim_from_fact(fact_file, expected_bits)
            results.append(
                {
                    "fact_file": fact_file.name,
                    **verification,
                }
            )
        except (ValueError, json.JSONDecodeError) as e:
            # Log error but continue processing other facts
            results.append(
                {
                    "fact_file": fact_file.name,
                    "qim_verified": False,
                    "confidence": 0.0,
                    "score": 0.0,
                    "error": str(e),
                }
            )

    return results


def main() -> None:
    """
    CLI entrypoint for QIM verification.

    Usage:
        python scripts/gateway/qim_verifier.py <facts_dir>
        python scripts/gateway/qim_verifier.py <fact_file.json>
    """
    import sys

    if len(sys.argv) < 2:
        print(
            "Usage: python qim_verifier.py <facts_dir|fact_file.json>", file=sys.stderr
        )
        sys.exit(1)

    path = Path(sys.argv[1])

    if path.is_dir():
        # Batch processing
        results = verify_qim_batch(path)
        print(json.dumps(results, indent=2))
    elif path.is_file():
        # Single fact processing
        result = verify_qim_from_fact(path)
        print(json.dumps(result, indent=2))
    else:
        print(f"Error: Path not found: {path}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
