"""Unit tests for AST-based RNG policy linter (scripts/lint/check_prohibited_rngs.py)"""
import sys
import tempfile
import textwrap
from pathlib import Path

# Ensure scripts/lint is importable before importing the checker
try:
    rngchk = __import__("check_prohibited_rngs")
except ModuleNotFoundError:
    ROOT = Path(__file__).resolve().parents[3]
    lint_path = str(ROOT / "scripts" / "lint")
    if lint_path not in sys.path:
        sys.path.insert(0, lint_path)
    rngchk = __import__("check_prohibited_rngs")


def _write(tmp: Path, name: str, content: str) -> Path:
    p = tmp / name
    p.write_text(textwrap.dedent(content), encoding="utf8")
    return p


def test_detect_random_call():
    """Detect random.randint() usage"""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        f = _write(tmp, "a.py", "import random\nrandom.randint(1, 2)\n")
        findings = rngchk.check_path(f)
        assert any(finding.kind.startswith("random") for finding in findings), findings


def test_detect_numpy_random_alias():
    """Detect np.random.rand() usage"""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        f = _write(tmp, "b.py", "import numpy as np\nnp.random.rand()\n")
        findings = rngchk.check_path(f)
        assert any(finding.kind == "numpy-random-call" for finding in findings), findings


def test_alias_random_module():
    """Detect aliased random imports (import random as rnd)"""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        f = _write(tmp, "c.py", "import random as rnd\nrnd.choice([1,2])\n")
        findings = rngchk.check_path(f)
        assert any(finding.kind == "random-call" for finding in findings), findings


def test_direct_import_function():
    """Detect direct function imports (from random import randint)"""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        f = _write(tmp, "d.py", "from random import randint\nprint(randint(0,3))\n")
        findings = rngchk.check_path(f)
        assert any(finding.kind == "random-func" for finding in findings), findings


def test_file_suppression():
    """File-level suppression with # allow-prohibited-rng"""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        f = _write(
            tmp, "e.py", "# allow-prohibited-rng\nimport random\nrandom.random()\n"
        )
        findings = rngchk.check_path(f)
        assert findings == []


def test_line_suppression():
    """Line-level suppression with # rng-ok"""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        f = _write(tmp, "f.py", "import random\nrandom.random()  # rng-ok\n")
        findings = rngchk.check_path(f)
        assert findings == []


def test_safe_usage_no_findings():
    """Safe usage (secrets.token_bytes) should not trigger"""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        f = _write(
            tmp, "g.py", "from secrets import token_bytes\nprint(token_bytes(16))\n"
        )
        findings = rngchk.check_path(f)
        assert findings == []


def test_system_random_allowed():
    """SystemRandom from random module should be allowed (it's a CSPRNG)"""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        f = _write(
            tmp, "h.py", "from random import SystemRandom\nsr = SystemRandom()\nsr.randint(1, 10)\n"
        )
        findings = rngchk.check_path(f)
        assert findings == []


def test_star_import_detected():
    """Star imports from random should be detected"""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        f = _write(tmp, "i.py", "from random import *\nprint('test')\n")
        findings = rngchk.check_path(f)
        assert any(finding.kind == "star-import" for finding in findings), findings


def test_star_import_with_call_detected():
    """Star imports with function calls should detect both import and call"""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        f = _write(tmp, "i2.py", "from random import *\nval = randint(1, 10)\n")
        findings = rngchk.check_path(f)
        # Should find both the star import and the function call
        assert any(finding.kind == "star-import" for finding in findings), findings
        assert any(finding.kind == "star-import-call" for finding in findings), findings


def test_numpy_star_import_with_call_detected():
    """numpy.random star imports with calls should be detected"""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        f = _write(tmp, "i3.py", "from numpy.random import *\nval = rand(5)\n")
        findings = rngchk.check_path(f)
        # Should find both the star import and the function call
        assert any(finding.kind == "star-import" for finding in findings), findings
        assert any(finding.kind == "star-import-call" for finding in findings), findings


def test_numpy_random_state_detected():
    """numpy.random.RandomState should be detected (not cryptographically secure)"""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        f = _write(
            tmp, "j.py", "import numpy as np\nrng = np.random.RandomState(42)\n"
        )
        findings = rngchk.check_path(f)
        assert any(finding.kind == "numpy-random-call" for finding in findings), findings
