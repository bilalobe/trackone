"""Corruption and path-safety checks for detached corpus inventory verification."""

import hashlib
import tempfile
import unittest
from pathlib import Path

from replay_corpus import verify_inventory


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "evidence.bin").write_bytes(b"exact evidence")
        digest = hashlib.sha256(b"exact evidence").hexdigest()
        (self.root / "SHA256SUMS").write_text(f"{digest}  evidence.bin\n")

    def test_exact_inventory_passes(self):
        verify_inventory(self.root)

    def test_changed_bytes_fail(self):
        (self.root / "evidence.bin").write_bytes(b"altered evidence")
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            verify_inventory(self.root)

    def test_missing_file_fails(self):
        (self.root / "evidence.bin").unlink()
        with self.assertRaises(FileNotFoundError):
            verify_inventory(self.root)

    def test_extra_file_fails(self):
        (self.root / "extra.bin").write_bytes(b"unexpected")
        with self.assertRaisesRegex(ValueError, "file set mismatch"):
            verify_inventory(self.root)

    def test_parent_traversal_fails(self):
        (self.root / "SHA256SUMS").write_text(f"{'0' * 64}  ../outside\n")
        with self.assertRaisesRegex(ValueError, "unsafe"):
            verify_inventory(self.root)

    def test_duplicate_entry_fails(self):
        inventory = self.root / "SHA256SUMS"
        inventory.write_text(inventory.read_text() * 2)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            verify_inventory(self.root)


if __name__ == "__main__":
    unittest.main()
