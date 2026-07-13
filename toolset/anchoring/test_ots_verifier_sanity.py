import json
import unittest
from pathlib import Path

import ots_verifier_sanity as sanity


class OtsVerifierSanityFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parent / "fixtures"
        cls.metadata = json.loads(
            (cls.root / "hello-world-header.json").read_text(encoding="utf-8")
        )
        cls.header = bytes.fromhex(cls.metadata["bitcoin_header_hex"])

    def test_checked_in_header_matches_hash_merkle_root_and_pow(self):
        result = sanity.validate_header(self.header, self.metadata)
        self.assertEqual(result["block_hash"], self.metadata["bitcoin_block_hash"])
        self.assertEqual(result["merkle_root"], self.metadata["bitcoin_merkle_root"])

    def test_sparse_sidecar_has_one_height_header_record(self):
        sidecar = sanity.build_sparse_sidecar(
            self.metadata["bitcoin_block_height"], self.header
        )
        self.assertEqual(sidecar[:4], b"OTSV")
        self.assertEqual(len(sidecar), 100)
        self.assertEqual(
            int.from_bytes(sidecar[16:20], "little"),
            self.metadata["bitcoin_block_height"],
        )
        self.assertEqual(sidecar[20:], self.header)

    def test_corrupted_header_is_rejected(self):
        corrupted = bytearray(self.header)
        corrupted[36] ^= 1
        with self.assertRaises(sanity.SanityError):
            sanity.validate_header(bytes(corrupted), self.metadata)


if __name__ == "__main__":
    unittest.main()
