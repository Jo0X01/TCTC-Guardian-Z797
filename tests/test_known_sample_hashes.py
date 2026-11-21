from __future__ import annotations

import unittest

from guardian.indicators import KNOWN_SAMPLE_ARTIFACTS, known_sample_artifact


class KnownSampleArtifactHashTests(unittest.TestCase):
    def test_exact_hash_and_size_match_returns_sample_label(self):
        digest, (size, label) = next(iter(KNOWN_SAMPLE_ARTIFACTS.items()))
        self.assertEqual(known_sample_artifact(digest, size), label)

    def test_hash_match_with_wrong_size_is_not_accepted(self):
        digest, (size, _) = next(iter(KNOWN_SAMPLE_ARTIFACTS.items()))
        self.assertIsNone(known_sample_artifact(digest, size + 1))

    def test_unknown_hash_is_not_accepted(self):
        self.assertIsNone(known_sample_artifact("0" * 64, 8147456))

    def test_all_known_hashes_have_expected_sha256_shape(self):
        self.assertEqual(len(KNOWN_SAMPLE_ARTIFACTS), 7)
        self.assertTrue(all(len(key) == 64 and int(key, 16) >= 0 for key in KNOWN_SAMPLE_ARTIFACTS))


if __name__ == "__main__":
    unittest.main()
