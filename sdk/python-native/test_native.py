"""End-to-end tests for the native (PyO3) binding.

Run:
    ./build.sh && python3 -m pytest test_native.py     # or: python3 test_native.py

Works with pytest or as a plain script. Builds nothing itself — run build.sh
first so `neleus_native.so` sits next to this file.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))

try:
    import neleus_native as n
except ImportError as e:  # pragma: no cover
    raise SystemExit(
        f"neleus_native not built ({e}). Run ./build.sh first."
    )


class NativeBinding(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="neleus-native-")
        self.db = n.Neleus(os.path.join(self.tmp, "db"))

    def _seed(self, head="main"):
        manifest, commit = self.db.put_document(
            head, "kb.md",
            "Native Python agents need verifiable per-jurisdiction audit trails.",
        )
        return manifest, commit

    def test_ingest_search_prove_verify(self):
        _, commit = self._seed()
        hits = self.db.search("main", "verifiable audit", mode="hybrid", top_k=3)
        self.assertGreater(len(hits), 0)
        self.assertIn("chunk", hits[0])

        proof = self.db.prove(commit, hits[0]["chunk"])
        self.assertIsInstance(proof, bytes)
        verdict = self.db.verify_proof(proof)
        self.assertTrue(verdict["valid"])
        self.assertEqual(verdict["anchor"], "doc")

    def test_tampered_proof_is_invalid(self):
        _, commit = self._seed()
        hits = self.db.search("main", "verifiable audit", mode="semantic", top_k=1)
        proof = bytearray(self.db.prove(commit, hits[0]["chunk"]))
        proof[len(proof) // 2] ^= 0xFF
        verdict = self.db.verify_proof(bytes(proof))
        self.assertFalse(verdict["valid"])

    def test_audit_export(self):
        self._seed()
        qm = self.db.record_query("main", "verifiable audit", principal="agent:py")
        self.db.commit("main", "audit", manifests=[qm])
        self.db.checkpoint("main")

        bundle = os.path.join(self.tmp, "q.nelaudit")
        self.assertEqual(self.db.audit_export("main", bundle), 1)
        self.assertTrue(os.path.exists(bundle))

    def test_time_travel(self):
        _, c1 = self._seed()
        # newer commit adds a second document
        self.db.put_document("main", "kb2", "completely unrelated second document about widgets")
        # querying the old commit must not see the newer doc
        old = self.db.search(c1, "widgets", mode="semantic", top_k=5)
        self.assertEqual(len(old), 0)

    def test_sessions(self):
        self._seed()
        seq = self.db.session_append("main", "s1", "hello", role="user", ttl_secs=3600)
        self.assertEqual(seq, 0)
        seq2 = self.db.session_append("main", "s1", "world", role="assistant")
        self.assertEqual(seq2, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
