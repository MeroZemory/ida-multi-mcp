"""Neural-recall integration tests (mock backend, no torch/IDA).

Verifies the opt-in jTrans recall stage: a function with NO shared instruction
shingles and NO shared anchors (so LSH + anchor candidate-gen can never surface
it) IS found once the neural backend places it near the query -- exactly the
anchor-less cross-compiler case the design targets.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ida_multi_mcp.tools import sim_score, similarity  # noqa: E402
from ida_multi_mcp.tools import neural_backend  # noqa: E402

# semantic class -> unit vector; neural twins share a class (cosine 1.0)
_SEM_VEC = {"reduce": [1.0, 0.0, 0.0], "crypto": [0.0, 1.0, 0.0], "misc": [0.0, 0.0, 1.0]}

# two DISJOINT 12-token streams: no shared shingle -> MinHash never collides
_TA = [f"a{i}.rr" for i in range(12)]
_TB = [f"b{i}.rm" for i in range(12)]
_TC = [f"c{i}.ri" for i in range(12)]
_CFG = {"bb_count": 4, "edge_count": 5, "complexity": 3, "loops": 1,
        "callee_count": 0, "caller_count": 1, "out_deg_seq": [2, 1, 0, 0]}


def _feat(addr, name, tokens, apis):
    return {
        "addr": addr, "name": name, "is_named": bool(apis), "size": 100,
        "cfg": dict(_CFG),
        "minhash": sim_score.compute_minhash(tokens),
        "apis": sorted(set(apis)), "strings": [], "consts": [],
    }


# addr -> (feature, semantic-class, jTrans tokens)
_CORPUS = {
    "0xA": (_feat("0xA", "query_reduce", _TA, []), "reduce", ["SEM_reduce"] + _TA),
    "0xB": (_feat("0xB", "twin_reduce", _TB, []), "reduce", ["SEM_reduce"] + _TB),  # neural twin, no overlap
    "0xC": (_feat("0xC", "distractor", _TC, ["malloc"]), "misc", ["SEM_misc"] + _TC),
}


class _MockBackend:
    name = "jtrans"
    dim = 3

    def embed_batch(self, token_lists):
        out = []
        for toks in token_lists:
            sem = next((t[4:] for t in toks if t.startswith("SEM_")), "misc")
            out.append(list(_SEM_VEC.get(sem, [0.0, 0.0, 0.0])))
        return out

    def unk_rate(self, token_lists):
        return 0.0


class _MockRegistry:
    def __init__(self, registry_path):
        self.registry_path = registry_path

    def list_instances(self):
        return {"nn": {"binary_name": "nn.exe", "binary_path": "C:/x/nn.exe", "arch": "x86_64"}}

    def get_instance(self, iid):
        return self.list_instances().get(iid)


class _MockRouter:
    def route_request(self, method, params):
        name = params.get("name")
        args = params.get("arguments", {})
        feats = [v[0] for v in _CORPUS.values()]
        if name == "binary_fingerprint":
            payload = {"sha256": "sha-nn", "md5": None, "function_count": len(feats), "arch": "x86_64"}
        elif name == "func_features":
            addrs = args.get("addrs", "*")
            if addrs == "*":
                payload = {"functions": feats, "total": len(feats), "cursor": {"done": True}}
            else:
                m = [f for f in feats if f["addr"] == str(addrs) or f["name"] == str(addrs)]
                payload = {"functions": m[:1], "total": len(m), "cursor": {"done": True}}
        elif name == "func_tokens":
            addrs = args.get("addrs", "*")
            if addrs == "*":
                toks = {a: v[2] for a, v in _CORPUS.items()}
            else:
                toks = {a: v[2] for a, v in _CORPUS.items()
                        if a == str(addrs) or v[0]["name"] == str(addrs)}
            payload = {"tokens": toks, "total": len(toks), "cursor": {"done": True}}
        else:
            return {"error": f"unknown tool {name}"}
        return {"content": [{"type": "text", "text": json.dumps(payload)}],
                "structuredContent": payload}


class NeuralRecallTest(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        similarity.set_registry(_MockRegistry(os.path.join(self._td.name, "instances.json")))
        similarity.set_router(_MockRouter())
        similarity._jobs.clear()
        similarity._loaded.clear()
        # enable neural + install the mock backend
        self._saved = (similarity._NEURAL, neural_backend.is_available, neural_backend.get_backend)
        similarity._NEURAL = True
        neural_backend.is_available = lambda: True
        neural_backend.get_backend = lambda *a, **k: _MockBackend()

    def tearDown(self):
        similarity._NEURAL, neural_backend.is_available, neural_backend.get_backend = self._saved
        similarity._jobs.clear()
        similarity._loaded.clear()
        self._td.cleanup()

    def test_index_stores_vectors(self):
        res = similarity.index_functions({"instance_id": "nn", "background": False})
        self.assertEqual(res["status"], "ready")
        self.assertTrue(res.get("neural"))

    def test_neural_recall_surfaces_anchorless_twin(self):
        similarity.index_functions({"instance_id": "nn", "background": False})
        out = similarity.similar_functions({"instance_id": "nn", "func": "0xA", "top_k": 5})
        addrs = [r["addr"] for r in out["results"]]
        # 0xB shares no shingle and no anchor with 0xA -> only neural recall can find it
        self.assertIn("0xB", addrs)
        top = out["results"][0]
        self.assertEqual(top["addr"], "0xB")
        self.assertIn("neural", top["signals"])
        self.assertGreater(top["signals"]["neural"], 0.99)

    def test_disabled_neural_misses_twin(self):
        similarity._NEURAL = False  # candidate-gen falls back to lexical/anchor only
        similarity.index_functions({"instance_id": "nn", "background": False})
        out = similarity.similar_functions({"instance_id": "nn", "func": "0xA", "top_k": 5})
        self.assertNotIn("0xB", [r["addr"] for r in out["results"]])

    def test_index_status_reports_full_embed_progress(self):
        from ida_multi_mcp.tools import index_store
        similarity.index_functions({"instance_id": "nn", "background": False})
        st = similarity.index_status({"instance_id": "nn"})
        self.assertEqual(st["embed_total"], 3)
        self.assertEqual(st["embed_done"], 3)
        self.assertEqual(st["embed_progress"], 1.0)
        self.assertEqual(st["embed_status"], "done")
        self.assertEqual(len(index_store.read_vectors("sha-nn", similarity._registry_path())), 3)

    def test_partial_vectors_usable_then_resume(self):
        from ida_multi_mcp.tools import index_store
        rp = similarity._registry_path()
        # phase 1: features only (neural off) -> index usable, zero vectors
        similarity._NEURAL = False
        similarity.index_functions({"instance_id": "nn", "background": False})
        self.assertEqual(index_store.read_vectors("sha-nn", rp), {})
        # hand-place ONE vector (partial), matching 0xA's neural vector
        index_store.append_vectors("sha-nn", {"0xB": [1.0, 0.0, 0.0]}, rp)
        similarity._loaded.clear()
        # partial is usable: 0xA (no anchor/shingle overlap with 0xB) still finds it
        similarity._NEURAL = True
        out = similarity.similar_functions({"instance_id": "nn", "func": "0xA", "top_k": 5})
        self.assertIn("0xB", [r["addr"] for r in out["results"]])
        st = similarity.index_status({"instance_id": "nn"})
        self.assertEqual((st["embed_done"], st["embed_total"], st["embed_status"]), (1, 3, "partial"))
        # resume: embeds the remaining functions, skipping the one already done
        similarity.index_functions({"instance_id": "nn", "background": False})
        self.assertEqual(len(index_store.read_vectors("sha-nn", rp)), 3)

    def test_sync_branch_skips_embedding_for_zero_valid_functions(self):
        # Reuse this test class's corpus/mocks but swap in a router that
        # reports zero valid functions (every func_features record is an
        # error stub) -- mirrors the real shape func_features returns for
        # an unextractable function (see test_similarity.py's _ErrRouter).
        class _EmptyValidRouter:
            def route_request(self, method, params):
                name = params.get("name")
                if name == "binary_fingerprint":
                    payload = {"sha256": "sha-empty", "md5": None,
                              "function_count": 1, "arch": "x86_64"}
                elif name == "func_features":
                    payload = {"functions": [{"addr": "0x1", "error": "no func"}],
                              "total": 1, "cursor": {"done": True}}
                else:
                    return {"error": f"unknown tool {name}"}
                return {"content": [{"type": "text", "text": json.dumps(payload)}],
                        "structuredContent": payload}

        similarity.set_router(_EmptyValidRouter())
        called = {"n": 0}

        def _raise_if_called(*a, **k):
            called["n"] += 1
            raise AssertionError("get_backend() must not be called for zero valid functions")

        orig_get_backend = neural_backend.get_backend
        neural_backend.get_backend = _raise_if_called
        try:
            res = similarity.index_functions({"instance_id": "nn", "background": False})
        finally:
            neural_backend.get_backend = orig_get_backend

        self.assertEqual(res["function_count"], 0)
        self.assertEqual(called["n"], 0)

    def test_background_branch_reports_done_for_zero_valid_functions(self):
        import time

        class _EmptyValidRouter:
            def route_request(self, method, params):
                name = params.get("name")
                if name == "binary_fingerprint":
                    payload = {"sha256": "sha-empty-bg", "md5": None,
                              "function_count": 1, "arch": "x86_64"}
                elif name == "func_features":
                    payload = {"functions": [{"addr": "0x1", "error": "no func"}],
                              "total": 1, "cursor": {"done": True}}
                else:
                    return {"error": f"unknown tool {name}"}
                return {"content": [{"type": "text", "text": json.dumps(payload)}],
                        "structuredContent": payload}

        similarity.set_router(_EmptyValidRouter())
        similarity.index_functions({"instance_id": "nn", "background": True})

        deadline = time.time() + 5.0
        st = {}
        while time.time() < deadline:
            st = similarity.index_status({"instance_id": "nn"})
            if st.get("embed_status") == "done":
                break
            time.sleep(0.01)
        else:
            self.fail("embed_status never reached 'done' within 5s "
                      f"(last status: {st})")

        self.assertEqual(st["embed_total"], 0)


class NeuralBackendPathsTest(unittest.TestCase):
    def test_env_override_and_default_tokenizer(self):
        old = (os.environ.get("JTRANS_MODEL"), os.environ.get("JTRANS_TOKENIZER"))
        try:
            os.environ["JTRANS_MODEL"] = "/x/model"
            os.environ["JTRANS_TOKENIZER"] = "/x/tok"
            m, t = neural_backend.resolve_paths(download=False)
            self.assertEqual((m, t), ("/x/model", "/x/tok"))
            # tokenizer falls back to the model id when unset
            os.environ.pop("JTRANS_TOKENIZER")
            m, t = neural_backend.resolve_paths(download=False)
            self.assertEqual((m, t), ("/x/model", "/x/model"))
        finally:
            for k, v in zip(("JTRANS_MODEL", "JTRANS_TOKENIZER"), old):
                os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)


if __name__ == "__main__":
    unittest.main()
