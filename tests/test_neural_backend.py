"""Unit tests for tools/neural_backend.py's device selection and batched
embedding. torch/transformers are an optional [neural] extra; every test
here is gated on their availability and skips cleanly when absent.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ida_multi_mcp.tools import neural_backend  # noqa: E402

_SKIP_REASON = "torch/transformers not installed (optional [neural] extra)"


@unittest.skipUnless(neural_backend.is_available(), _SKIP_REASON)
class SelectDeviceTest(unittest.TestCase):
    def setUp(self):
        import torch
        self._orig_cuda = torch.cuda.is_available
        self._orig_mps = torch.backends.mps.is_available

    def tearDown(self):
        import torch
        torch.cuda.is_available = self._orig_cuda
        torch.backends.mps.is_available = self._orig_mps

    def test_prefers_cuda_when_available(self):
        import torch
        torch.cuda.is_available = lambda: True
        torch.backends.mps.is_available = lambda: True
        self.assertEqual(neural_backend._select_device(), "cuda")

    def test_prefers_mps_over_cpu_when_cuda_unavailable(self):
        import torch
        torch.cuda.is_available = lambda: False
        torch.backends.mps.is_available = lambda: True
        self.assertEqual(neural_backend._select_device(), "mps")

    def test_falls_back_to_cpu(self):
        import torch
        torch.cuda.is_available = lambda: False
        torch.backends.mps.is_available = lambda: False
        self.assertEqual(neural_backend._select_device(), "cpu")


class EmbedBatchTest(unittest.TestCase):
    def test_empty_list_returns_empty_without_torch(self):
        # Must not require torch/transformers to be installed: verifies the
        # guard runs before `import torch`.
        backend = neural_backend.JTransBackend("unused-model-id", "unused-tok-id")
        self.assertEqual(backend.embed_batch([]), [])


@unittest.skipUnless(neural_backend.is_available(), _SKIP_REASON)
class EmbedBatchBatchingTest(unittest.TestCase):
    """Verifies embed_batch's real tensor batching logic (padding, attention
    mask, [CLS] indexing, output ordering) via a hand-mocked _load() --
    fake-but-real small torch tensors, no real transformers model needed.
    """

    def setUp(self):
        import torch

        class _FakeTokenizer:
            def __call__(self, texts, return_tensors, truncation, max_length, padding):
                # One token per character (deterministic, easy to reason about);
                # pad to the longest text in the batch (mirrors a real tokenizer).
                lengths = [max(len(t), 1) for t in texts]
                width = max(lengths)
                input_ids = torch.zeros((len(texts), width), dtype=torch.long)
                attention_mask = torch.zeros((len(texts), width), dtype=torch.long)
                for i, n in enumerate(lengths):
                    attention_mask[i, :n] = 1
                return {"input_ids": input_ids, "attention_mask": attention_mask}

        class _FakeOutput:
            def __init__(self, last_hidden_state):
                self.last_hidden_state = last_hidden_state

        class _FakeModel:
            def __call__(self, input_ids, attention_mask):
                batch, width = input_ids.shape
                # 4-dim hidden state; row i's [CLS] (position 0) is a one-hot
                # encoding of (i + that row's real, masked sequence length).
                # Folding attention_mask into the *class index* (not just
                # magnitude, which L2-normalize would erase) means a batch
                # transposition/misindexing AND a dropped/wrong attention_mask
                # are both detectable by decoding argmax back to the row.
                hidden = torch.zeros((batch, width, 4))
                for i in range(batch):
                    real_len = int(attention_mask[i].sum().item())
                    hidden[i, 0, (i + real_len) % 4] = 1.0
                return _FakeOutput(hidden)

        self._tok, self._model, self._dev = _FakeTokenizer(), _FakeModel(), "cpu"
        self._orig_load = neural_backend._load
        neural_backend._load = lambda model_id, tokenizer_id: (
            self._tok, self._model, self._dev)

    def tearDown(self):
        neural_backend._load = self._orig_load

    def test_batched_output_preserves_order_and_count(self):
        backend = neural_backend.JTransBackend("fake-model", "fake-tok")
        token_lists = [["a", "b", "c"], ["d"], ["e", "f"]]
        # Mirrors embed_batch's own text construction, to independently
        # compute each row's expected (real, masked) sequence length.
        texts = [" ".join(toks) if toks else "" for toks in token_lists]
        lengths = [max(len(t), 1) for t in texts]

        vecs = backend.embed_batch(token_lists)
        self.assertEqual(len(vecs), 3)
        for i, v in enumerate(vecs):
            self.assertEqual(len(v), 4)
            decoded = max(range(4), key=lambda j: v[j])
            expected = (i + lengths[i]) % 4
            self.assertEqual(decoded, expected,
                              f"row {i}'s decoded index doesn't match -- batch "
                              "dimension may be transposed/misindexed, or "
                              "attention_mask isn't reaching the model correctly")

    def test_empty_token_list_entry_within_a_nonempty_batch(self):
        backend = neural_backend.JTransBackend("fake-model", "fake-tok")
        vecs = backend.embed_batch([["a", "b"], [], ["c"]])
        self.assertEqual(len(vecs), 3)


if __name__ == "__main__":
    unittest.main()
