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


if __name__ == "__main__":
    unittest.main()
