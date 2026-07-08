"""Neural BCSD embedding backend (optional ``[neural]`` extra).

Lazy-loads jTrans (a jump-aware BERT) on demand and embeds jTrans-style token
streams (from ``api_similarity.func_tokens``) into per-function vectors for the
recall stage of ``similar_functions``.

The similarity model is **jTrans-finetune** (contrastive on BinaryCorp; MIT,
(c) 2022 VUL337 Group) -- NOT the HF ``jtrans-mfc`` malware-classification finetune.
It is downloaded on demand to ``~/.ida-mcp/models/`` (owner waived zero-dep); the
tokenizer is bundled (``tools/jtrans_tokenizer/``). ``torch``/``transformers`` are
imported lazily so the core package stays importable without the extra.
See ``docs/plans/function-similarity/04-neural-semantic-track.md``.
"""

from __future__ import annotations

import functools
import os
from pathlib import Path

_MODELS_DIR = Path.home() / ".ida-mcp" / "models"
_MODEL_SUBDIR = "jTrans-finetune"
_BUNDLED_TOKENIZER = Path(__file__).with_name("jtrans_tokenizer")
# jTrans models.tar.gz (~1.23 GB, jTrans-finetune + jTrans-pretrain), MIT-licensed.
_JTRANS_URL = "https://cloud.vul337.team:8443/s/tM5qGQPJa6iynCf/download"


def is_available() -> bool:
    """True if torch + transformers are importable (the [neural] extra is installed)."""
    import importlib.util
    return all(importlib.util.find_spec(m) for m in ("torch", "transformers"))


def ensure_model() -> Path:
    """Download + extract jTrans-finetune to ``~/.ida-mcp/models`` on first use.

    No-op if already present. Returns the model directory. Network + ~1.2 GB
    download; only the ``jTrans-finetune`` member is kept.
    """
    model_dir = _MODELS_DIR / _MODEL_SUBDIR
    if model_dir.exists():
        return model_dir
    import shutil
    import tarfile
    import tempfile
    import urllib.request
    _MODELS_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        tar_path = Path(td) / "models.tar.gz"
        urllib.request.urlretrieve(_JTRANS_URL, tar_path)  # noqa: S310 (pinned author URL)
        with tarfile.open(tar_path) as tf:
            members = [m for m in tf.getmembers()
                       if _MODEL_SUBDIR in m.name.replace("\\", "/")]
            tf.extractall(td, members=members)  # noqa: S202 (trusted archive)
        src = next(Path(td).rglob(_MODEL_SUBDIR + "/config.json")).parent
        shutil.move(str(src), str(model_dir))
    return model_dir


def resolve_paths(download: bool = True) -> tuple[str, str]:
    """Return ``(model_id, tokenizer_id)``.

    Priority: ``JTRANS_MODEL``/``JTRANS_TOKENIZER`` env override, else the local
    ``~/.ida-mcp/models/jTrans-finetune`` (downloaded on demand when ``download``)
    plus the bundled tokenizer.
    """
    env_m = os.environ.get("JTRANS_MODEL")
    if env_m:
        return env_m, os.environ.get("JTRANS_TOKENIZER", env_m)
    model_dir = _MODELS_DIR / _MODEL_SUBDIR
    if not model_dir.exists() and download:
        model_dir = ensure_model()
    tok = os.environ.get("JTRANS_TOKENIZER") or (
        str(_BUNDLED_TOKENIZER) if _BUNDLED_TOKENIZER.exists() else str(model_dir))
    return str(model_dir), tok


def _select_device() -> str:
    import torch
    if torch.cuda.is_available():
        return "cuda"
    if torch.backends.mps.is_available():
        return "mps"
    return "cpu"


@functools.lru_cache(maxsize=2)
def _load(model_id: str, tokenizer_id: str):
    import torch
    from transformers import AutoTokenizer, BertModel

    class BinBertModel(BertModel):
        """jTrans's model: BERT with position embeddings tied to word embeddings,
        so a JUMP_ADDR_k token resonates with the target instruction's position
        (its jump-aware mechanism). Exactly jTrans eval_save.py:105."""

        def __init__(self, config, add_pooling_layer=False):
            super().__init__(config, add_pooling_layer=add_pooling_layer)
            self.embeddings.position_embeddings = self.embeddings.word_embeddings

    tok = AutoTokenizer.from_pretrained(tokenizer_id)
    model = BinBertModel.from_pretrained(
        model_id, add_pooling_layer=False, ignore_mismatched_sizes=True)
    dev = _select_device()
    model.to(dev).eval()
    return tok, model, dev


class JTransBackend:
    """EmbeddingBackend impl over a jTrans checkpoint. Input = jTrans token lists."""

    name = "jtrans"
    dim = 768

    def __init__(self, model_id: str, tokenizer_id: str, max_len: int = 512):
        self.model_id = model_id
        self.tokenizer_id = tokenizer_id
        self.max_len = max_len

    def embed_batch(self, token_lists: list[list[str]]) -> list[list[float]]:
        """token_lists -> unit-normalized [CLS] vectors (list[list[float]]).

        One padded-batch tokenizer call + one forward pass per invocation
        (not per item)."""
        if not token_lists:
            return []
        import torch
        tok, model, dev = _load(self.model_id, self.tokenizer_id)
        texts = [" ".join(toks) if toks else "" for toks in token_lists]
        with torch.no_grad():
            enc = tok(texts, return_tensors="pt", truncation=True,
                      max_length=self.max_len, padding=True)
            enc = {k: v.to(dev) for k, v in enc.items()}
            cls = model(**enc).last_hidden_state[:, 0]          # [CLS] per row
            vecs = torch.nn.functional.normalize(cls, dim=1).cpu().tolist()
        return vecs

    def unk_rate(self, token_lists: list[list[str]]) -> float:
        """Fraction of [UNK] tokens (diagnostic: how well tokenisation matches vocab)."""
        tok, _, _ = _load(self.model_id, self.tokenizer_id)
        unk = tot = 0
        for toks in token_lists:
            ids = tok(" ".join(toks) if toks else "", truncation=True,
                      max_length=self.max_len)["input_ids"]
            unk += sum(1 for i in ids if i == tok.unk_token_id)
            tot += len(ids)
        return unk / tot if tot else 0.0


def get_backend(name: str = "jtrans", model_id: str | None = None,
                tokenizer_id: str | None = None) -> JTransBackend:
    if name != "jtrans":
        raise ValueError(f"unknown neural backend: {name!r}")
    if model_id is None:
        model_id, resolved_tok = resolve_paths(download=True)
        tokenizer_id = tokenizer_id or resolved_tok
    elif tokenizer_id is None:
        tokenizer_id = model_id
    return JTransBackend(model_id, tokenizer_id)
