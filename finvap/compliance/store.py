"""Vector store for the regulatory clauses (ChromaDB, persisted on disk).

One collection per framework, cosine-space so similarity = ``1 - distance``.
Embeddings come from ChromaDB's built-in ONNX ``all-MiniLM-L6-v2`` — no PyTorch,
downloaded once (~80 MB) on first use. The clause's section heading is prepended
to its text before embedding (extra topic signal), while the raw clause text and
citation are kept in metadata for display and report grounding.
"""
from __future__ import annotations

from ..config import CHROMA_DIR
from .regulations import Clause, load_clauses

_COSINE = {"hnsw:space": "cosine"}


def _client():
    import chromadb
    return chromadb.PersistentClient(path=str(CHROMA_DIR))


def _name(framework: str) -> str:
    return f"reg_{framework}"


def build_index(framework: str, clauses: list[Clause] | None = None) -> int:
    """(Re)build the vector index for a framework. Returns the clause count."""
    if clauses is None:
        clauses = load_clauses(framework)
    client = _client()
    try:
        client.delete_collection(_name(framework))
    except Exception:
        pass
    col = client.create_collection(_name(framework), metadata=_COSINE)

    ids, docs, metas = [], [], []
    for c in clauses:
        ids.append(f"{framework}:{c.clause_id}")
        docs.append(f"{c.section}: {c.text}" if c.section else c.text)
        metas.append({
            "clause_id": c.clause_id, "section": c.section, "binding": c.binding,
            "citation": c.citation, "framework": framework, "text": c.text,
        })
    if ids:
        col.add(ids=ids, documents=docs, metadatas=metas)
    return len(ids)


def index_count(framework: str) -> int:
    try:
        return _client().get_collection(_name(framework)).count()
    except Exception:
        return 0


def query(framework: str, text: str, k: int = 3, floor: float = 0.2) -> list[dict]:
    """Return up to k clause matches with cosine similarity >= floor, best first."""
    try:
        col = _client().get_collection(_name(framework))
    except Exception as e:
        raise RuntimeError(
            f"No clause index for {framework.upper()} — run "
            f"`finvap map --framework {framework} --rebuild` first."
        ) from e
    if not text.strip():
        return []
    res = col.query(query_texts=[text], n_results=k)
    out: list[dict] = []
    for meta, dist in zip(res["metadatas"][0], res["distances"][0]):
        sim = 1.0 - float(dist)  # cosine space
        if sim >= floor:
            out.append({**meta, "score": round(sim, 3)})
    return out
