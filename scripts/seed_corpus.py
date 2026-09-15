"""
seed_corpus.py
──────────────
Indexes the benign document corpus (data/corpus/documents.yaml) into the
embedded ChromaDB collection used by RetrievalTool. Idempotent: re-running
just upserts the same document ids.

Usage:
  python -m scripts.seed_corpus
"""

import logging
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.tools.retrieval_tool import RetrievalTool  # noqa: E402

logging.basicConfig(level="INFO", format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def main() -> None:
    corpus_path = Path(__file__).resolve().parents[1] / "data" / "corpus" / "documents.yaml"
    with open(corpus_path) as f:
        docs = yaml.safe_load(f)

    tool = RetrievalTool({"collection": "enterprise_corpus"})
    for doc in docs:
        tool.index_document(
            doc_id=doc["id"],
            content=" ".join(doc["content"].split()),
            metadata={"source": doc["source"], "topic": doc["topic"],
                      "urgency": doc["urgency"]},
            is_poisoned=False,
        )
    logger.info(f"Seeded {len(docs)} documents into 'enterprise_corpus'")


if __name__ == "__main__":
    main()
