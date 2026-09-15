"""
retrieval_tool.py
─────────────────
ChromaDB-backed RAG retrieval tool.

PRIMARY ATTACK SURFACE for:
  - Indirect prompt injection (via poisoned corpus documents)
  - Cross-tenant leakage (shared index, insufficient access control)

Defense applied here:
  - Content isolated with explicit untrusted delimiters before returning
  - Adversarial screening delegated to InputScreener in orchestrator
"""

import logging
import os

import chromadb
from chromadb.utils import embedding_functions

logger = logging.getLogger(__name__)


class RetrievalTool:
    DESCRIPTION = (
        "Retrieves relevant documents from the enterprise knowledge base "
        "given a search query. Returns matching document excerpts. "
        "USE THIS TOOL to look up policies, procedures, or factual information."
    )

    def __init__(self, config: dict) -> None:
        self.config = config
        self.top_k = config.get("top_k", 5)
        self.threshold = config.get("similarity_threshold", 0.35)
        self.collection_name = config.get("collection", "enterprise_corpus")
        self._client: chromadb.Client | None = None
        self._collection = None

    def _get_collection(self):
        if self._collection is None:
            persist_dir = os.getenv("CHROMA_PERSIST_DIR", "data/chroma")
            self._client = chromadb.PersistentClient(path=persist_dir)
            # sentence-transformers rather than Chroma's bundled ONNX default —
            # same model family, but reuses the one already vendored locally
            # for GoalVerifier/InputScreener instead of a separate downloader.
            ef = embedding_functions.SentenceTransformerEmbeddingFunction(
                model_name="sentence-transformers/all-MiniLM-L6-v2")
            self._collection = self._client.get_or_create_collection(
                name=self.collection_name,
                embedding_function=ef,
                # Explicit cosine space so "1 - distance" below is a true
                # cosine similarity (Chroma's default index space is L2,
                # under which that arithmetic would not mean similarity).
                metadata={"hnsw:space": "cosine"},
            )
        return self._collection

    def execute(self, tool_input: dict) -> dict:
        """
        Execute a retrieval query.

        Args:
            tool_input: {"query": str, "tenant_id": str (optional)}

        Returns:
            dict with "documents" list, each containing "content" and "source"
        """
        query = tool_input.get("query", "")
        tenant_id = tool_input.get("tenant_id")

        if not query:
            return {"error": "No query provided", "documents": []}

        try:
            collection = self._get_collection()
            where_filter = {"tenant_id": tenant_id} if tenant_id else None

            results = collection.query(
                query_texts=[query],
                n_results=self.top_k,
                where=where_filter,
            )
            documents = []
            for i, doc in enumerate(results["documents"][0]):
                distance = results["distances"][0][i]
                if (1 - distance) >= self.threshold:
                    documents.append({
                        "content": doc,
                        "source": results["metadatas"][0][i].get("source", "unknown"),
                        "similarity": round(1 - distance, 4),
                        # Explicit untrusted flag — used by context manager
                        "trusted": False,
                    })

            logger.info(f"Retrieval: query='{query[:50]}' returned {len(documents)} docs")
            return {"documents": documents, "query": query}

        except Exception as exc:
            logger.error(f"Retrieval tool error: {exc}")
            return {"error": str(exc), "documents": []}

    def index_document(self, doc_id: str, content: str,
                       metadata: dict, is_poisoned: bool = False) -> None:
        """
        Index a document into the corpus.
        is_poisoned flag is for experiment tracking only — not a security control.
        """
        collection = self._get_collection()
        meta = {**metadata, "is_poisoned": is_poisoned}
        collection.upsert(
            ids=[doc_id],
            documents=[content],
            metadatas=[meta],
        )
        logger.info(f"Indexed doc_id={doc_id} | poisoned={is_poisoned}")

    def delete_document(self, doc_id: str) -> None:
        """Remove a document from the corpus (used to clean up after
        indirect-injection trials so poisoned content doesn't leak into
        later, unrelated trials)."""
        collection = self._get_collection()
        collection.delete(ids=[doc_id])
        logger.info(f"Deleted doc_id={doc_id}")
