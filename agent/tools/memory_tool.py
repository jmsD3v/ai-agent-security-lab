import json
import os
from typing import Any


class MemoryToolError(Exception):
    pass


class MemoryTool:
    """
    Dual memory: Redis (key-value) + Chroma (vector/semantic).
    Only JSON serialization — no pickle. TTL enforced on all Redis writes.
    """

    name = "memory_tool"
    _MAX_VALUE_BYTES = 10_240
    _DEFAULT_TTL = int(os.getenv("MEMORY_TTL_SECONDS", "3600"))
    _PERSIST = os.getenv("MEMORY_PERSIST", "false").lower() == "true"

    def __init__(self, redis_url: str | None = None, chroma_host: str | None = None,
                 chroma_port: int | None = None):
        import redis as redis_lib
        import chromadb

        redis_url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self._redis = redis_lib.from_url(redis_url, decode_responses=True)

        host = chroma_host or os.getenv("CHROMA_HOST", "localhost")
        port = chroma_port or int(os.getenv("CHROMA_PORT", "8000"))
        self._chroma = chromadb.HttpClient(host=host, port=port)
        self._collection = self._chroma.get_or_create_collection("agent_memory")

    # --- Redis: key-value ---

    def store(self, key: str, value: Any) -> None:
        serialized = json.dumps(value)
        if len(serialized.encode()) > self._MAX_VALUE_BYTES:
            raise MemoryToolError(f"value too large: {len(serialized.encode())} bytes (max {self._MAX_VALUE_BYTES})")
        if self._PERSIST:
            self._redis.set(key, serialized)
        else:
            self._redis.setex(name=key, time=self._DEFAULT_TTL, value=serialized)

    def retrieve(self, key: str) -> Any | None:
        raw = self._redis.get(key)
        if raw is None:
            return None
        return json.loads(raw)  # fails fast on non-JSON — blocks deserialization attacks

    def delete(self, key: str) -> None:
        self._redis.delete(key)

    # --- Chroma: semantic / vector ---

    def embed_store(self, doc_id: str, text: str, metadata: dict | None = None) -> None:
        if len(text.encode()) > self._MAX_VALUE_BYTES:
            raise MemoryToolError(f"document too large for embedding")
        self._collection.upsert(
            documents=[text],
            ids=[doc_id],
            metadatas=[metadata or {}],
        )

    def semantic_search(self, query: str, n_results: int = 3) -> list[dict]:
        results = self._collection.query(query_texts=[query], n_results=n_results)
        docs = results.get("documents", [[]])[0]
        metas = results.get("metadatas", [[]])[0]
        return [{"document": d, "metadata": m} for d, m in zip(docs, metas)]

    def flush_all(self) -> None:
        """Wipe all memory — idempotent, used between test runs."""
        self._redis.flushdb()
        self._chroma.delete_collection("agent_memory")
        self._collection = self._chroma.get_or_create_collection("agent_memory")
