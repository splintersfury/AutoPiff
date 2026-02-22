"""
Function embedding index for cross-driver variant search.

Builds and queries a ChromaDB collection of decompiled function embeddings
from the driver corpus. Used by variant_finder.py for Mode 3.
"""

import hashlib
import logging
import os
import re
from pathlib import Path

import chromadb

logger = logging.getLogger("kernelsense.embeddings")

# ChromaDB persistent directory
DEFAULT_PERSIST_DIR = os.path.expanduser("~/Documents/AutoPiff/data/embeddings")
DEFAULT_COLLECTION = "driver_functions"


class FunctionEmbeddingIndex:
    """ChromaDB-backed index of decompiled driver function embeddings."""

    def __init__(
        self,
        persist_dir: str = DEFAULT_PERSIST_DIR,
        collection_name: str = DEFAULT_COLLECTION,
    ):
        self.persist_dir = persist_dir
        os.makedirs(persist_dir, exist_ok=True)

        self.client = chromadb.PersistentClient(path=persist_dir)
        self.collection = self.client.get_or_create_collection(
            name=collection_name,
            metadata={"hnsw:space": "cosine"},
        )

        logger.info(
            f"Embedding index: {self.collection.count()} functions in "
            f"{persist_dir}"
        )

    def add_driver(self, driver_name: str, decompiled_path: str) -> int:
        """Parse a decompiled C file and add all functions to the index.

        Returns the number of functions added.
        """
        path = Path(decompiled_path)
        if not path.exists():
            logger.warning(f"File not found: {decompiled_path}")
            return 0

        code = path.read_text(encoding="utf-8", errors="replace")
        functions = self._split_functions(code)

        if not functions:
            logger.info(f"No functions found in {driver_name}")
            return 0

        ids = []
        documents = []
        metadatas = []

        for func_name, func_code in functions:
            # Skip very short functions (likely stubs)
            if len(func_code.strip()) < 50:
                continue

            doc_id = self._make_id(driver_name, func_name)

            # Skip if already indexed
            existing = self.collection.get(ids=[doc_id])
            if existing["ids"]:
                continue

            ids.append(doc_id)
            documents.append(func_code)
            metadatas.append({
                "driver": driver_name,
                "function": func_name,
                "code_length": len(func_code),
                "source_file": str(path.name),
            })

        if ids:
            # ChromaDB will use its default embedding function
            self.collection.add(
                ids=ids,
                documents=documents,
                metadatas=metadatas,
            )
            logger.info(f"Added {len(ids)} functions from {driver_name}")

        return len(ids)

    def query_similar(
        self,
        function_code: str,
        n_results: int = 20,
        exclude_driver: str | None = None,
    ) -> list[dict]:
        """Find functions similar to the given code.

        Args:
            function_code: Decompiled C code of the query function
            n_results: Number of results to return
            exclude_driver: Exclude functions from this driver

        Returns:
            List of {driver, function, code, similarity} dicts
        """
        where_filter = None
        if exclude_driver:
            where_filter = {"driver": {"$ne": exclude_driver}}

        results = self.collection.query(
            query_texts=[function_code],
            n_results=n_results,
            where=where_filter,
            include=["documents", "metadatas", "distances"],
        )

        similar = []
        if results["ids"] and results["ids"][0]:
            for i, doc_id in enumerate(results["ids"][0]):
                meta = results["metadatas"][0][i]
                distance = results["distances"][0][i]
                similarity = 1.0 - distance  # cosine distance → similarity

                similar.append({
                    "driver": meta["driver"],
                    "function": meta["function"],
                    "code": results["documents"][0][i],
                    "similarity": round(similarity, 4),
                })

        return similar

    def get_stats(self) -> dict:
        """Return index statistics."""
        count = self.collection.count()

        # Get unique drivers
        if count > 0:
            sample = self.collection.peek(limit=min(count, 1000))
            drivers = set()
            for meta in sample["metadatas"]:
                drivers.add(meta.get("driver", ""))
            return {
                "total_functions": count,
                "drivers_sampled": len(drivers),
                "persist_dir": self.persist_dir,
            }

        return {
            "total_functions": 0,
            "drivers_sampled": 0,
            "persist_dir": self.persist_dir,
        }

    def _split_functions(self, code: str) -> list[tuple[str, str]]:
        """Split decompiled C code into individual functions.

        Decompiled output from Ghidra typically has clear function boundaries
        with return type + function name + parameter list.
        """
        functions = []

        # Pattern matches typical Ghidra decompiled function signatures
        # e.g., "void FunctionName(int param1, char *param2)"
        func_pattern = re.compile(
            r"^(\w[\w\s\*]+?)\s+(\w+)\s*\([^)]*\)\s*\{",
            re.MULTILINE,
        )

        matches = list(func_pattern.finditer(code))

        for i, match in enumerate(matches):
            func_name = match.group(2)
            start = match.start()

            # Find the end of this function (matching braces)
            end = self._find_function_end(code, match.end() - 1)
            if end < 0:
                # Fallback: use the start of the next function
                end = matches[i + 1].start() if i + 1 < len(matches) else len(code)

            func_code = code[start:end]
            functions.append((func_name, func_code))

        return functions

    def _find_function_end(self, code: str, brace_pos: int) -> int:
        """Find the position of the closing brace for a function."""
        depth = 0
        i = brace_pos

        while i < len(code):
            if code[i] == "{":
                depth += 1
            elif code[i] == "}":
                depth -= 1
                if depth == 0:
                    return i + 1
            i += 1

        return -1

    def _make_id(self, driver: str, function: str) -> str:
        """Create a deterministic ID for a driver+function pair."""
        key = f"{driver}::{function}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]
