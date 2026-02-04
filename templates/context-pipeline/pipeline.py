#!/usr/bin/env python3
"""
Context Pipeline: FAISS retrieval + LLMLingua compression.

Token-efficient context loading for AI agents.
Drop-in replacement for loading entire files.

Usage:
    from pipeline import ContextPipeline
    
    p = ContextPipeline()
    p.index_workspace()
    
    result = p.get_context("What are the agent constraints?")
    print(result["context"])  # Compressed, relevant context
    print(result["stats"])    # {"origin_tokens": 5000, "compressed_tokens": 1200, ...}

Part of Agent Guard (https://agentguard.co)
"""

import os
import json
import hashlib
from pathlib import Path
from typing import Optional

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer

# Optional: LLMLingua compression
try:
    from llmlingua import PromptCompressor
    HAS_LLMLINGUA = True
except ImportError:
    HAS_LLMLINGUA = False


class ContextRetriever:
    """FAISS-based semantic search over text chunks."""

    def __init__(
        self,
        model_name: str = "all-MiniLM-L6-v2",
        chunk_size: int = 512,
        chunk_overlap: int = 50,
    ):
        self.model = SentenceTransformer(model_name)
        self.dim = self.model.get_sentence_embedding_dimension()
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        
        self.index = faiss.IndexFlatIP(self.dim)
        self.chunks: list[dict] = []
        self.file_hashes: dict[str, str] = {}

    def _chunk_text(self, text: str, source: str) -> list[dict]:
        """Split into overlapping chunks."""
        words = text.split()
        chunks = []
        
        for i in range(0, len(words), self.chunk_size - self.chunk_overlap):
            chunk_words = words[i:i + self.chunk_size]
            if len(chunk_words) < 20:
                continue
            chunks.append({
                "text": " ".join(chunk_words),
                "source": source,
                "start": i,
            })
        return chunks

    def index_file(self, path: str, force: bool = False) -> int:
        """Index a file. Returns chunks added."""
        path = str(Path(path).resolve())
        
        with open(path, "rb") as f:
            current_hash = hashlib.md5(f.read()).hexdigest()
        
        if not force and self.file_hashes.get(path) == current_hash:
            return 0
        
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
        
        chunks = self._chunk_text(text, path)
        if not chunks:
            return 0
        
        embeddings = self.model.encode(
            [c["text"] for c in chunks],
            normalize_embeddings=True
        )
        
        self.index.add(np.array(embeddings, dtype=np.float32))
        self.chunks.extend(chunks)
        self.file_hashes[path] = current_hash
        
        return len(chunks)

    def index_directory(
        self,
        directory: str,
        extensions: tuple[str, ...] = (".md", ".txt", ".py"),
        force: bool = False,
    ) -> int:
        """Index directory recursively."""
        total = 0
        skip_dirs = {"node_modules", "__pycache__", ".venv", "venv", ".git", ".context-index"}
        
        for path in Path(directory).rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in extensions:
                continue
            if path.name.startswith("."):
                continue
            if any(d in path.parts for d in skip_dirs):
                continue
            
            try:
                total += self.index_file(str(path), force=force)
            except Exception as e:
                print(f"Warning: {path}: {e}")
        
        return total

    def search(self, query: str, k: int = 5, min_score: float = 0.3) -> list[dict]:
        """Search for relevant chunks."""
        if self.index.ntotal == 0:
            return []
        
        embedding = self.model.encode([query], normalize_embeddings=True)
        scores, indices = self.index.search(
            np.array(embedding, dtype=np.float32),
            min(k, self.index.ntotal)
        )
        
        results = []
        for score, idx in zip(scores[0], indices[0]):
            if idx >= 0 and score >= min_score:
                chunk = self.chunks[idx].copy()
                chunk["score"] = float(score)
                results.append(chunk)
        
        return results

    def save(self, path: str):
        """Save index to disk."""
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        faiss.write_index(self.index, str(path / "index.faiss"))
        with open(path / "meta.json", "w") as f:
            json.dump({"chunks": self.chunks, "hashes": self.file_hashes}, f)

    def load(self, path: str):
        """Load index from disk."""
        path = Path(path)
        if (path / "index.faiss").exists():
            self.index = faiss.read_index(str(path / "index.faiss"))
        if (path / "meta.json").exists():
            with open(path / "meta.json") as f:
                data = json.load(f)
                self.chunks = data.get("chunks", [])
                self.file_hashes = data.get("hashes", {})


class ContextCompressor:
    """LLMLingua-2 prompt compression."""

    def __init__(self, device: str = "mps"):
        if not HAS_LLMLINGUA:
            raise ImportError("pip install llmlingua")
        
        self.compressor = PromptCompressor(
            model_name="microsoft/llmlingua-2-bert-base-multilingual-cased-meetingbank",
            use_llmlingua2=True,
            device_map=device,
        )

    def compress(self, text: str, target_ratio: float = 0.5) -> dict:
        """Compress text. Returns dict with compressed_prompt, stats."""
        # LLMLingua-2 has ~512 token limit, chunk if needed
        max_chars = 1500
        
        if len(text) <= max_chars:
            result = self.compressor.compress_prompt(
                text,
                rate=target_ratio,
                force_tokens=["\n", ".", "!", "?"],
            )
            return {
                "compressed_prompt": result["compressed_prompt"],
                "origin_tokens": result["origin_tokens"],
                "compressed_tokens": result["compressed_tokens"],
                "ratio": float(str(result["ratio"]).rstrip("x")),
            }
        
        # Chunk and compress
        chunks = [text[i:i+max_chars] for i in range(0, len(text), max_chars)]
        compressed = []
        origin_total = 0
        compressed_total = 0
        
        for chunk in chunks:
            if not chunk.strip():
                continue
            r = self.compressor.compress_prompt(chunk, rate=target_ratio)
            compressed.append(r["compressed_prompt"])
            origin_total += r["origin_tokens"]
            compressed_total += r["compressed_tokens"]
        
        return {
            "compressed_prompt": " ".join(compressed),
            "origin_tokens": origin_total,
            "compressed_tokens": compressed_total,
            "ratio": compressed_total / origin_total if origin_total else 1.0,
        }


class ContextPipeline:
    """
    Complete pipeline: index → retrieve → compress.
    
    Usage:
        p = ContextPipeline()
        p.index_workspace()
        result = p.get_context("query")
    """

    def __init__(
        self,
        workspace: Optional[str] = None,
        index_dir: Optional[str] = None,
        use_compression: bool = True,
        device: str = "mps",
    ):
        self.workspace = Path(workspace or os.path.expanduser("~/.openclaw/workspace"))
        self.index_dir = Path(index_dir or self.workspace / ".context-index")
        self.use_compression = use_compression and HAS_LLMLINGUA
        self._device = device
        
        self.retriever = ContextRetriever()
        if self.index_dir.exists():
            self.retriever.load(str(self.index_dir))
        
        self._compressor: Optional[ContextCompressor] = None

    @property
    def compressor(self) -> ContextCompressor:
        """Lazy-load compressor."""
        if self._compressor is None:
            self._compressor = ContextCompressor(device=self._device)
        return self._compressor

    def index_workspace(
        self,
        extensions: tuple[str, ...] = (".md", ".txt", ".py"),
        force: bool = False,
    ) -> dict:
        """Index workspace files."""
        chunks = self.retriever.index_directory(str(self.workspace), extensions, force)
        self.retriever.save(str(self.index_dir))
        
        return {
            "chunks_added": chunks,
            "total_chunks": self.retriever.index.ntotal,
            "files": len(self.retriever.file_hashes),
        }

    def get_context(
        self,
        query: str,
        k: int = 5,
        min_score: float = 0.3,
        max_tokens: int = 2000,
        compress: Optional[bool] = None,
    ) -> dict:
        """
        Get relevant, compressed context for a query.
        
        Returns:
            {
                "context": str,      # Ready for LLM
                "sources": list,     # Source files
                "stats": {           # Token metrics
                    "origin_tokens": int,
                    "compressed_tokens": int,
                    "ratio": float,
                    "savings_pct": float,
                }
            }
        """
        chunks = self.retriever.search(query, k=k, min_score=min_score)
        
        if not chunks:
            return {
                "context": "",
                "sources": [],
                "stats": {"origin_tokens": 0, "compressed_tokens": 0, "ratio": 1.0, "savings_pct": 0},
            }
        
        combined = "\n\n---\n\n".join(
            f"[{c['source']}]\n{c['text']}" for c in chunks
        )
        sources = list(set(c["source"] for c in chunks))
        
        should_compress = compress if compress is not None else self.use_compression
        
        if should_compress:
            # Estimate target ratio
            est_tokens = len(combined) / 4
            target = min(0.9, max_tokens / est_tokens) if est_tokens else 0.5
            
            result = self.compressor.compress(combined, target_ratio=target)
            return {
                "context": result["compressed_prompt"],
                "sources": sources,
                "stats": {
                    "origin_tokens": result["origin_tokens"],
                    "compressed_tokens": result["compressed_tokens"],
                    "ratio": result["ratio"],
                    "savings_pct": (1 - result["ratio"]) * 100,
                },
            }
        
        # No compression
        words = len(combined.split())
        return {
            "context": combined,
            "sources": sources,
            "stats": {"origin_tokens": words, "compressed_tokens": words, "ratio": 1.0, "savings_pct": 0},
        }

    def search(self, query: str, k: int = 5) -> list[dict]:
        """Search without compression."""
        return self.retriever.search(query, k=k)


# CLI
if __name__ == "__main__":
    import sys
    
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print("Usage: python pipeline.py <query> [--compress] [-k N]")
        sys.exit(0)
    
    query = args[0]
    compress = "--compress" in args or "-c" in args
    k = 5
    if "-k" in args:
        k = int(args[args.index("-k") + 1])
    
    p = ContextPipeline(use_compression=compress)
    
    if p.retriever.index.ntotal == 0:
        print("Indexing workspace...")
        stats = p.index_workspace()
        print(f"Indexed {stats['files']} files, {stats['total_chunks']} chunks\n")
    
    result = p.get_context(query, k=k, compress=compress)
    
    print(f"Sources: {', '.join(Path(s).name for s in result['sources'])}")
    print(f"Stats: {result['stats']['origin_tokens']} → {result['stats']['compressed_tokens']} tokens "
          f"({result['stats']['savings_pct']:.0f}% saved)\n")
    print(result["context"])
