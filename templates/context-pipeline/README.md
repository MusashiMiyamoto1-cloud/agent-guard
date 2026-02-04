# Context Pipeline Template

Token-efficient context loading for AI agents. FAISS retrieval + LLMLingua-2 compression.

**Results:** 50-80% token reduction with minimal semantic loss.

## Quick Start

```bash
# 1. Create venv
python3 -m venv .venv && source .venv/bin/activate

# 2. Install deps
pip install -r requirements.txt

# 3. Index your workspace
python -c "from pipeline import ContextPipeline; p = ContextPipeline(); print(p.index_workspace())"

# 4. Use
./ctx "your query here" --compress
```

## Usage

### CLI
```bash
# Search only (no compression)
./ctx "agent security rules"

# Search + compress
./ctx "agent security rules" --compress

# Control result count
./ctx "query" -k 10
```

### Python API
```python
from pipeline import ContextPipeline

# Initialize (indexes automatically if needed)
p = ContextPipeline(workspace="/path/to/files")

# Get compressed context
result = p.get_context("What are the security constraints?", k=5)

print(result["context"])       # Ready for LLM
print(result["stats"])         # Token savings
print(result["sources"])       # Source files
```

### Integration with Agent Systems

```python
# OpenClaw / LangChain / AutoGen integration
def load_context(query: str, max_tokens: int = 2000) -> str:
    """Load only relevant, compressed context."""
    p = ContextPipeline()
    result = p.get_context(query, max_tokens=max_tokens)
    
    # Log savings
    stats = result["stats"]
    print(f"Loaded {stats['compressed_tokens']} tokens "
          f"(saved {stats['savings_pct']:.0f}%)")
    
    return result["context"]

# Use in prompt construction
context = load_context("user's question about X")
prompt = f"Context:\n{context}\n\nQuestion: {user_question}"
```

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  Workspace  │ ──► │   Retriever  │ ──► │ Compressor  │ ──► Optimized
│   Files     │     │   (FAISS)    │     │ (LLMLingua) │     Context
└─────────────┘     └──────────────┘     └─────────────┘
                          │
                    Semantic Search
                    (MiniLM embeddings)
```

1. **Indexer**: Chunks files, creates FAISS index with MiniLM embeddings
2. **Retriever**: Semantic search returns top-k relevant chunks
3. **Compressor**: LLMLingua-2 removes redundancy while preserving meaning

## Configuration

```python
ContextPipeline(
    workspace="/path/to/index",      # What to index
    index_dir="/path/to/.index",     # Where to store index
    use_compression=True,            # Enable LLMLingua
    device="mps",                    # mps (Apple), cuda, cpu
)
```

## File Types

Default: `.md`, `.txt`, `.py`

```python
p.index_workspace(extensions=(".md", ".txt", ".py", ".json", ".yaml"))
```

## Performance

| Metric | Value |
|--------|-------|
| Index 1000 files | ~30 seconds |
| Search latency | <50ms |
| Compression (LLMLingua-2) | ~200ms |
| Token reduction | 50-80% |

## Requirements

- Python 3.10+
- 4GB RAM minimum (8GB recommended for compression)
- Apple Silicon: uses MPS acceleration
- NVIDIA: uses CUDA if available

## Troubleshooting

**"FAISS not found"**: `pip install faiss-cpu`

**Slow first run**: Models download on first use (~500MB)

**MPS errors on Mac**: Set `device="cpu"` as fallback

---

Part of [Agent Guard](https://agentguard.co) — Security tooling for AI agents.
