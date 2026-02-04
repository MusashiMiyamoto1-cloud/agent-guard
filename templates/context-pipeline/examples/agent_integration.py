#!/usr/bin/env python3
"""
Example: Integrating Context Pipeline with an AI Agent.

Shows how to replace naive file loading with semantic retrieval + compression.
"""

import sys
sys.path.insert(0, "..")
from pipeline import ContextPipeline


# Before: Naive approach (expensive)
def load_context_naive(files: list[str]) -> str:
    """Load entire files. Wastes tokens on irrelevant content."""
    context = []
    for path in files:
        with open(path) as f:
            context.append(f"[{path}]\n{f.read()}")
    return "\n\n".join(context)


# After: Smart approach (efficient)
def load_context_smart(query: str, max_tokens: int = 2000) -> str:
    """
    Load only relevant, compressed context.
    
    Typical savings: 50-80% fewer tokens.
    """
    pipeline = ContextPipeline(use_compression=True)
    
    # Index on first run (cached after)
    if pipeline.retriever.index.ntotal == 0:
        pipeline.index_workspace()
    
    result = pipeline.get_context(query, max_tokens=max_tokens)
    
    # Log savings (optional)
    stats = result["stats"]
    print(f"[Context] {stats['origin_tokens']} → {stats['compressed_tokens']} tokens "
          f"({stats['savings_pct']:.0f}% saved)")
    
    return result["context"]


# Usage in an agent
def agent_respond(user_question: str) -> str:
    """Example agent using smart context loading."""
    
    # Load relevant context for this specific question
    context = load_context_smart(user_question, max_tokens=2000)
    
    # Construct prompt
    prompt = f"""Context (from relevant documents):
{context}

---

User Question: {user_question}

Answer based on the context above:"""
    
    # Here you'd send to your LLM
    # response = llm.complete(prompt)
    
    return prompt  # For demo, just return the prompt


if __name__ == "__main__":
    # Demo
    question = "What are the security constraints for the agent?"
    
    print("=" * 60)
    print("Context Pipeline Demo")
    print("=" * 60)
    
    prompt = agent_respond(question)
    
    print(f"\nGenerated prompt ({len(prompt)} chars):")
    print("-" * 60)
    print(prompt[:1000] + "..." if len(prompt) > 1000 else prompt)
