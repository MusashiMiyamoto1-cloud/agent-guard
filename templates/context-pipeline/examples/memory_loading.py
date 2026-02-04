#!/usr/bin/env python3
"""
Example: Efficient Memory Loading for Agents.

Instead of loading entire MEMORY.md + daily files,
search for relevant memories based on current context.
"""

import sys
from datetime import datetime
sys.path.insert(0, "..")
from pipeline import ContextPipeline


class SmartMemory:
    """
    Memory system that loads only relevant context.
    
    Replaces:
        with open("MEMORY.md") as f: memory = f.read()
        
    With:
        memory = SmartMemory().recall("current topic")
    """
    
    def __init__(self, workspace: str = None):
        self.pipeline = ContextPipeline(workspace=workspace)
        
        # Index memory files specifically
        if self.pipeline.retriever.index.ntotal == 0:
            self.pipeline.index_workspace(
                extensions=(".md",),  # Only markdown memories
            )
    
    def recall(
        self,
        query: str,
        k: int = 5,
        max_tokens: int = 1500,
        include_recent: bool = True,
    ) -> dict:
        """
        Recall relevant memories for a query.
        
        Args:
            query: What to remember about
            k: Number of memory chunks to retrieve
            max_tokens: Max tokens in output
            include_recent: Always include today's memory file
            
        Returns:
            {
                "memories": str,      # Compressed relevant memories
                "sources": list,      # Which files contributed
                "stats": dict,        # Token metrics
            }
        """
        result = self.pipeline.get_context(
            query,
            k=k,
            max_tokens=max_tokens,
            compress=True,
        )
        
        return {
            "memories": result["context"],
            "sources": result["sources"],
            "stats": result["stats"],
        }
    
    def recall_topic(self, topic: str) -> str:
        """Simple interface - just get the memory text."""
        return self.recall(topic)["memories"]


# Example usage patterns
def demo():
    memory = SmartMemory()
    
    # Pattern 1: Recall based on user question
    user_asks = "What did we decide about the trading limits?"
    context = memory.recall(user_asks)
    print(f"Recalled {context['stats']['compressed_tokens']} tokens about trading")
    
    # Pattern 2: Recall for task context
    task = "Update the security documentation"
    memories = memory.recall_topic(task)
    
    # Pattern 3: Multi-topic recall
    topics = ["agent security", "polymarket strategy", "x/twitter marketing"]
    for topic in topics:
        result = memory.recall(topic, k=3)
        print(f"{topic}: {len(result['sources'])} sources, "
              f"{result['stats']['compressed_tokens']} tokens")


if __name__ == "__main__":
    demo()
