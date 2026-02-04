# Agent Guard Templates

Drop-in templates for building secure, efficient AI agents.

## Available Templates

### [context-pipeline/](./context-pipeline/)
Token-efficient context loading using FAISS retrieval + LLMLingua compression.

- **Problem:** Loading entire files wastes tokens on irrelevant content
- **Solution:** Semantic search + compression = 50-80% token savings
- **Setup:** `cd context-pipeline && bash setup.sh`

## Coming Soon

- **hardening-template/** — Security configuration checklist
- **audit-log/** — Structured audit trail for agent actions
- **trust-zones/** — Input validation by source trust tier

---

Part of [Agent Guard](https://agentguard.co)
