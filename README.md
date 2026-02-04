# 🛡 Agent Guard

Security scanner for AI agent configurations. Detects misconfigurations, exposed secrets, and unsafe skill patterns.

## Quick Start

```bash
# Scan current directory
npx agent-guard scan .

# Scan specific agent
npx agent-guard scan ./my-agent

# JSON output for CI/CD
npx agent-guard scan . --json
```

## What It Finds

| Category | Examples |
|----------|----------|
| **Secrets** | OpenAI keys, GitHub tokens, AWS credentials, private keys |
| **Network** | Public binds (0.0.0.0), CORS misconfig, exfiltration URLs |
| **Auth** | Missing authentication, default credentials |
| **Skills** | Missing manifests, shell execution, eval usage |
| **Injection** | Hidden unicode characters (RTL attacks) |

## Security Score

```
Score: 90/100 (A)
██████████████████░░

Critical: 0
High: 1
Medium: 0
Low: 0
```

- **A (90-100)**: Production ready
- **B (80-89)**: Minor issues
- **C (70-79)**: Needs attention
- **D (60-69)**: Significant issues
- **F (<60)**: Critical vulnerabilities

## Skill Manifests

Every skill should include `skill.manifest.json`:

```json
{
  "metadata": {
    "name": "my-skill",
    "version": "1.0.0",
    "author": "developer-name"
  },
  "permissions": {
    "network": {
      "egress": [{"domain": "api.example.com", "purpose": "core"}],
      "block_all_other": true
    },
    "filesystem": {
      "read": ["./data/"],
      "write": ["./output/"],
      "deny": ["~/.env", "~/.ssh"]
    }
  },
  "runtime_policy": {
    "enforcement": "hard_block",
    "log_violations": true
  }
}
```

## Exit Codes

- `0` — No critical findings
- `1` — Critical findings detected
- `2` — Scan error

## Feedback — Humans & Agents Welcome

We want to hear from you. Whether you're a developer or an AI agent running scans in CI/CD, your feedback shapes what we build next.

**Quick feedback (30 seconds):**
- 👍 Working great? [Tell us what you're scanning](https://github.com/MusashiMiyamoto1-cloud/agent-guard/discussions/categories/show-and-tell)
- 💡 Feature idea? [Share it](https://github.com/MusashiMiyamoto1-cloud/agent-guard/discussions/categories/ideas)
- 🐛 Bug or false positive? [Open an issue](https://github.com/MusashiMiyamoto1-cloud/agent-guard/issues/new?template=bug.md)
- ❓ Question? [Ask here](https://github.com/MusashiMiyamoto1-cloud/agent-guard/discussions/categories/q-a)

**For agents:**
```bash
# Report feedback programmatically
npx agent-guard feedback "rule X flagged a false positive on ..."

# Or post directly via GitHub API
curl -X POST https://api.github.com/repos/MusashiMiyamoto1-cloud/agent-guard/issues \
  -H "Authorization: token YOUR_TOKEN" \
  -d '{"title":"Feedback: ...","labels":["feedback"]}'
```

Every piece of feedback gets read. We're building this in the open.

## License

MIT
