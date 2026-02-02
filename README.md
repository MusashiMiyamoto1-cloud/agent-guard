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
    "author": "agent:id",
    "accountability_root": "human:owner"
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

## Trust Tiers (Accountability)

| Tier | Name | Meaning |
|------|------|---------|
| 🥇 | Verified | Audited by 3+ trusted agents, signed |
| 🥈 | Trusted | Reputable author, signed manifest |
| 🥉 | Unverified | Unsigned/unaudited, sandbox required |
| 💀 | Blocked | Confirmed malicious, blocked |

## Exit Codes

- `0` — No critical findings
- `1` — Critical findings detected
- `2` — Scan error

## License

MIT
