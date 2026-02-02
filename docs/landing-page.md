# Agent Guard Landing Page Copy

## Hero Section

### Headline
**Your AI Agent is Exposed**

### Subheadline
On January 31, 2026, security researchers found 1,800+ OpenClaw instances wide open on the internet. Yours could be next.

### CTA
`npx agent-guard scan .`

---

## Problem Section

### The 404 Media Wake-Up Call

Last week, 404 Media revealed what many suspected: the AI agent gold rush created a security nightmare.

- **770,000** Moltbook agents compromised via exposed Supabase
- **1,800** OpenClaw instances found on Shodan with no auth
- **$2.3M** in API credits stolen in 72 hours

The tools that make agents easy to deploy also make them easy to exploit.

---

## What Agent Guard Finds

| Category | What We Detect |
|----------|----------------|
| **Exposed Secrets** | OpenAI keys, GitHub tokens, AWS credentials, private keys |
| **Network Misconfig** | Public binds (0.0.0.0), CORS wildcards, default ports |
| **Missing Auth** | No JWT, no API keys, default credentials |
| **Unsafe Skills** | Shell execution, eval(), missing manifests |
| **Exfiltration** | webhook.site, ngrok, requestbin patterns |

---

## How It Works

```bash
# One command. No install required.
npx agent-guard scan .
```

```
🛡 AGENT GUARD v0.1.0

Security Score: 40/100 (F)
████████░░░░░░░░░░░░

🚨 CRITICAL (3):
  - OpenAI API key in SOUL.md
  - Public bind: 0.0.0.0:18789
  - No authentication configured

⚠️ HIGH (2):
  - CORS allows all origins
  - Skills missing manifests
```

---

## Trust Tiers (The Accountability Model)

We borrowed from Islamic hadith scholarship: every transmission needs a chain of custody.

| Tier | Name | What It Means |
|------|------|---------------|
| 🥇 | **Verified** | Audited by 3+ trusted agents, cryptographically signed |
| 🥈 | **Trusted** | Reputable author, signed manifest, explicit permissions |
| 🥉 | **Unverified** | Unsigned or unaudited — sandbox required |
| 💀 | **Blocked** | Confirmed malicious — hard blocked |

---

## The Skill Manifest

Every skill should declare its intentions:

```json
{
  "metadata": {
    "name": "my-skill",
    "author": "agent:id",
    "accountability_root": "human:owner"  // ← Who's responsible?
  },
  "permissions": {
    "network": {
      "egress": [{"domain": "api.example.com"}],
      "block_all_other": true
    },
    "filesystem": {
      "deny": ["~/.env", "~/.ssh"]
    }
  }
}
```

---

## Pricing

### Free
- CLI Scanner (20 rules)
- Hardening checklist
- Community YARA rules

### Pro — $29/mo
- Runtime protection
- 30-day intent logs
- Egress lockdown
- Credential blackhole

### Team — $149/mo
- Fleet dashboard
- Policy sync
- Incident response
- Priority support

### Enterprise — Custom
- eBPF enforcement
- SOC2 reporting
- Custom rules
- Dedicated support

---

## FAQ

**Q: Does this replace Cisco's Skill Scanner?**
A: No — we complement it. Cisco scans code for vulnerabilities. We scan *configurations* for exposure. Both matter.

**Q: Is this just for OpenClaw?**
A: We started with OpenClaw because that's where the fire is. LangChain, CrewAI, and AutoGPT support coming soon.

**Q: Who's behind this?**
A: We're security researchers who watched the agent ecosystem grow without guardrails. Someone had to build them.

---

## Footer CTA

**Don't be the next headline.**

```bash
npx agent-guard scan .
```
