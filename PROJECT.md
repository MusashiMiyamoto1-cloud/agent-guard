# Agent Guard — Project Plan

**Status:** Phase 1 MVP Complete — Ready for npm publish
**Last Updated:** 2026-02-02 23:00 IST

---

## Phase 1: The Scanner (Week 1)

**Goal:** 5,000+ npm downloads

### Tasks

| Task | Status | Acceptance Criteria |
|------|--------|---------------------|
| Core scanner | ✅ Done | Scans directory, finds patterns |
| 17 security rules | ✅ Done | NET, AUTH, SEC, SKILL, CFG, INJ, PORT |
| CLI interface | ✅ Done | `npx agent-guard scan .` works |
| Scoring system | ✅ Done | 0-100 score, A-F grade |
| Secret redaction | ✅ Done | Keys shown as `sk-****REDACTED***` |
| JSON output | ✅ Done | `--json` flag works |
| skill.manifest.json | ✅ Done | Schema defined, detection works |
| Complete 20 rules | ✅ Done | 20 rules implemented |
| npm publish ready | ✅ Done | package.json complete, bin works |
| molt-guard.sh | ✅ Done | Bash triage script |
| Landing page copy | ✅ Done | docs/landing-page.md |
| 404 Media case study | ✅ Done | docs/404-media-case-study.md |
| Twitter launch thread | ✅ Done | docs/twitter-launch-thread.md |
| Moltbook bot concept | ✅ Done | docs/moltbook-bot-concept.md |
| YARA ruleset | ✅ Done | rules/agent-security.yar |
| npm publish docs | ✅ Done | docs/npm-publish.md |

### Rules Checklist (20 total)

**Implemented (17):**
- [x] NET-001: Public Bind
- [x] NET-002: CORS Allow All
- [x] NET-003: Exfiltration URL
- [x] AUTH-001: No Authentication
- [x] AUTH-002: Default Credentials
- [x] SEC-001: OpenAI API Key
- [x] SEC-002: GitHub Token
- [x] SEC-003: AWS Credentials
- [x] SEC-004: Private Key
- [x] SEC-005: Hardcoded Secret
- [x] SKILL-001: Shell Execution
- [x] SKILL-002: No Manifest
- [x] SKILL-003: Eval Usage
- [x] CFG-001: Debug Mode
- [x] CFG-002: Verbose Logging
- [x] INJ-001: Unicode Injection
- [x] PORT-001: Default Port

**Implemented (20):**
- [x] MEM-001: Memory path exposure
- [x] ENV-001: Exposed .env file
- [x] TOOL-001: Unrestricted tool access

---

## Phase 2: Runtime Protection (Month 1)

**Goal:** Paid Pro conversions ($29/mo)

**Design:** docs/phase2-runtime-design.md

### Architecture Decision: Proxy Mode (MVP)

Insert as HTTP proxy between agent and LLM API. No agent modification needed.

### Tasks

| Task | Status | Acceptance Criteria |
|------|--------|---------------------|
| Architecture design | ✅ Done | docs/phase2-runtime-design.md |
| HTTP proxy server | ✅ Done | src/proxy/index.js |
| Egress control | ✅ Done | src/proxy/egress.js |
| Policy loader | ✅ Done | src/proxy/policy.js |
| Event logger | ✅ Done | src/proxy/logger.js |
| CLI proxy command | ✅ Done | `agent-guard proxy [port]` |
| Credential blackhole | 🔲 Todo | Intercept ~/.ssh, ~/.aws reads |
| Intent verification | 🔲 Todo | Phi-4 validates tool calls |
| ACT receipt generation | 🔲 Todo | Signed action receipts |

---

## Phase 3: ATAP Infrastructure (Month 3+)

**Goal:** Enterprise standardization

### Tasks

| Task | Status | Acceptance Criteria |
|------|--------|---------------------|
| AID (Agent Identity) | 🔲 Todo | did:atap → ERC-8004 mapping |
| State attestation | 🔲 Todo | Merkle tree of agent state |
| ACT signing | 🔲 Todo | Crypto proof of intent |
| YARA ruleset | 🔲 Todo | Community malware signatures |

---

## Business

### Pricing Tiers
- Free: CLI Scanner + Hardening Checklist
- Pro ($29/mo): Runtime Interceptor + 30-day Intent Logs
- Team ($149/mo): Fleet Dashboard + Policy Sync
- Enterprise: eBPF + SOC2 Reporting

### GTM
1. Launch scanner with 404 Media framing
2. Security Score bot on Moltbook (viral loop)
3. Email capture from scan reports
4. Convert power users to Pro

---

## Current Sprint

**Focus:** Phase 1 Complete ✅

1. ✅ Core scanner
2. ✅ 20 rules (all implemented)
3. ✅ npm publish prep
4. ✅ molt-guard.sh
5. ✅ Landing page content
6. ✅ 404 Media case study
7. ✅ Twitter launch thread

**Next:** 
- Publish to npm
- Register agentguard.co domain
- Deploy landing page
- Create Moltbook security bot

---

## Blockers

*None currently*

---

## Notes

- Accountability roots in manifests trace to human operators
- Scanner ignores agent-guard/ dir to avoid self-scan false positives
- Test fixtures in test/fixtures/vulnerable-agent/
