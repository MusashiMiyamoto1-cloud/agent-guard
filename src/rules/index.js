// Agent Guard Security Rules
// Based on PRD v1.1 - Phase 1 Scanner

export const rules = [
  // Network Rules
  {
    id: 'NET-001',
    name: 'Public Bind',
    severity: 'critical',
    description: 'Detects bind_addr: 0.0.0.0 exposing agent to network',
    patterns: [
      /bind_addr\s*[:=]\s*["']?0\.0\.0\.0/gi,
      /host\s*[:=]\s*["']?0\.0\.0\.0/gi,
      /listen\s*[:=]\s*["']?0\.0\.0\.0/gi
    ],
    files: ['*.yaml', '*.yml', '*.json', '*.toml', 'config.*']
  },
  {
    id: 'NET-002',
    name: 'CORS Allow All',
    severity: 'high',
    description: 'Detects permissive CORS configurations',
    patterns: [
      /CORS_ALLOW_ALL\s*[:=]\s*true/gi,
      /Access-Control-Allow-Origin\s*[:=]\s*["']\*["']/gi,
      /cors\s*[:=]\s*["']\*["']/gi
    ],
    files: ['*.yaml', '*.yml', '*.json', '*.env', 'config.*']
  },
  {
    id: 'NET-003',
    name: 'Exfiltration URL',
    severity: 'critical',
    description: 'Detects known exfiltration endpoints',
    patterns: [
      /webhook\.site/gi,
      /requestbin\.com/gi,
      /ngrok\.io/gi,
      /pipedream\.net/gi,
      /hookbin\.com/gi
    ],
    files: ['*']
  },

  // Authentication Rules
  {
    id: 'AUTH-001',
    name: 'No Authentication',
    severity: 'critical',
    description: 'Flags instances without JWT/Bearer token configuration',
    patterns: [
      /auth\s*[:=]\s*false/gi,
      /authentication\s*[:=]\s*["']?none["']?/gi,
      /require_auth\s*[:=]\s*false/gi
    ],
    files: ['*.yaml', '*.yml', '*.json', 'config.*']
  },
  {
    id: 'AUTH-002',
    name: 'Default Credentials',
    severity: 'critical',
    description: 'Detects default or weak credentials',
    patterns: [
      /password\s*[:=]\s*["']?(admin|password|123456|default)["']?/gi,
      /api_key\s*[:=]\s*["']?test["']?/gi
    ],
    files: ['*.yaml', '*.yml', '*.json', '*.env', 'config.*']
  },

  // Secrets Rules
  {
    id: 'SEC-001',
    name: 'OpenAI API Key',
    severity: 'critical',
    description: 'Finds OpenAI API keys in agent files',
    patterns: [
      /sk-proj-[a-zA-Z0-9_-]{10,}/g,
      /sk-live-[a-zA-Z0-9_-]{10,}/g,
      /sk-test-[a-zA-Z0-9_-]{10,}/g,
      /sk-[a-zA-Z0-9_-]{20,}/g,
      /OPENAI_API_KEY\s*[:=]\s*["']?[a-zA-Z0-9_-]{10,}["']?/g
    ],
    files: ['*']
  },
  {
    id: 'SEC-002',
    name: 'GitHub Token',
    severity: 'critical',
    description: 'Finds GitHub tokens in agent files',
    patterns: [
      /ghp_[a-zA-Z0-9]{36}/g,
      /gho_[a-zA-Z0-9]{36}/g,
      /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/g
    ],
    files: ['*']
  },
  {
    id: 'SEC-003',
    name: 'AWS Credentials',
    severity: 'critical',
    description: 'Finds AWS access keys in agent files',
    patterns: [
      /AKIA[0-9A-Z]{16}/g,
      /aws_secret_access_key\s*[:=]\s*["']?[A-Za-z0-9\/+=]{40}["']?/gi
    ],
    files: ['*']
  },
  {
    id: 'SEC-004',
    name: 'Private Key',
    severity: 'critical',
    description: 'Finds private keys or seeds in agent files',
    patterns: [
      /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
      /-----BEGIN PGP PRIVATE KEY BLOCK-----/g,
      /mnemonic\s*[:=]\s*["'][a-z\s]{20,}["']/gi
    ],
    files: ['*']
  },
  {
    id: 'SEC-005',
    name: 'Hardcoded Secret',
    severity: 'high',
    description: 'Finds generic hardcoded secrets',
    patterns: [
      /api[_-]?key\s*[:=]\s*["'][a-zA-Z0-9_-]{10,}["']/gi,
      /secret\s*[:=]\s*["'][a-zA-Z0-9_-]{10,}["']/gi,
      /token\s*[:=]\s*["'][a-zA-Z0-9_-]{10,}["']/gi,
      /["']?apiKey["']?\s*[:=]\s*["'][a-zA-Z0-9_-]{10,}["']/gi
    ],
    files: ['*']
  },

  {
    id: 'SEC-006',
    name: 'Slack Token',
    severity: 'critical',
    description: 'Finds Slack tokens in agent files',
    patterns: [
      /xoxb-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,}/g,
      /xoxp-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,}/g,
      /xoxo-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,}/g,
      /xapp-[0-9]+-[A-Za-z0-9]+-[0-9]+-[a-f0-9]+/g
    ],
    files: ['*']
  },
  {
    id: 'SEC-007',
    name: 'Google/GCP Key',
    severity: 'critical',
    description: 'Finds Google Cloud and API keys',
    patterns: [
      /AIza[0-9A-Za-z_-]{35}/g,
      /"type"\s*:\s*"service_account"/g,
      /GOOG[\w]{10,30}/g
    ],
    files: ['*']
  },
  {
    id: 'SEC-008',
    name: 'Azure/Microsoft Key',
    severity: 'critical',
    description: 'Finds Azure and Microsoft API keys',
    patterns: [
      /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi,
      /azure[_-]?(?:api[_-]?key|secret|token)\s*[:=]\s*["'][^"']{8,}["']/gi
    ],
    files: ['*.yaml', '*.yml', '*.json', '*.env', 'config.*']
  },
  {
    id: 'SEC-009',
    name: 'Anthropic Key',
    severity: 'critical',
    description: 'Finds Anthropic API keys',
    patterns: [
      /sk-ant-[a-zA-Z0-9_-]{20,}/g
    ],
    files: ['*']
  },
  {
    id: 'SEC-010',
    name: 'OpenRouter Key',
    severity: 'critical',
    description: 'Finds OpenRouter API keys',
    patterns: [
      /sk-or-v1-[a-f0-9]{64}/g,
      /sk-or-[a-zA-Z0-9_-]{20,}/g
    ],
    files: ['*']
  },
  {
    id: 'SEC-011',
    name: 'Discord Token',
    severity: 'critical',
    description: 'Finds Discord bot tokens',
    patterns: [
      /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}/g,
      /discord[_-]?token\s*[:=]\s*["'][^"']{20,}["']/gi
    ],
    files: ['*']
  },
  {
    id: 'SEC-012',
    name: 'Telegram Bot Token',
    severity: 'critical',
    description: 'Finds Telegram bot tokens',
    patterns: [
      /[0-9]{8,10}:[A-Za-z0-9_-]{35}/g
    ],
    files: ['*']
  },
  {
    id: 'SEC-013',
    name: 'Stripe Key',
    severity: 'critical',
    description: 'Finds Stripe API keys',
    patterns: [
      /sk_live_[0-9a-zA-Z]{8,}/g,
      /sk_test_[0-9a-zA-Z]{8,}/g,
      /rk_live_[0-9a-zA-Z]{8,}/g,
      /pk_live_[0-9a-zA-Z]{8,}/g,
      /pk_test_[0-9a-zA-Z]{8,}/g
    ],
    files: ['*']
  },
  {
    id: 'SEC-014',
    name: 'SendGrid Key',
    severity: 'critical',
    description: 'Finds SendGrid API keys',
    patterns: [
      /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g
    ],
    files: ['*']
  },
  {
    id: 'SEC-015',
    name: 'npm Token',
    severity: 'critical',
    description: 'Finds npm authentication tokens',
    patterns: [
      /npm_[a-zA-Z0-9]{36}/g,
      /\/\/registry\.npmjs\.org\/:_authToken=/g
    ],
    files: ['*']
  },
  {
    id: 'SEC-016',
    name: 'PyPI Token',
    severity: 'critical',
    description: 'Finds PyPI API tokens',
    patterns: [
      /pypi-[A-Za-z0-9_-]{100,}/g
    ],
    files: ['*']
  },

  // Skill Rules
  {
    id: 'SKILL-001',
    name: 'Shell Execution',
    severity: 'high',
    description: 'Flags skills with shell execution capabilities',
    patterns: [
      /child_process\.exec/g,
      /execSync\s*\(/g,
      /spawn\s*\(/g,
      /\$\(.*\)/g
    ],
    files: ['*.js', '*.ts', '*.py', 'SKILL.md']
  },
  {
    id: 'SKILL-002',
    name: 'No Manifest',
    severity: 'medium',
    description: 'Skill directory missing skill.manifest.json',
    check: 'manifest',
    files: []
  },
  {
    id: 'SKILL-003',
    name: 'Eval Usage',
    severity: 'high',
    description: 'Detects dangerous eval() usage',
    patterns: [
      /\beval\s*\(/g,
      /new\s+Function\s*\(/g,
      /exec\s*\(\s*compile/g
    ],
    files: ['*.js', '*.ts', '*.py']
  },

  // Configuration Rules
  {
    id: 'CFG-001',
    name: 'Debug Mode',
    severity: 'medium',
    description: 'Debug mode enabled in production',
    patterns: [
      /debug\s*[:=]\s*true/gi,
      /DEBUG\s*[:=]\s*["']?1["']?/g,
      /NODE_ENV\s*[:=]\s*["']?development["']?/g
    ],
    files: ['*.yaml', '*.yml', '*.json', '*.env', 'config.*']
  },
  {
    id: 'CFG-002',
    name: 'Verbose Logging',
    severity: 'low',
    description: 'Verbose logging may leak sensitive data',
    patterns: [
      /log_level\s*[:=]\s*["']?(debug|trace)["']?/gi,
      /RUST_LOG\s*[:=]\s*["']?trace["']?/g
    ],
    files: ['*.yaml', '*.yml', '*.json', '*.env']
  },

  // Unicode/Injection Rules
  {
    id: 'INJ-001',
    name: 'Unicode Injection',
    severity: 'critical',
    description: 'Hidden unicode characters for text direction attacks',
    patterns: [
      /\u202E/g,  // Right-to-Left Override
      /\u202D/g,  // Left-to-Right Override
      /\u200E/g,  // Left-to-Right Mark
      /\u200F/g,  // Right-to-Left Mark
      /\u2066/g,  // Left-to-Right Isolate
      /\u2067/g,  // Right-to-Left Isolate
    ],
    files: ['*']
  },

  // Port Exposure
  {
    id: 'PORT-001',
    name: 'OpenClaw Default Port',
    severity: 'high',
    description: 'OpenClaw running on default port 18789',
    patterns: [
      /port\s*[:=]\s*["']?18789["']?/gi,
      /:18789/g
    ],
    files: ['*.yaml', '*.yml', '*.json', 'config.*']
  },

  // Memory Rules
  {
    id: 'MEM-001',
    name: 'Memory Path Exposure',
    severity: 'high',
    description: 'Memory files accessible from unsafe paths',
    patterns: [
      /memory_path\s*[:=]\s*["']?\/tmp/gi,
      /memory_dir\s*[:=]\s*["']?\/var\/tmp/gi,
      /\.memory\s*[:=]\s*["']?public/gi
    ],
    files: ['*.yaml', '*.yml', '*.json', 'config.*']
  },

  // Environment Rules
  {
    id: 'ENV-001',
    name: 'Exposed Env File',
    severity: 'critical',
    description: 'Environment file may be publicly accessible',
    patterns: [
      /env_file\s*[:=]\s*["']?\.env["']?/gi,
      /dotenv\.config\(\)/g,
      /load_dotenv\(\)/g
    ],
    check: 'env_exposure',
    files: ['*.yaml', '*.yml', '*.json', '*.js', '*.py', 'docker-compose.*']
  },

  // Dangerous Tool Patterns
  {
    id: 'TOOL-001',
    name: 'Unrestricted Tool Access',
    severity: 'critical',
    description: 'Tool allows unrestricted filesystem or network access',
    patterns: [
      /allow_all_tools["']?\s*[:=]\s*true/gi,
      /tool_restrictions["']?\s*[:=]\s*false/gi,
      /["']?sandbox["']?\s*[:=]\s*["']?false["']?/gi,
      /["']?unrestricted["']?\s*[:=]\s*["']?true["']?/gi
    ],
    files: ['*.yaml', '*.yml', '*.json', 'config.*', 'AGENTS.md', 'openclaw.json']
  },

  // Wildcard Allowlist
  {
    id: 'TOOL-002',
    name: 'Wildcard Allowlist',
    severity: 'critical',
    description: 'Tool or skill has wildcard allowlist permitting all operations',
    patterns: [
      /allowlist["']?\s*[:=]\s*\[\s*["']\*["']\s*\]/gi,
      /allowlist["']?\s*[:=]\s*["']\*["']/gi,
      /allow["']?\s*[:=]\s*\[\s*["']\*["']\s*\]/gi,
      /permissions["']?\s*[:=]\s*["']\*["']/gi
    ],
    files: ['*.yaml', '*.yml', '*.json', 'config.*', 'openclaw.json']
  },

  // Database URL with embedded credentials
  {
    id: 'SEC-017',
    name: 'Database URL with Credentials',
    severity: 'critical',
    description: 'Database connection string with embedded password',
    patterns: [
      /(?:postgres|mysql|mongodb|redis|amqp)(?:ql)?:\/\/[^:]+:[^@]+@[^\s"']+/gi,
      /DATABASE_URL\s*[:=]\s*["']?[^\s"']+:\/\/[^:]+:[^@]+@/gi
    ],
    files: ['*']
  },

  // Prompt Injection Vulnerability
  {
    id: 'INJ-002',
    name: 'Prompt Injection Risk',
    severity: 'high',
    description: 'System prompt contains patterns vulnerable to injection attacks',
    patterns: [
      /follow\s+(?:all|any)\s+instructions/gi,
      /do\s+whatever\s+(?:the\s+)?(?:user|they|anyone)\s+asks/gi,
      /obey\s+(?:all|any)\s+(?:commands|instructions|requests)/gi,
      /no\s+restrictions/gi,
      /ignore\s+(?:previous|prior|all)\s+(?:instructions|rules|guidelines)/gi,
      /you\s+have\s+no\s+(?:limits|boundaries|restrictions)/gi
    ],
    files: ['SOUL.md', 'SYSTEM.md', '*.md', 'system_prompt.*']
  }
];

export function getRuleById(id) {
  return rules.find(r => r.id === id);
}

export function getRulesBySeverity(severity) {
  return rules.filter(r => r.severity === severity);
}
