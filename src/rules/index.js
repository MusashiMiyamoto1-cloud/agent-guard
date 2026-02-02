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
      /sk-[a-zA-Z0-9]{20,}/g,
      /sk-proj-[a-zA-Z0-9]{20,}/g
    ],
    files: ['*.md', '*.yaml', '*.yml', '*.json', '*.txt', 'SOUL.md', 'HEARTBEAT.md']
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
    files: ['*.md', '*.yaml', '*.yml', '*.json', '*.txt', '.env']
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
      /api[_-]?key\s*[:=]\s*["'][a-zA-Z0-9]{16,}["']/gi,
      /secret\s*[:=]\s*["'][a-zA-Z0-9]{16,}["']/gi,
      /token\s*[:=]\s*["'][a-zA-Z0-9]{16,}["']/gi
    ],
    files: ['*.md', '*.yaml', '*.yml', '*.json', 'SOUL.md']
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
      /allow_all_tools\s*[:=]\s*true/gi,
      /tool_restrictions\s*[:=]\s*false/gi,
      /sandbox\s*[:=]\s*false/gi,
      /unrestricted\s*[:=]\s*true/gi
    ],
    files: ['*.yaml', '*.yml', '*.json', 'config.*', 'AGENTS.md']
  }
];

export function getRuleById(id) {
  return rules.find(r => r.id === id);
}

export function getRulesBySeverity(severity) {
  return rules.filter(r => r.severity === severity);
}
