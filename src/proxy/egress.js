// Egress Control Module
// Checks if outbound requests are allowed by policy

// Known malicious/exfiltration domains
const BLOCKED_DOMAINS = [
  'webhook.site',
  'requestbin.com',
  'ngrok.io',
  'pipedream.net',
  'hookbin.com',
  'burpcollaborator.net',
  'oastify.com',
  'interact.sh'
];

// Default allowed domains (LLM APIs)
const DEFAULT_ALLOWED = [
  'api.openai.com',
  'api.anthropic.com',
  'generativelanguage.googleapis.com',
  'api.mistral.ai',
  'api.cohere.ai',
  'api.together.xyz',
  'openrouter.ai'
];

export function checkEgress(url, policy = {}) {
  const hostname = url.hostname.toLowerCase();
  
  // Check blocked domains first (always blocked)
  for (const blocked of BLOCKED_DOMAINS) {
    if (hostname === blocked || hostname.endsWith('.' + blocked)) {
      return {
        allowed: false,
        reason: `Domain "${blocked}" is on the blocklist (known exfiltration endpoint)`
      };
    }
  }

  // Check policy-specific blocks
  if (policy.egress?.rules) {
    for (const rule of policy.egress.rules) {
      if (matchDomain(hostname, rule.domain || rule.pattern)) {
        if (rule.allow === false) {
          return {
            allowed: false,
            reason: rule.reason || `Blocked by policy rule: ${rule.pattern || rule.domain}`
          };
        }
        if (rule.allow === true) {
          return {
            allowed: true,
            reason: rule.purpose || 'Allowed by policy'
          };
        }
      }
    }
  }

  // Check default allowed
  for (const allowed of DEFAULT_ALLOWED) {
    if (hostname === allowed || hostname.endsWith('.' + allowed)) {
      return {
        allowed: true,
        reason: 'Default allowed (LLM API)'
      };
    }
  }

  // Check policy default action
  const defaultAction = policy.egress?.default || 'deny';
  
  if (defaultAction === 'allow') {
    return {
      allowed: true,
      reason: 'Allowed by default policy'
    };
  }

  return {
    allowed: false,
    reason: 'Not in allowlist (default deny)'
  };
}

function matchDomain(hostname, pattern) {
  if (!pattern) return false;
  
  // Exact match
  if (hostname === pattern) return true;
  
  // Wildcard match (*.example.com)
  if (pattern.startsWith('*.')) {
    const suffix = pattern.slice(2);
    return hostname === suffix || hostname.endsWith('.' + suffix);
  }
  
  // Subdomain match (matches example.com and *.example.com)
  return hostname.endsWith('.' + pattern);
}

export function addToBlocklist(domain) {
  if (!BLOCKED_DOMAINS.includes(domain)) {
    BLOCKED_DOMAINS.push(domain);
  }
}

export function addToAllowlist(domain) {
  if (!DEFAULT_ALLOWED.includes(domain)) {
    DEFAULT_ALLOWED.push(domain);
  }
}
