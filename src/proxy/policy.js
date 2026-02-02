// Policy Management
// Load and validate security policies

import { readFileSync, existsSync } from 'fs';
import { parse as parseYaml } from 'yaml';
import { join } from 'path';

const POLICY_FILES = [
  'agent-guard-policy.yaml',
  'agent-guard-policy.yml',
  '.agent-guard.yaml',
  '.agent-guard.yml'
];

const DEFAULT_POLICY = {
  version: '1.0',
  
  egress: {
    default: 'deny',
    rules: []
  },
  
  filesystem: {
    deny: [
      '~/.ssh/*',
      '~/.aws/*',
      '~/.env',
      '~/.config/gcloud/*',
      '/etc/shadow',
      '/etc/passwd'
    ],
    audit: []
  },
  
  intent: {
    enabled: false,
    model: 'phi-4',
    enforcement: 'audit'
  },
  
  act: {
    enabled: false,
    store: './act-receipts/',
    sign: false
  },
  
  enforcement: {
    mode: 'audit',
    on_violation: {
      log: true,
      alert: false,
      block: false
    }
  }
};

export function loadPolicy(customPath = null) {
  // Try custom path first
  if (customPath && existsSync(customPath)) {
    return loadPolicyFile(customPath);
  }

  // Search for policy file
  const cwd = process.cwd();
  
  for (const filename of POLICY_FILES) {
    const filepath = join(cwd, filename);
    if (existsSync(filepath)) {
      return loadPolicyFile(filepath);
    }
  }

  // Return default policy
  console.log('ℹ️  No policy file found, using default (deny-by-default)');
  return DEFAULT_POLICY;
}

function loadPolicyFile(filepath) {
  try {
    const content = readFileSync(filepath, 'utf-8');
    const policy = parseYaml(content);
    
    // Merge with defaults
    const merged = mergeDeep(DEFAULT_POLICY, policy);
    
    console.log(`✓ Loaded policy from ${filepath}`);
    return merged;
  } catch (err) {
    console.error(`⚠️  Error loading policy: ${err.message}`);
    return DEFAULT_POLICY;
  }
}

function mergeDeep(target, source) {
  const output = { ...target };
  
  for (const key in source) {
    if (source[key] instanceof Object && key in target) {
      output[key] = mergeDeep(target[key], source[key]);
    } else {
      output[key] = source[key];
    }
  }
  
  return output;
}

export function validatePolicy(policy) {
  const errors = [];
  
  // Check version
  if (!policy.version) {
    errors.push('Missing policy version');
  }
  
  // Check egress
  if (policy.egress) {
    if (!['allow', 'deny'].includes(policy.egress.default)) {
      errors.push('egress.default must be "allow" or "deny"');
    }
  }
  
  // Check enforcement
  if (policy.enforcement) {
    if (!['audit', 'soft_enforce', 'enforce'].includes(policy.enforcement.mode)) {
      errors.push('enforcement.mode must be "audit", "soft_enforce", or "enforce"');
    }
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
}

export function generatePolicy(scanResults) {
  // Generate policy from Phase 1 scan results
  const policy = { ...DEFAULT_POLICY };
  
  // Add egress rules from skill manifests
  if (scanResults.manifests) {
    for (const manifest of scanResults.manifests) {
      if (manifest.permissions?.network?.egress) {
        for (const rule of manifest.permissions.network.egress) {
          policy.egress.rules.push({
            domain: rule.domain,
            allow: true,
            purpose: rule.purpose,
            source: manifest.metadata.name
          });
        }
      }
    }
  }
  
  return policy;
}
