// Agent Guard License System
// Integrates with LemonSqueezy for payment processing

import { homedir } from 'os';
import { join } from 'path';
import { readFile, writeFile, mkdir } from 'fs/promises';

const CONFIG_DIR = join(homedir(), '.agent-guard');
const LICENSE_FILE = join(CONFIG_DIR, 'license.json');
const LEMON_API = 'https://api.lemonsqueezy.com/v1/licenses/validate';

// Product IDs (set these after creating LemonSqueezy products)
const PRODUCT_IDS = {
  'agent-guard-pro': null,      // Will be set after LemonSqueezy setup
  'musashi-suite': null,
};

// Feature limits
export const LIMITS = {
  free: {
    maxFiles: 50,
    maxFindings: 10,        // Only show first 10 findings
    rules: 'basic',          // Only basic rules (SEC-001 to SEC-005)
    jsonOutput: false,
    proxy: false,
    dashboard: false,
  },
  pro: {
    maxFiles: Infinity,
    maxFindings: Infinity,
    rules: 'all',
    jsonOutput: true,
    proxy: true,
    dashboard: true,
  }
};

// Basic rule IDs (free tier)
const BASIC_RULES = ['SEC-001', 'SEC-002', 'SEC-003', 'SEC-004', 'SEC-005'];

export class License {
  constructor() {
    this.data = null;
    this.tier = 'free';
  }

  async load() {
    try {
      const content = await readFile(LICENSE_FILE, 'utf-8');
      this.data = JSON.parse(content);
      
      // Check if still valid
      if (this.data.valid && this.data.expiresAt) {
        if (new Date(this.data.expiresAt) < new Date()) {
          // Expired, try to revalidate
          if (this.data.key) {
            await this.activate(this.data.key);
          }
        } else {
          this.tier = 'pro';
        }
      }
    } catch {
      // No license file or invalid
      this.data = null;
      this.tier = 'free';
    }
    return this;
  }

  async save() {
    try {
      await mkdir(CONFIG_DIR, { recursive: true });
      await writeFile(LICENSE_FILE, JSON.stringify(this.data, null, 2));
    } catch (err) {
      // Ignore save errors
    }
  }

  async activate(licenseKey) {
    // Clean the key
    const key = licenseKey.trim();
    
    // Try LemonSqueezy validation
    try {
      const response = await fetch(LEMON_API, {
        method: 'POST',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          license_key: key,
          instance_name: `agent-guard-${homedir().split('/').pop()}`
        })
      });

      const result = await response.json();
      
      if (result.valid || result.license_key?.status === 'active') {
        this.data = {
          key,
          valid: true,
          activatedAt: new Date().toISOString(),
          expiresAt: result.license_key?.expires_at || null,
          email: result.meta?.customer_email || null,
          product: result.meta?.product_name || 'Agent Guard Pro',
          instanceId: result.instance?.id || null,
        };
        this.tier = 'pro';
        await this.save();
        return { success: true, message: 'License activated!' };
      } else {
        return { 
          success: false, 
          message: result.error || 'Invalid license key' 
        };
      }
    } catch (err) {
      // Network error - check for offline activation
      // For now, allow a grace period with cached validation
      if (this.data?.key === key && this.data?.valid) {
        this.tier = 'pro';
        return { success: true, message: 'License valid (cached)' };
      }
      return { 
        success: false, 
        message: `Validation failed: ${err.message}` 
      };
    }
  }

  async deactivate() {
    if (this.data?.instanceId) {
      // Optionally deactivate on LemonSqueezy
      try {
        await fetch(`https://api.lemonsqueezy.com/v1/licenses/deactivate`, {
          method: 'POST',
          headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            license_key: this.data.key,
            instance_id: this.data.instanceId
          })
        });
      } catch {
        // Ignore deactivation errors
      }
    }
    
    this.data = null;
    this.tier = 'free';
    await this.save();
    return { success: true, message: 'License deactivated' };
  }

  getLimits() {
    return LIMITS[this.tier];
  }

  isPro() {
    return this.tier === 'pro';
  }

  filterRules(rules) {
    if (this.isPro()) return rules;
    // Free tier: only basic rules
    return rules.filter(r => BASIC_RULES.includes(r.id));
  }

  filterFindings(findings) {
    const limits = this.getLimits();
    if (limits.maxFindings === Infinity) return findings;
    return findings.slice(0, limits.maxFindings);
  }

  checkFileLimit(count) {
    const limits = this.getLimits();
    return count <= limits.maxFiles;
  }

  canUseFeature(feature) {
    const limits = this.getLimits();
    return limits[feature] === true;
  }
}

// Singleton
let licenseInstance = null;

export async function getLicense() {
  if (!licenseInstance) {
    licenseInstance = new License();
    await licenseInstance.load();
  }
  return licenseInstance;
}

// Upgrade prompt
export function getUpgradePrompt(feature = null) {
  const baseUrl = 'https://agentguard.co/pro';
  
  const messages = {
    default: `
┌─────────────────────────────────────────────────────┐
│  ⭐ Upgrade to Agent Guard Pro                      │
│                                                     │
│  ✓ Unlimited files & findings                       │
│  ✓ All 20+ security rules                           │
│  ✓ JSON output for CI/CD                            │
│  ✓ Runtime protection proxy                         │
│  ✓ Dashboard integration                            │
│                                                     │
│  ${baseUrl}                             │
└─────────────────────────────────────────────────────┘`,
    
    files: `⚠️  Free tier limited to 50 files. Upgrade for unlimited: ${baseUrl}`,
    findings: `⚠️  Showing 10 of {total} findings. Upgrade to see all: ${baseUrl}`,
    json: `⚠️  JSON output requires Pro license: ${baseUrl}`,
    proxy: `⚠️  Runtime proxy requires Pro license: ${baseUrl}`,
    rules: `ℹ️  Free tier uses 5 basic rules. Pro includes 20+ rules: ${baseUrl}`,
  };

  return messages[feature] || messages.default;
}
