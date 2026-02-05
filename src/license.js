// Agent Guard License System
// Keygen.sh integration for software licensing

import { homedir, hostname, platform, arch } from 'os';
import { join } from 'path';
import { readFile, writeFile, mkdir } from 'fs/promises';
import { createHash } from 'crypto';

const CONFIG_DIR = join(homedir(), '.agent-guard');
const LICENSE_FILE = join(CONFIG_DIR, 'license.json');

// Keygen account ID (set after creating Keygen account)
const KEYGEN_ACCOUNT = process.env.KEYGEN_ACCOUNT || 'YOUR_ACCOUNT_ID';
const KEYGEN_API = `https://api.keygen.sh/v1/accounts/${KEYGEN_ACCOUNT}`;

// Feature entitlements
const ENTITLEMENTS = {
  'all-rules': { name: 'All Security Rules', tier: 'pro' },
  'unlimited-files': { name: 'Unlimited Files', tier: 'pro' },
  'unlimited-findings': { name: 'Unlimited Findings', tier: 'pro' },
  'json-output': { name: 'JSON Output', tier: 'pro' },
  'runtime-proxy': { name: 'Runtime Proxy', tier: 'pro' },
  'dashboard': { name: 'Dashboard Integration', tier: 'team' },
  'priority-support': { name: 'Priority Support', tier: 'team' },
};

// Feature limits by tier
export const LIMITS = {
  free: {
    maxFiles: 50,
    maxFindings: 10,
    rules: 'basic',
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
    dashboard: false,
  },
  team: {
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

// Generate machine fingerprint for device-locked licenses
function getMachineFingerprint() {
  const data = `${hostname()}:${platform()}:${arch()}:${homedir()}`;
  return createHash('sha256').update(data).digest('hex').slice(0, 32);
}

export class License {
  constructor() {
    this.data = null;
    this.tier = 'free';
    this.entitlements = [];
    this.fingerprint = getMachineFingerprint();
  }

  async load() {
    try {
      const content = await readFile(LICENSE_FILE, 'utf-8');
      this.data = JSON.parse(content);
      
      // Check if still valid (cached validation)
      if (this.data.valid && this.data.expiresAt) {
        const expiry = new Date(this.data.expiresAt);
        if (expiry < new Date()) {
          // Expired, try to revalidate
          if (this.data.key) {
            await this.activate(this.data.key);
          }
        } else {
          this.tier = this.data.tier || 'pro';
          this.entitlements = this.data.entitlements || [];
        }
      }
      
      // Check if we should revalidate (every 24h)
      if (this.data.lastValidated) {
        const lastCheck = new Date(this.data.lastValidated);
        const hoursSince = (Date.now() - lastCheck.getTime()) / (1000 * 60 * 60);
        if (hoursSince > 24 && this.data.key) {
          // Background revalidation
          this.activate(this.data.key).catch(() => {});
        }
      }
    } catch {
      this.data = null;
      this.tier = 'free';
    }
    return this;
  }

  async save() {
    try {
      await mkdir(CONFIG_DIR, { recursive: true });
      await writeFile(LICENSE_FILE, JSON.stringify(this.data, null, 2));
    } catch {
      // Ignore save errors
    }
  }

  async activate(licenseKey) {
    const key = licenseKey.trim();
    
    try {
      // Step 1: Validate the license key
      const validateRes = await fetch(`${KEYGEN_API}/licenses/actions/validate-key`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify({
          meta: {
            key: key,
            scope: { fingerprint: this.fingerprint }
          }
        })
      });

      const validateData = await validateRes.json();
      
      if (validateData.errors) {
        return { 
          success: false, 
          message: validateData.errors[0]?.detail || 'Invalid license key' 
        };
      }

      const { valid, code, license } = validateData.meta || {};
      
      // Handle validation codes
      if (!valid) {
        const messages = {
          'FINGERPRINT_SCOPE_MISMATCH': 'License is activated on another machine. Deactivate first or upgrade to Team.',
          'NO_MACHINES': 'License needs activation. Activating now...',
          'NO_MACHINE': 'License needs activation. Activating now...',
          'EXPIRED': 'License has expired. Please renew.',
          'SUSPENDED': 'License has been suspended. Contact support.',
          'NOT_FOUND': 'Invalid license key.',
        };
        
        if (code === 'NO_MACHINES' || code === 'NO_MACHINE' || code === 'FINGERPRINT_SCOPE_MISMATCH') {
          // Try to activate this machine
          const activateResult = await this.activateMachine(key, validateData.data?.id);
          if (!activateResult.success) {
            return activateResult;
          }
        } else {
          return { 
            success: false, 
            message: messages[code] || `Validation failed: ${code}` 
          };
        }
      }

      // Extract license info
      const licenseData = validateData.data?.attributes || license?.attributes || {};
      const entitlements = validateData.included
        ?.filter(i => i.type === 'entitlements')
        ?.map(e => e.attributes?.code) || [];
      
      // Determine tier from entitlements or policy
      let tier = 'pro';
      if (entitlements.includes('dashboard') || entitlements.includes('priority-support')) {
        tier = 'team';
      }

      this.data = {
        key,
        valid: true,
        tier,
        entitlements,
        activatedAt: new Date().toISOString(),
        lastValidated: new Date().toISOString(),
        expiresAt: licenseData.expiry || null,
        email: licenseData.metadata?.email || null,
        name: licenseData.name || 'Agent Guard Pro',
        licenseId: validateData.data?.id,
        fingerprint: this.fingerprint,
      };
      
      this.tier = tier;
      this.entitlements = entitlements;
      await this.save();
      
      return { success: true, message: 'License activated!' };
      
    } catch (err) {
      // Network error - use cached validation if available
      if (this.data?.key === key && this.data?.valid) {
        this.tier = this.data.tier || 'pro';
        return { success: true, message: 'License valid (cached)' };
      }
      return { 
        success: false, 
        message: `Activation failed: ${err.message}` 
      };
    }
  }

  async activateMachine(licenseKey, licenseId) {
    try {
      const res = await fetch(`${KEYGEN_API}/machines`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'Authorization': `License ${licenseKey}`,
        },
        body: JSON.stringify({
          data: {
            type: 'machines',
            attributes: {
              fingerprint: this.fingerprint,
              name: `${hostname()} (${platform()})`,
              platform: platform(),
            },
            relationships: {
              license: {
                data: { type: 'licenses', id: licenseId }
              }
            }
          }
        })
      });

      const data = await res.json();
      
      if (data.errors) {
        const err = data.errors[0];
        if (err.code === 'MACHINE_LIMIT_EXCEEDED') {
          return { 
            success: false, 
            message: 'Machine limit reached. Deactivate another machine or upgrade.' 
          };
        }
        return { success: false, message: err.detail || 'Activation failed' };
      }
      
      return { success: true };
    } catch (err) {
      return { success: false, message: err.message };
    }
  }

  async deactivate() {
    if (this.data?.licenseId && this.data?.key) {
      try {
        // Find and delete this machine
        const res = await fetch(
          `${KEYGEN_API}/machines?fingerprint=${this.fingerprint}`,
          {
            headers: {
              'Authorization': `License ${this.data.key}`,
              'Accept': 'application/json',
            }
          }
        );
        const data = await res.json();
        
        if (data.data?.[0]?.id) {
          await fetch(`${KEYGEN_API}/machines/${data.data[0].id}`, {
            method: 'DELETE',
            headers: {
              'Authorization': `License ${this.data.key}`,
            }
          });
        }
      } catch {
        // Ignore deactivation errors
      }
    }
    
    this.data = null;
    this.tier = 'free';
    this.entitlements = [];
    await this.save();
    return { success: true, message: 'License deactivated' };
  }

  getLimits() {
    return LIMITS[this.tier] || LIMITS.free;
  }

  isPro() {
    return this.tier === 'pro' || this.tier === 'team';
  }

  isTeam() {
    return this.tier === 'team';
  }

  hasEntitlement(code) {
    return this.entitlements.includes(code);
  }

  filterRules(rules) {
    if (this.isPro()) return rules;
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

// Upgrade prompts
export function getUpgradePrompt(feature = null) {
  const baseUrl = 'https://agentguard.co/pro';
  
  const messages = {
    default: `
┌─────────────────────────────────────────────────────┐
│  ⭐ Upgrade to Agent Guard Pro                      │
│                                                     │
│  ✓ Unlimited files & findings                       │
│  ✓ All 34 security rules                            │
│  ✓ JSON output for CI/CD                            │
│  ✓ Runtime protection proxy                         │
│                                                     │
│  Pro: $49/mo  •  Team: $199/mo                      │
│  ${baseUrl}                             │
└─────────────────────────────────────────────────────┘`,
    
    files: `⚠️  Free tier limited to 50 files. Upgrade for unlimited: ${baseUrl}`,
    findings: `⚠️  Showing 10 of {total} findings. Upgrade to see all: ${baseUrl}`,
    json: `⚠️  JSON output requires Pro license: ${baseUrl}`,
    proxy: `⚠️  Runtime proxy requires Pro license: ${baseUrl}`,
    rules: `ℹ️  Free tier uses 5 basic rules. Pro includes 34 rules: ${baseUrl}`,
    dashboard: `⚠️  Dashboard requires Team license: ${baseUrl}`,
  };

  return messages[feature] || messages.default;
}
