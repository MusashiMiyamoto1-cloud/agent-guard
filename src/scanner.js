// Agent Guard Scanner
// Phase 1: Configuration & Secret Scanner

import { readdir, readFile, stat } from 'fs/promises';
import { join, basename, extname } from 'path';
import { rules } from './rules/index.js';

const IGNORE_DIRS = [
  'node_modules', '.git', '.venv', '__pycache__', 
  'dist', 'build', '.next', 'coverage', 'agent-guard'
];

const IGNORE_FILES = [
  '.DS_Store', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'
];

export class Scanner {
  constructor(options = {}) {
    this.findings = [];
    this.scannedFiles = 0;
    this.options = {
      maxFileSize: options.maxFileSize || 1024 * 1024, // 1MB
      followSymlinks: options.followSymlinks || false,
      ...options
    };
  }

  async scan(targetPath) {
    this.findings = [];
    this.scannedFiles = 0;
    
    const stats = await stat(targetPath);
    
    if (stats.isDirectory()) {
      await this.scanDirectory(targetPath);
      await this.checkManifests(targetPath);
    } else {
      await this.scanFile(targetPath);
    }
    
    return this.generateReport();
  }

  async scanDirectory(dirPath) {
    try {
      const entries = await readdir(dirPath, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = join(dirPath, entry.name);
        
        if (entry.isDirectory()) {
          if (!IGNORE_DIRS.includes(entry.name)) {
            await this.scanDirectory(fullPath);
          }
        } else if (entry.isFile()) {
          if (!IGNORE_FILES.includes(entry.name)) {
            await this.scanFile(fullPath);
          }
        }
      }
    } catch (err) {
      // Permission denied or other error, skip
    }
  }

  async scanFile(filePath) {
    try {
      const stats = await stat(filePath);
      
      if (stats.size > this.options.maxFileSize) {
        return; // Skip large files
      }
      
      const content = await readFile(filePath, 'utf-8');
      const fileName = basename(filePath);
      
      this.scannedFiles++;
      
      for (const rule of rules) {
        if (!rule.patterns) continue; // Skip non-pattern rules
        
        if (!this.matchesFilePattern(fileName, rule.files)) {
          continue;
        }
        
        for (const pattern of rule.patterns) {
          const matches = content.match(pattern);
          
          if (matches) {
            for (const match of matches) {
              this.addFinding(rule, filePath, match, content);
            }
          }
        }
      }
    } catch (err) {
      // Binary file or read error, skip
    }
  }

  matchesFilePattern(fileName, patterns) {
    if (patterns.includes('*')) return true;
    
    for (const pattern of patterns) {
      if (pattern.startsWith('*.')) {
        const ext = pattern.slice(1);
        if (fileName.endsWith(ext)) return true;
      } else if (fileName === pattern) {
        return true;
      } else if (pattern.includes('*')) {
        const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
        if (regex.test(fileName)) return true;
      }
    }
    
    return false;
  }

  async checkManifests(dirPath) {
    // Check for skills without manifests
    try {
      const entries = await readdir(dirPath, { withFileTypes: true });
      
      for (const entry of entries) {
        if (entry.isDirectory() && entry.name === 'skills') {
          await this.checkSkillsDirectory(join(dirPath, entry.name));
        }
      }
    } catch (err) {
      // Skip
    }
  }

  async checkSkillsDirectory(skillsPath) {
    try {
      const skills = await readdir(skillsPath, { withFileTypes: true });
      
      for (const skill of skills) {
        if (skill.isDirectory()) {
          const manifestPath = join(skillsPath, skill.name, 'skill.manifest.json');
          
          try {
            await stat(manifestPath);
          } catch {
            // Manifest doesn't exist
            const rule = rules.find(r => r.id === 'SKILL-002');
            if (rule) {
              this.findings.push({
                rule: rule.id,
                name: rule.name,
                severity: rule.severity,
                description: rule.description,
                file: join(skillsPath, skill.name),
                match: 'Missing skill.manifest.json',
                line: null
              });
            }
          }
        }
      }
    } catch (err) {
      // Skip
    }
  }

  addFinding(rule, filePath, match, content) {
    // Find line number
    const lines = content.split('\n');
    let lineNum = null;
    
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].includes(match.substring(0, 50))) {
        lineNum = i + 1;
        break;
      }
    }
    
    // Redact sensitive values
    const redactedMatch = this.redactSensitive(match);
    
    this.findings.push({
      rule: rule.id,
      name: rule.name,
      severity: rule.severity,
      description: rule.description,
      file: filePath,
      match: redactedMatch,
      line: lineNum
    });
  }

  redactSensitive(match) {
    // Redact API keys and secrets
    return match
      .replace(/(sk-[a-zA-Z0-9]{4})[a-zA-Z0-9]+/g, '$1***REDACTED***')
      .replace(/(ghp_[a-zA-Z0-9]{4})[a-zA-Z0-9]+/g, '$1***REDACTED***')
      .replace(/(AKIA[A-Z0-9]{4})[A-Z0-9]+/g, '$1***REDACTED***')
      .replace(/(password\s*[:=]\s*["']?)[^"'\s]+/gi, '$1***REDACTED***')
      .replace(/(secret\s*[:=]\s*["']?)[^"'\s]+/gi, '$1***REDACTED***')
      .replace(/(api[_-]?key\s*[:=]\s*["']?)[^"'\s]+/gi, '$1***REDACTED***');
  }

  generateReport() {
    const critical = this.findings.filter(f => f.severity === 'critical');
    const high = this.findings.filter(f => f.severity === 'high');
    const medium = this.findings.filter(f => f.severity === 'medium');
    const low = this.findings.filter(f => f.severity === 'low');
    
    // Calculate score (0-100)
    // Weights: Critical=30, High=20, Medium=5, Low=2
    // 1 High = 80 (B), 1 Critical = 70 (C)
    const score = Math.max(0, 100 - (
      critical.length * 30 +
      high.length * 20 +
      medium.length * 5 +
      low.length * 2
    ));
    
    const grade = 
      score >= 90 ? 'A' :
      score >= 80 ? 'B' :
      score >= 70 ? 'C' :
      score >= 60 ? 'D' : 'F';
    
    return {
      score,
      grade,
      scannedFiles: this.scannedFiles,
      totalFindings: this.findings.length,
      summary: {
        critical: critical.length,
        high: high.length,
        medium: medium.length,
        low: low.length
      },
      findings: this.findings
    };
  }
}

export async function scan(targetPath, options = {}) {
  const scanner = new Scanner(options);
  return scanner.scan(targetPath);
}
