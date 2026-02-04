#!/usr/bin/env node

// Agent Guard CLI
// Security scanner for AI agent configurations

import { scan } from './scanner.js';
import { resolve } from 'path';

import { createProxy } from './proxy/index.js';

const VERSION = '0.2.2';

const FEEDBACK_URL = 'https://github.com/MusashiMiyamoto1-cloud/agent-guard/issues/new';
const REPO_URL = 'https://github.com/MusashiMiyamoto1-cloud/agent-guard';

const COLORS = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  gray: '\x1b[90m'
};

const SEVERITY_COLORS = {
  critical: COLORS.red,
  high: COLORS.magenta,
  medium: COLORS.yellow,
  low: COLORS.cyan
};

const SEVERITY_ICONS = {
  critical: '🚨',
  high: '⚠️ ',
  medium: '📋',
  low: 'ℹ️ '
};

function printBanner() {
  console.log(`
${COLORS.cyan}╔═══════════════════════════════════════════════════╗
║                                                   ║
║   ${COLORS.bold}🛡  AGENT GUARD${COLORS.reset}${COLORS.cyan}  v${VERSION}                       ║
║   Security Scanner for AI Agents                  ║
║                                                   ║
╚═══════════════════════════════════════════════════╝${COLORS.reset}
`);
}

function printHelp() {
  console.log(`
${COLORS.bold}Usage:${COLORS.reset}
  agent-guard scan [path]     Scan directory for security issues
  agent-guard proxy [port]    Start runtime protection proxy
  agent-guard feedback [msg]  Submit feedback or report an issue
  agent-guard --help          Show this help message
  agent-guard --version       Show version

${COLORS.bold}Examples:${COLORS.reset}
  npx agent-guard scan .              Scan current directory
  npx agent-guard scan ./my-agent     Scan specific agent directory
  npx agent-guard proxy               Start proxy on port 18800
  npx agent-guard proxy 8080          Start proxy on custom port
  npx agent-guard feedback            Open feedback form
  npx agent-guard feedback "Bug: ..."  Submit inline feedback

${COLORS.bold}Options:${COLORS.reset}
  --json                      Output results as JSON
  --quiet                     Only show findings (no banner)
  --policy <file>             Use custom policy file

${COLORS.bold}Environment:${COLORS.reset}
  HTTP_PROXY=http://127.0.0.1:18800   Route agent through proxy

${COLORS.bold}Exit Codes:${COLORS.reset}
  0    No critical findings
  1    Critical findings detected
  2    Error during scan
`);
}

function printScore(report) {
  const { score, grade } = report;
  
  const gradeColor = 
    grade === 'A' ? COLORS.green :
    grade === 'B' ? COLORS.cyan :
    grade === 'C' ? COLORS.yellow :
    grade === 'D' ? COLORS.magenta : COLORS.red;
  
  const bar = '█'.repeat(Math.floor(score / 5)) + '░'.repeat(20 - Math.floor(score / 5));
  
  console.log(`
${COLORS.bold}Security Score:${COLORS.reset} ${gradeColor}${score}/100 (${grade})${COLORS.reset}

  ${gradeColor}${bar}${COLORS.reset}

${COLORS.bold}Summary:${COLORS.reset}
  ${COLORS.red}Critical:${COLORS.reset} ${report.summary.critical}
  ${COLORS.magenta}High:${COLORS.reset}     ${report.summary.high}
  ${COLORS.yellow}Medium:${COLORS.reset}   ${report.summary.medium}
  ${COLORS.cyan}Low:${COLORS.reset}      ${report.summary.low}

  Files scanned: ${report.scannedFiles}
`);
}

function printFindings(findings) {
  if (findings.length === 0) {
    console.log(`${COLORS.green}✓ No security issues found!${COLORS.reset}\n`);
    return;
  }
  
  console.log(`${COLORS.bold}Findings:${COLORS.reset}\n`);
  
  // Group by severity
  const grouped = {
    critical: findings.filter(f => f.severity === 'critical'),
    high: findings.filter(f => f.severity === 'high'),
    medium: findings.filter(f => f.severity === 'medium'),
    low: findings.filter(f => f.severity === 'low')
  };
  
  for (const severity of ['critical', 'high', 'medium', 'low']) {
    const items = grouped[severity];
    if (items.length === 0) continue;
    
    const color = SEVERITY_COLORS[severity];
    const icon = SEVERITY_ICONS[severity];
    
    console.log(`${color}${COLORS.bold}${icon} ${severity.toUpperCase()} (${items.length})${COLORS.reset}\n`);
    
    for (const finding of items) {
      const lineInfo = finding.line ? `:${finding.line}` : '';
      console.log(`  ${color}[${finding.rule}]${COLORS.reset} ${finding.name}`);
      console.log(`  ${COLORS.gray}${finding.file}${lineInfo}${COLORS.reset}`);
      console.log(`  ${finding.description}`);
      console.log(`  Match: ${COLORS.yellow}${finding.match}${COLORS.reset}`);
      console.log();
    }
  }
}

function printRecommendations(report) {
  if (report.totalFindings === 0) return;
  
  console.log(`${COLORS.bold}Recommendations:${COLORS.reset}\n`);
  
  const hasSecrets = report.findings.some(f => f.rule.startsWith('SEC-'));
  const hasNetwork = report.findings.some(f => f.rule.startsWith('NET-'));
  const hasAuth = report.findings.some(f => f.rule.startsWith('AUTH-'));
  const hasSkill = report.findings.some(f => f.rule.startsWith('SKILL-'));
  
  if (hasSecrets) {
    console.log(`  ${COLORS.red}1.${COLORS.reset} Rotate exposed API keys immediately`);
    console.log(`     Move secrets to environment variables or a vault\n`);
  }
  
  if (hasNetwork) {
    console.log(`  ${COLORS.red}2.${COLORS.reset} Fix network exposure`);
    console.log(`     Bind to 127.0.0.1 instead of 0.0.0.0`);
    console.log(`     Use a reverse proxy with authentication\n`);
  }
  
  if (hasAuth) {
    console.log(`  ${COLORS.red}3.${COLORS.reset} Enable authentication`);
    console.log(`     Configure JWT or API key authentication\n`);
  }
  
  if (hasSkill) {
    console.log(`  ${COLORS.yellow}4.${COLORS.reset} Review skill permissions`);
    console.log(`     Add skill.manifest.json with explicit permissions`);
    console.log(`     Audit skills using shell execution\n`);
  }
}

function printFeedbackFooter() {
  console.log(`${COLORS.gray}───────────────────────────────────────────────────────${COLORS.reset}`);
  console.log(`${COLORS.gray}Feedback? Run: ${COLORS.cyan}npx agent-guard feedback${COLORS.gray} or visit:${COLORS.reset}`);
  console.log(`${COLORS.cyan}${FEEDBACK_URL}${COLORS.reset}\n`);
}

async function handleFeedback(message) {
  const { spawn } = await import('child_process');
  
  // Sanitize: limit length, strip control characters
  if (message) {
    message = message.slice(0, 500).replace(/[\x00-\x1f\x7f]/g, '');
  }
  
  // Build issue URL with pre-filled content (URLSearchParams handles encoding)
  const params = new URLSearchParams();
  params.set('labels', 'feedback');
  
  if (message) {
    const isAgent = /agent|automated|scan result|false positive/i.test(message);
    params.set('labels', isAgent ? 'feedback,from-agent' : 'feedback');
    params.set('title', message.slice(0, 80));
    params.set('body', `## Feedback\n\n${message}\n\n---\n*Submitted via CLI v${VERSION}*`);
  } else {
    params.set('title', 'Feedback: ');
    params.set('body', `## Feedback\n\n<!-- Describe your feedback, bug, or feature request -->\n\n## Context\n- Agent Guard version: ${VERSION}\n- Submitted via: CLI\n\n---\n*Thank you for helping improve Agent Guard!*`);
  }
  
  const url = `${FEEDBACK_URL}?${params.toString()}`;
  
  console.log(`${COLORS.cyan}Opening feedback form...${COLORS.reset}\n`);
  
  // Use spawn with args array to avoid shell injection (no shell interpolation)
  const platform = process.platform;
  try {
    const cmd = platform === 'darwin' ? 'open' : platform === 'win32' ? 'start' : 'xdg-open';
    const args = platform === 'win32' ? ['', url] : [url];
    const child = spawn(cmd, args, { stdio: 'ignore', detached: true });
    child.unref();
    console.log(`${COLORS.green}✓ Browser opened${COLORS.reset}`);
  } catch {
    console.log(`${COLORS.yellow}Could not open browser. Please visit:${COLORS.reset}`);
    console.log(`${COLORS.cyan}${url}${COLORS.reset}`);
  }
  
  console.log(`\n${COLORS.gray}Or visit: ${COLORS.cyan}${FEEDBACK_URL}${COLORS.reset}\n`);
}

async function main() {
  const args = process.argv.slice(2);
  
  const jsonOutput = args.includes('--json');
  const quiet = args.includes('--quiet');
  const filteredArgs = args.filter(a => !a.startsWith('--'));
  
  if (args.includes('--help') || args.includes('-h')) {
    printBanner();
    printHelp();
    process.exit(0);
  }
  
  if (args.includes('--version') || args.includes('-v')) {
    console.log(`agent-guard v${VERSION}`);
    process.exit(0);
  }
  
  const command = filteredArgs[0];
  
  if (command === 'feedback') {
    const message = filteredArgs.slice(1).join(' ') || null;
    if (!quiet) printBanner();
    await handleFeedback(message);
    process.exit(0);
  }
  
  if (command === 'proxy') {
    const port = parseInt(filteredArgs[1]) || 18800;
    if (!quiet) printBanner();
    console.log(`${COLORS.cyan}Starting runtime protection proxy...${COLORS.reset}\n`);
    
    try {
      const proxy = createProxy({ port });
      proxy.start();
      
      console.log(`${COLORS.green}Proxy ready.${COLORS.reset}`);
      console.log(`${COLORS.gray}Set HTTP_PROXY=http://127.0.0.1:${port} to route agent traffic${COLORS.reset}\n`);
      
      // Keep running
      process.on('SIGINT', () => {
        console.log(`\n${COLORS.yellow}Shutting down...${COLORS.reset}`);
        proxy.stop();
        process.exit(0);
      });
    } catch (err) {
      console.error(`${COLORS.red}Error: ${err.message}${COLORS.reset}`);
      process.exit(2);
    }
    return;
  }
  
  if (command !== 'scan') {
    if (!quiet) printBanner();
    printHelp();
    process.exit(0);
  }
  
  const targetPath = resolve(filteredArgs[1] || '.');
  
  if (!quiet && !jsonOutput) {
    printBanner();
    console.log(`${COLORS.gray}Scanning: ${targetPath}${COLORS.reset}\n`);
  }
  
  try {
    const report = await scan(targetPath);
    
    if (jsonOutput) {
      // Add feedback URL to JSON output for agent consumption
      report.feedback_url = FEEDBACK_URL;
      report.repo_url = REPO_URL;
      console.log(JSON.stringify(report, null, 2));
    } else {
      printScore(report);
      printFindings(report.findings);
      printRecommendations(report);
      printFeedbackFooter();
    }
    
    // Exit with 1 if critical findings
    process.exit(report.summary.critical > 0 ? 1 : 0);
    
  } catch (err) {
    console.error(`${COLORS.red}Error: ${err.message}${COLORS.reset}`);
    process.exit(2);
  }
}

main();
