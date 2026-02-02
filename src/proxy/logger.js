// Security Event Logger
// Structured logging for Agent Guard runtime events

import { appendFileSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';

const LOG_DIR = process.env.AGENT_GUARD_LOG_DIR || './agent-guard-logs';
const LOG_LEVEL = process.env.AGENT_GUARD_LOG_LEVEL || 'info';

const LEVELS = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
  critical: 4
};

let currentLogFile = null;

function ensureLogDir() {
  if (!existsSync(LOG_DIR)) {
    mkdirSync(LOG_DIR, { recursive: true });
  }
}

function getLogFile() {
  const date = new Date().toISOString().split('T')[0];
  const filename = `agent-guard-${date}.jsonl`;
  return join(LOG_DIR, filename);
}

export function logEvent(event) {
  const logEntry = {
    timestamp: new Date().toISOString(),
    level: event.violation ? 'warn' : 'info',
    ...event
  };

  // Console output for development
  if (process.env.NODE_ENV !== 'production') {
    const color = event.violation ? '\x1b[33m' : '\x1b[36m';
    const icon = event.violation ? '⚠️ ' : 'ℹ️ ';
    console.log(`${color}${icon}[${event.type}]\x1b[0m`, 
      event.target || event.error || '');
  }

  // File output
  try {
    ensureLogDir();
    const logFile = getLogFile();
    appendFileSync(logFile, JSON.stringify(logEntry) + '\n');
  } catch (err) {
    console.error('Failed to write log:', err.message);
  }

  // Violation alerting (placeholder for webhook/email)
  if (event.violation && event.type !== 'egress_allowed') {
    handleViolation(logEntry);
  }
}

function handleViolation(event) {
  // In production, this would:
  // 1. Send webhook to alerting system
  // 2. Increment violation counters
  // 3. Potentially trigger rate limiting
  
  if (process.env.AGENT_GUARD_WEBHOOK) {
    // POST to webhook
    // fetch(process.env.AGENT_GUARD_WEBHOOK, {
    //   method: 'POST',
    //   body: JSON.stringify(event)
    // });
  }
}

export function queryLogs(options = {}) {
  // Query historical logs
  // Used by dashboard and forensics
  
  const { 
    startTime,
    endTime,
    type,
    violationsOnly = false,
    limit = 100 
  } = options;

  // Implementation would read from log files
  // and filter based on criteria
  
  return [];
}

export function getViolationSummary(timeRange = '24h') {
  // Get summary of violations for dashboard
  
  return {
    total: 0,
    by_type: {},
    by_target: {},
    trend: []
  };
}

// Structured event types for type safety
export const EventTypes = {
  EGRESS_ALLOWED: 'egress_allowed',
  EGRESS_BLOCKED: 'egress_blocked',
  FILE_ACCESS_ALLOWED: 'file_access_allowed',
  FILE_ACCESS_BLOCKED: 'file_access_blocked',
  INTENT_VERIFIED: 'intent_verified',
  INTENT_MISMATCH: 'intent_mismatch',
  ACT_GENERATED: 'act_generated',
  PROXY_ERROR: 'proxy_error',
  REQUEST_COMPLETE: 'request_complete'
};
