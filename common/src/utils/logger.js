'use strict';

/**
 * Structured JSON logger.
 * In production, pipe stdout to your log aggregator (Loki, CloudWatch, Datadog).
 * PII redaction: userId is kept as an opaque identifier only — never log raw tokens,
 * passwords, or session cookies.
 */

const LOG_LEVEL_PRIORITY = { debug: 0, info: 1, warn: 2, error: 3 };
const MIN_LEVEL = process.env.LOG_LEVEL || 'info';

function shouldLog(level) {
  return (LOG_LEVEL_PRIORITY[level] ?? 1) >= (LOG_LEVEL_PRIORITY[MIN_LEVEL] ?? 1);
}

function redact(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  const REDACTED_KEYS = new Set(['password', 'token', 'authorization', 'cookie', 'secret', 'apiKey', 'api_key']);
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    out[k] = REDACTED_KEYS.has(k.toLowerCase()) ? '[REDACTED]' : v;
  }
  return out;
}

function log(level, data) {
  if (!shouldLog(level)) return;
  const entry = {
    level,
    time: new Date().toISOString(),
    service: process.env.SERVICE_NAME || 'api-threat-platform',
    ...(typeof data === 'string' ? { msg: data } : redact(data)),
  };
  const out = JSON.stringify(entry);
  if (level === 'error') process.stderr.write(out + '\n');
  else process.stdout.write(out + '\n');
}

module.exports = {
  debug: (data) => log('debug', data),
  info:  (data) => log('info',  data),
  warn:  (data) => log('warn',  data),
  error: (data) => log('error', data),
};
