'use strict';

/**
 * Reverse proxy gateway entrypoint.
 *
 * This is integration mechanism #1: reverse proxy.
 * Applications sit behind this gateway with ZERO code changes.
 * The gateway extracts security context, enforces threats, then proxies.
 *
 * For applications that handle their own proxying, use the HTTP Event API instead
 * (POST /api/security-events from your app's middleware).
 */

require('dotenv').config();
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const Redis = require('ioredis');
const helmet = require('helmet');

const { buildEnforcementMiddleware } = require('./middleware/enforcement');
const { buildEventIngestionRouter } = require('./routes/events');
const { ThreatStateStore } = require('../../common/src/services/ThreatStateStore');
const { SecurityEventProducer } = require('../../common/src/services/SecurityEventProducer');
const config = require('./config');
const logger = require('../../common/src/utils/logger');

process.env.SERVICE_NAME = 'gateway';

async function main() {
  const app = express();
  app.use(helmet());
  app.use(express.json({ limit: '512kb' }));
  app.set('trust proxy', true);

  // ── Infrastructure ────────────────────────────────────────────────────────
  const redis = new Redis({
    host: config.redis.host,
    port: config.redis.port,
    password: config.redis.password || undefined,
    retryStrategy: (times) => Math.min(times * 200, 5000),
    enableOfflineQueue: false, // Fail fast so gateway doesn't queue up
  });
  redis.on('error', (err) => logger.error({ msg: 'Redis error', err: err.message }));

  const threatStore = new ThreatStateStore(redis, { failClosed: config.gateway.failClosed });

  const producer = new SecurityEventProducer(config.kafka);
  await producer.connect();

  // ── Platform Routes (event ingestion API) ─────────────────────────────────
  app.use('/platform', buildEventIngestionRouter({
    eventProducer: producer,
    apiKeys: config.apiKeys,
  }));

  // ── Enforcement Middleware ────────────────────────────────────────────────
  const enforce = buildEnforcementMiddleware({
    threatStore,
    eventProducer: producer,
    config,
  });

  // ── Reverse Proxy to Upstream Application ─────────────────────────────────
  const upstreamUrl = config.gateway.upstreamUrl;
  if (upstreamUrl) {
    app.use('/', enforce, createProxyMiddleware({
      target: upstreamUrl,
      changeOrigin: true,
      on: {
        error: (err, req, res) => {
          logger.error({ msg: 'Proxy error', err: err.message, path: req.path });
          res.status(502).json({ error: 'Bad gateway' });
        },
      },
    }));
    logger.info({ msg: `Proxying requests to ${upstreamUrl}` });
  } else {
    logger.warn({ msg: 'No UPSTREAM_URL set — running in event-ingestion-only mode' });
    app.use('/', enforce, (req, res) => res.json({ msg: 'No upstream configured' }));
  }

  // ── Start ─────────────────────────────────────────────────────────────────
  const port = config.gateway.port || 3000;
  app.listen(port, () => logger.info({ msg: `Gateway listening on :${port}` }));

  const shutdown = async (signal) => {
    logger.info({ msg: `${signal} received, shutting down gateway` });
    await producer.disconnect();
    redis.disconnect();
    process.exit(0);
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT',  () => shutdown('SIGINT'));
}

main().catch(err => {
  logger.error({ msg: 'Fatal gateway error', err: err.message, stack: err.stack });
  process.exit(1);
});
