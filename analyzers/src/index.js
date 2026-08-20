'use strict';

require('dotenv').config();
const Redis = require('ioredis');
const { AnalyzerOrchestrator } = require('./analyzers/AnalyzerOrchestrator');
const { SecurityEventConsumer } = require('./consumers/SecurityEventConsumer');
const config = require('./config');
const logger = require('../../common/src/utils/logger');

process.env.SERVICE_NAME = 'analyzer-service';

async function main() {
  logger.info({ msg: 'Analyzer service starting' });

  const redis = new Redis({
    host: config.redis.host,
    port: config.redis.port,
    password: config.redis.password || undefined,
    retryStrategy: (times) => Math.min(times * 100, 3000),
    enableOfflineQueue: true,
  });

  redis.on('error', (err) => logger.error({ msg: 'Redis error', err: err.message }));
  redis.on('connect', () => logger.info({ msg: 'Redis connected' }));

  const orchestrator = new AnalyzerOrchestrator(config, { redis });
  orchestrator.initialize();

  const consumer = new SecurityEventConsumer(config.kafka, orchestrator);

  const shutdown = async (signal) => {
    logger.info({ msg: `Received ${signal}, shutting down` });
    await consumer.stop();
    redis.disconnect();
    process.exit(0);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT',  () => shutdown('SIGINT'));

  await consumer.start();
  logger.info({ msg: 'Analyzer service ready' });
}

main().catch(err => {
  logger.error({ msg: 'Fatal startup error', err: err.message, stack: err.stack });
  process.exit(1);
});
