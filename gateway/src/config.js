'use strict';

module.exports = {
  applicationId: process.env.APPLICATION_ID || 'default',

  gateway: {
    port: parseInt(process.env.PORT || '3000'),
    upstreamUrl: process.env.UPSTREAM_URL || null,
    failClosed: process.env.FAIL_CLOSED === 'true',
  },

  kafka: {
    brokers: (process.env.KAFKA_BROKERS || 'kafka:9092').split(','),
    clientId: 'threat-gateway',
  },

  redis: {
    host: process.env.REDIS_HOST || 'redis',
    port: parseInt(process.env.REDIS_PORT || '6379'),
    password: process.env.REDIS_PASSWORD || null,
  },

  // Map applicationId → API key for HTTP event ingestion
  apiKeys: {
    'sample-app': process.env.SAMPLE_APP_API_KEY || 'sample-app-secret',
    'default':    process.env.DEFAULT_API_KEY    || 'default-secret',
  },
};
