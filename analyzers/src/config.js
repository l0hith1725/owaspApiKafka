'use strict';

module.exports = {
  applicationId: process.env.APPLICATION_ID || 'default',
  threatTtlSeconds: parseInt(process.env.THREAT_TTL_SECONDS || '300'),

  kafka: {
    brokers: (process.env.KAFKA_BROKERS || 'kafka:9092').split(','),
    clientId: 'threat-analyzer',
    groupId: process.env.KAFKA_GROUP_ID || 'threat-analyzers',
  },

  redis: {
    host: process.env.REDIS_HOST || 'redis',
    port: parseInt(process.env.REDIS_PORT || '6379'),
    password: process.env.REDIS_PASSWORD || null,
  },

  analyzers: {
    credentialStuffing: {
      enabled: process.env.ANALYZER_CS_ENABLED !== 'false',
      windowSeconds: parseInt(process.env.CS_WINDOW_SECONDS || '60'),
      maxIpFailures: parseInt(process.env.CS_MAX_IP_FAILURES || '20'),
      maxUserFailures: parseInt(process.env.CS_MAX_USER_FAILURES || '5'),
      maxDistinctAccounts: parseInt(process.env.CS_MAX_DISTINCT_ACCOUNTS || '10'),
      maxDistinctIps: parseInt(process.env.CS_MAX_DISTINCT_IPS || '8'),
    },
    bola: {
      enabled: process.env.ANALYZER_BOLA_ENABLED !== 'false',
      windowSeconds: parseInt(process.env.BOLA_WINDOW_SECONDS || '120'),
      maxDistinctResources: parseInt(process.env.BOLA_MAX_DISTINCT_RESOURCES || '50'),
      maxCrossOwnershipAccess: parseInt(process.env.BOLA_MAX_CROSS_OWNERSHIP || '3'),
    },
    businessFlowAbuse: {
      enabled: process.env.ANALYZER_BFA_ENABLED !== 'false',
      workflows: [
        {
          id: 'payment-flow',
          steps: [
            'POST:/api/auth/login',
            'POST:/api/payment-methods',
            'PATCH:/api/account',
            'POST:/api/transfers',
          ],
          maxCompletionsPerWindow: 2,
          windowSeconds: 300,
        },
        {
          id: 'otp-abuse',
          steps: [
            'POST:/api/otp/generate',
            'POST:/api/otp/verify',
          ],
          maxCompletionsPerWindow: 3,
          windowSeconds: 60,
        },
      ],
    },
  },
};
