#!/usr/bin/env node
'use strict';

/**
 * Kafka topic setup script.
 * Run once before starting services: node infrastructure/kafka/setup-topics.js
 */

const { Kafka } = require('kafkajs');

const kafka = new Kafka({
  clientId: 'topic-setup',
  brokers: (process.env.KAFKA_BROKERS || 'localhost:9092').split(','),
});

const admin = kafka.admin();

const TOPICS = [
  {
    topic: 'security.events.raw',
    numPartitions: 12,       // Scale: 12 partitions → 12 max parallel consumers
    replicationFactor: 1,    // Set to 3 in production
    configEntries: [
      { name: 'retention.ms',          value: String(7 * 24 * 60 * 60 * 1000) }, // 7 days
      { name: 'compression.type',      value: 'gzip' },
      { name: 'max.message.bytes',     value: '1048576' }, // 1MB
    ],
  },
  {
    topic: 'security.events.threats',
    numPartitions: 6,
    replicationFactor: 1,
    configEntries: [
      { name: 'retention.ms',     value: String(3 * 24 * 60 * 60 * 1000) }, // 3 days
      { name: 'compression.type', value: 'gzip' },
    ],
  },
];

async function setup() {
  await admin.connect();
  console.log('Connected to Kafka');

  const existing = await admin.listTopics();
  const toCreate = TOPICS.filter(t => !existing.includes(t.topic));

  if (toCreate.length === 0) {
    console.log('All topics already exist');
  } else {
    await admin.createTopics({ topics: toCreate, waitForLeaders: true });
    toCreate.forEach(t => console.log(`Created topic: ${t.topic} (${t.numPartitions} partitions)`));
  }

  await admin.disconnect();
  console.log('Done');
}

setup().catch(err => {
  console.error('Topic setup failed:', err.message);
  process.exit(1);
});
