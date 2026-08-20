# Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        External Traffic                              │
└─────────────────────────────────┬───────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     API Threat Gateway :3000                         │
│                                                                      │
│  ┌──────────────────────┐    ┌──────────────────────────────────┐   │
│  │  Enforcement         │    │  Event Ingestion API              │   │
│  │  Middleware          │    │  POST /platform/security-events   │   │
│  │                      │    │  (for non-proxy integrations)     │   │
│  │  1. Extract context  │    └──────────────────────────────────┘   │
│  │  2. Redis threat lookup                                           │
│  │  3. ALLOW/WARN/       │                                           │
│  │     RATE_LIMIT/BLOCK  │                                           │
│  │  4. Publish to Kafka  │                                           │
│  │     (async, fire+forget)                                          │
│  └──────────┬───────────┘                                           │
└─────────────┼───────────────────────────────────────────────────────┘
              │                          │
              │ proxy                    │ kafka publish (async)
              ▼                          ▼
┌─────────────────────┐    ┌────────────────────────────────────────┐
│   Upstream App      │    │           Apache Kafka                  │
│   (any framework)   │    │                                         │
│                     │    │  Topic: security.events.raw             │
│  Spring Boot        │    │  Partitions: 12                         │
│  Express/Node       │    │  Key: appId:user:userId                 │
│  FastAPI            │    │                                         │
│  Go / .NET          │    └───────────────┬────────────────────────┘
└─────────────────────┘                    │
                                           │ consume
                              ┌────────────▼────────────────────────┐
                              │     Analyzer Service                  │
                              │                                       │
                              │  Consumer Group: threat-analyzers     │
                              │  (scales horizontally)                │
                              │                                       │
                              │  ┌─────────────────────────────────┐ │
                              │  │   AnalyzerOrchestrator           │ │
                              │  │                                   │ │
                              │  │  ┌──────────────────────────┐   │ │
                              │  │  │ CredentialStuffing        │   │ │
                              │  │  │ Analyzer                  │   │ │
                              │  │  └──────────────────────────┘   │ │
                              │  │  ┌──────────────────────────┐   │ │
                              │  │  │ BOLA Analyzer             │   │ │
                              │  │  └──────────────────────────┘   │ │
                              │  │  ┌──────────────────────────┐   │ │
                              │  │  │ BusinessFlowAbuse         │   │ │
                              │  │  │ Analyzer                  │   │ │
                              │  │  └──────────────────────────┘   │ │
                              │  └─────────────────┬───────────────┘ │
                              └────────────────────┼─────────────────┘
                                                   │ write threat signal
                                                   ▼
                              ┌────────────────────────────────────────┐
                              │              Redis                      │
                              │                                         │
                              │  threat:{appId}:ip:{ip}          TTL   │
                              │  threat:{appId}:user:{userId}    TTL   │
                              │  sw:cs:ip:fail:{appId}:{ip}     (sorted set) │
                              │  bfa:state:{appId}:{wfId}:{user} TTL  │
                              └────────────────────────────────────────┘
                                          ▲
                                          │ read on next request
                                   Gateway Enforcement
```

## Request Flow — Normal Request

```
Client → Gateway → Extract context
                 → Redis pipeline read (threat:ip, threat:user)
                 → No threats found
                 → Forward to upstream (proxy)
                 → Upstream responds
                 → Publish SecurityEvent to Kafka (setImmediate)
                 → Return response to client
```

## Request Flow — Malicious Request (after detection)

```
Client → Gateway → Extract context
                 → Redis read → Threat found (CRITICAL, BLOCK)
                 → Return 403 Forbidden
                 → Publish SecurityEvent to Kafka (still published)
```

## Analyzer Flow

```
Kafka Message → Consumer → validate event
                         → AnalyzerOrchestrator.analyze(event)
                         → Promise.all([cs.analyze, bola.analyze, bfa.analyze])
                         → Each analyzer queries Redis sliding windows
                         → Each analyzer returns ThreatDetectionResult
                         → Orchestrator aggregates: max score + multi-signal bonus
                         → If threat detected → write to Redis with TTL
```

## Component Responsibilities

| Component | Owns | Does NOT own |
|-----------|------|--------------|
| Gateway | Request enforcement, event publishing | Behavioral analysis |
| Analyzer | Threat detection, Redis threat writes | Request handling |
| Redis | Threat state, sliding window state | Long-term storage |
| Kafka | Event delivery, decoupling | Analysis logic |
| ThreatStateStore | Redis key schema | Detection logic |
| SlidingWindow | Time-window counting | Threat decisions |

## Scaling

- **Gateway**: Stateless, scale horizontally behind a load balancer. All state is in Redis/Kafka.
- **Analyzer**: Scale by adding instances. Kafka distributes partitions across consumer group members. Because events are partitioned by userId/IP, a given user's events go to the same partition and consumer instance, ensuring correct sliding-window state without distributed locks.
- **Redis**: Use Redis Cluster for horizontal scaling. Sliding-window keys are independent, so no cross-shard coordination is needed.
- **Kafka**: Increase partition count to increase parallelism. Currently 12 partitions → 12 max analyzer instances.

## Failure Modes

| Failure | Gateway behavior | Analyzer behavior |
|---------|-----------------|-------------------|
| Redis down | Fail-open (allow) or fail-closed (503) per config | Sliding windows return 0; detection degrades gracefully |
| Kafka down | Events dropped (logged); requests still served | Consumer reconnects; replays from last committed offset |
| Analyzer crash | No immediate impact; Redis threat state persists | Consumer restarts; Kafka replays uncommitted events |
| Duplicate event | Published again; Redis sorted-set deduplicates by requestId | Minor count inflation; thresholds absorb this |

## Eventual Consistency Trade-off

Because behavioral analysis is **asynchronous**, the first N malicious requests in a credential stuffing attack will pass through the gateway before the analyzer detects the pattern and writes to Redis. This is an **intentional trade-off**: the alternative (synchronous analysis on every request) would add significant latency to every legitimate request.

Mitigation strategies:
1. Set detection thresholds low enough to catch attacks early.
2. Use the synchronous enforcement layer for high-confidence signals (e.g., known bad IP lists from a threat intelligence feed).
3. Accept that the first few requests in a new attack pattern may succeed; focus on preventing sustained attacks.
