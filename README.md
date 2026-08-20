# API Threat Detection Platform

> A reusable API security platform combining low-latency synchronous enforcement with asynchronous behavioral threat detection. Applications detect emerging attack patterns and feed temporary risk signals back into the request path.

---

## Problem Statement

API gateways typically enforce authentication and rate limits synchronously. But modern API attacks — credential stuffing, BOLA enumeration, business flow abuse — require **behavioral analysis across multiple requests over time**. A single request rarely looks malicious in isolation.

This platform solves that by:
1. Enforcing known threats **synchronously** (< 2ms overhead per request)
2. Detecting new threat patterns **asynchronously** via Kafka consumers
3. Feeding threat signals back into the synchronous enforcement path via Redis TTL flags

---

## Architecture

```
Internet → [Gateway :3000] → [Upstream App]
                ↓ (async, non-blocking)
            [Kafka] → [Analyzer Service]
                              ↓
                           [Redis] ← reads on next request
                              ↑
                         Gateway enforcement
```

See [architecture/ARCHITECTURE.md](architecture/ARCHITECTURE.md) for full diagrams.

---

## Quick Start

```bash
# Start everything
docker-compose up --build

# Wait ~30 seconds for Kafka to initialize, then:

# Run attack simulations
npm run simulate:cs      # Credential stuffing
npm run simulate:bola    # BOLA / resource enumeration
npm run simulate:flow    # Business flow abuse

# Run tests
npm test

# View Kafka events
open http://localhost:8080   # Kafka UI

# View metrics
open http://localhost:3001   # Grafana (admin/admin)
open http://localhost:9090   # Prometheus
```

---

## Services

| Service | Port | Description |
|---------|------|-------------|
| Gateway | 3000 | Enforcement proxy + event ingestion API |
| Sample App | 4000 | Demo vulnerable Node.js app (internal) |
| Kafka | 9092 | Event streaming |
| Kafka UI | 8080 | Kafka topic browser |
| Redis | 6379 | Threat state + sliding windows |
| Prometheus | 9090 | Metrics |
| Grafana | 3001 | Dashboards |

---

## Repository Structure

```
api-threat-platform/
├── common/                     # Shared models, utils, services
│   └── src/
│       ├── models/
│       │   ├── SecurityEvent.js          # Canonical event schema
│       │   └── ThreatDetectionResult.js  # Risk scoring model
│       ├── services/
│       │   ├── SecurityEventProducer.js  # Kafka producer
│       │   └── ThreatStateStore.js       # Redis threat R/W
│       └── utils/
│           ├── SlidingWindow.js          # Redis sorted-set windows
│           └── logger.js                 # Structured JSON logger
│
├── gateway/                    # API gateway + enforcement
│   └── src/
│       ├── middleware/enforcement.js     # Core enforcement middleware
│       ├── routes/events.js              # HTTP event ingestion API
│       ├── config.js
│       └── index.js
│
├── analyzers/                  # Kafka consumer + threat analyzers
│   └── src/
│       ├── analyzers/
│       │   ├── ThreatAnalyzer.js          # Abstract base class
│       │   ├── AnalyzerOrchestrator.js    # Runs all analyzers
│       │   ├── CredentialStuffingAnalyzer.js
│       │   ├── BOLAAnalyzer.js
│       │   └── BusinessFlowAbuseAnalyzer.js
│       ├── consumers/SecurityEventConsumer.js
│       ├── config.js
│       └── index.js
│
├── sample-app/                 # Demo Node.js app (intentionally vulnerable)
│
├── tests/
│   ├── unit/                   # Unit tests for all components
│   ├── integration/            # Gateway integration tests
│   └── simulation/             # Attack scenario scripts
│
├── infrastructure/
│   ├── kafka/                  # Topic setup
│   ├── prometheus/             # Scrape config
│   └── grafana/                # Dashboards + datasources
│
├── architecture/ARCHITECTURE.md
├── docs/INTEGRATION_GUIDE.md
└── docker-compose.yml
```

---

## Event Schema

Every API request produces a `SecurityEvent`. Mandatory fields:

| Field | Type | Description |
|-------|------|-------------|
| requestId | string | UUID per request |
| applicationId | string | Which app produced this event |
| timestamp | ISO-8601 | UTC timestamp |
| sourceIp | string | Client IP |
| httpMethod | string | GET/POST/etc |
| path | string | Raw request path |
| endpointId | string | Normalized: `METHOD:/path/{param}` |
| statusCode | number | HTTP response code |

Optional but strongly recommended:

| Field | Purpose |
|-------|---------|
| userId | Enables per-user detection |
| authSuccess | Enables credential stuffing detection |
| resourceType + resourceId | Enables BOLA detection |
| metadata.ownerUserId | Enables cross-ownership BOLA detection |
| metadata.isAuthEndpoint | Marks login endpoints explicitly |

**Never include**: passwords, tokens, cookies, session data.

---

## Analyzer Configuration

```yaml
# Via environment variables (docker-compose.yml)

# Credential Stuffing
CS_WINDOW_SECONDS: 60
CS_MAX_IP_FAILURES: 20
CS_MAX_USER_FAILURES: 5
CS_MAX_DISTINCT_ACCOUNTS: 10
CS_MAX_DISTINCT_IPS: 8

# BOLA
BOLA_WINDOW_SECONDS: 120
BOLA_MAX_DISTINCT_RESOURCES: 50

# Threat TTL (how long Redis blocks persist)
THREAT_TTL_SECONDS: 300
```

Business flow workflows are configured in `analyzers/src/config.js`:
```javascript
workflows: [
  {
    id: 'payment-flow',
    steps: ['POST:/api/auth/login', 'POST:/api/payment-methods', 'POST:/api/transfers'],
    maxCompletionsPerWindow: 2,
    windowSeconds: 300,
  }
]
```

---

## Risk Scoring

| Score | Level | Default Action |
|-------|-------|----------------|
| 0–29 | LOW | ALLOW |
| 30–59 | MEDIUM | WARN (header set) |
| 60–79 | HIGH | RATE_LIMIT (429) |
| 80–100 | CRITICAL | BLOCK (403) |

Multiple analyzer signals add a 10-point bonus (capped at 100).

---

## Attack Simulations

```bash
# 1. Credential stuffing (25 failed login attempts from one IP)
node tests/simulation/credential-stuffing.js

# 2. BOLA (enumerate 30 order IDs)
node tests/simulation/bola-attack.js

# 3. Business flow abuse (complete payment flow 5x rapidly)
node tests/simulation/business-flow-abuse.js

# 4. Normal user (false-positive verification)
node tests/simulation/normal-user.js
```

Expected output for credential stuffing:
```
[001] victim1@example.com → HTTP 401 ✓
[002] victim2@example.com → HTTP 401 ✓
...
[012] victim3@example.com → HTTP 401 ✓
[013] victim4@example.com → HTTP 403 ⛔ BLOCKED    ← Redis flag hit
[014] alice@example.com   → HTTP 403 ⛔ BLOCKED
```

---

## Observability

```bash
# Live Redis threat state
redis-cli keys "threat:*"
redis-cli get "threat:sample-app:ip:172.18.0.1"

# Kafka consumer lag
kafka-consumer-groups.sh --bootstrap-server localhost:9092 \
  --describe --group threat-analyzers

# Logs (structured JSON)
docker-compose logs -f gateway
docker-compose logs -f analyzer
```

Grafana dashboards (after first events): http://localhost:3001

---

## Security Considerations

- Gateway-to-analyzer communication is via Kafka (no direct calls)
- Redis keys include `applicationId` to prevent cross-tenant bleed
- Events never contain passwords, tokens, or raw credentials
- API key auth protects the HTTP event ingestion endpoint
- Redis `maxmemory-policy allkeys-lru` prevents OOM; oldest sliding-window entries are evicted first (graceful degradation)
- `failClosed=true` blocks requests when Redis is unavailable (strict mode)

---

## Limitations

1. **Eventual consistency**: First ~10 requests in a new attack pattern pass before detection
2. **Shared IP detection**: Users behind corporate NAT/VPN share IP signals
3. **BOLA completeness**: Requires `metadata.ownerUserId` for cross-ownership detection
4. **No persistent audit log**: Kafka retention (7 days) is the only long-term store
5. **Single Kafka cluster**: No geographic distribution in this implementation
6. **No ML**: Detection is threshold-based; sophisticated low-and-slow attacks may evade

---

## Future Roadmap

- [ ] Tenant-specific threshold configuration (per-applicationId YAML)
- [ ] Threat intelligence feed integration (known bad IPs/ASNs)
- [ ] Webhook notifications on threat detection
- [ ] Admin API to manually clear/set threat signals
- [ ] Anomaly-based detection (statistical deviation, not just thresholds)
- [ ] mTLS between gateway and analyzer
- [ ] OpenTelemetry tracing across gateway → Kafka → analyzer
- [ ] Multi-region Kafka replication

---


