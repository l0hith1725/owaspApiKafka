# Integration Guide

## Overview

The platform supports two integration patterns:

### Pattern 1: Reverse Proxy (Zero-code integration)
Deploy the gateway in front of your application. No code changes required.

### Pattern 2: HTTP Event API (SDK/middleware integration)
Your application posts security events directly. Use this when:
- You need richer resource context (ownerUserId for BOLA detection)
- Your app manages its own load balancer
- You want to use the platform as a detection-only service

---

## Pattern 1: Reverse Proxy

```
                      ┌─────────────┐
Internet ────────────▶│   Gateway   │────────────▶ Your App
         port 3000    │  :3000      │              :4000
                      └─────────────┘
```

Set `UPSTREAM_URL=http://your-app:4000` and point DNS to the gateway.

---

## Pattern 2: HTTP Event API

### Authentication
Include these headers on every request:
```
X-API-Key: <your-api-key>
X-Application-Id: <your-app-id>
```

### Endpoint
```
POST http://gateway:3000/platform/api/security-events
Content-Type: application/json
```

### Event Schema

**Mandatory fields:**
```json
{
  "requestId":    "uuid",
  "applicationId":"your-app",
  "timestamp":    "2024-01-01T00:00:00.000Z",
  "sourceIp":     "1.2.3.4",
  "httpMethod":   "POST",
  "path":         "/api/orders/123",
  "endpointId":   "POST:/api/orders/{id}",
  "statusCode":   200
}
```

**Optional enrichment (improves detection accuracy):**
```json
{
  "userId":             "user-123",
  "tenantId":           "tenant-456",
  "authenticationType": "JWT",
  "authSuccess":        true,
  "resourceType":       "order",
  "resourceId":         "123",
  "action":             "READ",
  "userAgent":          "Mozilla/5.0...",
  "requestDurationMs":  45,
  "metadata": {
    "ownerUserId":       "user-789",
    "isAuthEndpoint":    false
  }
}
```

---

## Node.js / Express Integration Example

```javascript
const axios = require('axios');

function securityEventMiddleware(req, res, next) {
  const start = Date.now();
  res.on('finish', () => {
    const event = {
      requestId:    require('crypto').randomUUID(),
      applicationId:'my-express-app',
      timestamp:    new Date().toISOString(),
      sourceIp:     req.ip,
      httpMethod:   req.method,
      path:         req.path,
      endpointId:   `${req.method}:${req.route?.path || req.path}`,
      statusCode:   res.statusCode,
      userId:       req.user?.id || null,
      authSuccess:  req.user ? true : (res.statusCode === 401 ? false : null),
      resourceType: req.resourceType || null,
      resourceId:   req.resourceId   || null,
      action:       req.action       || null,
      userAgent:    req.headers['user-agent'],
      requestDurationMs: Date.now() - start,
      metadata:     req.securityMeta || {},
    };

    // Non-blocking
    axios.post('http://gateway:3000/platform/api/security-events', event, {
      headers: { 'X-API-Key': 'my-api-key', 'X-Application-Id': 'my-express-app' },
    }).catch(() => {});
  });
  next();
}
```

---

## Spring Boot Integration Example

```java
@Component
public class SecurityEventFilter implements Filter {
    private final RestTemplate restTemplate;

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest  httpReq = (HttpServletRequest)  req;
        HttpServletResponse httpRes = (HttpServletResponse) res;
        long start = System.currentTimeMillis();

        chain.doFilter(req, res);

        // Post-request: publish event asynchronously
        CompletableFuture.runAsync(() -> {
            Map<String, Object> event = new HashMap<>();
            event.put("requestId",     UUID.randomUUID().toString());
            event.put("applicationId", "my-spring-app");
            event.put("timestamp",     Instant.now().toString());
            event.put("sourceIp",      httpReq.getRemoteAddr());
            event.put("httpMethod",    httpReq.getMethod());
            event.put("path",          httpReq.getRequestURI());
            event.put("endpointId",    httpReq.getMethod() + ":" + httpReq.getRequestURI());
            event.put("statusCode",    httpRes.getStatus());
            event.put("requestDurationMs", System.currentTimeMillis() - start);

            HttpHeaders headers = new HttpHeaders();
            headers.set("X-API-Key",        "my-api-key");
            headers.set("X-Application-Id", "my-spring-app");

            restTemplate.postForEntity(
                "http://gateway:3000/platform/api/security-events",
                new HttpEntity<>(event, headers),
                String.class
            );
        });
    }
}
```

---

## Python / FastAPI Integration Example

```python
import httpx
import asyncio
import uuid
from datetime import datetime, timezone
from fastapi import Request

async def security_event_middleware(request: Request, call_next):
    import time
    start = time.time()
    response = await call_next(request)
    duration_ms = int((time.time() - start) * 1000)

    event = {
        "requestId":        str(uuid.uuid4()),
        "applicationId":    "my-fastapi-app",
        "timestamp":        datetime.now(timezone.utc).isoformat(),
        "sourceIp":         request.client.host,
        "httpMethod":       request.method,
        "path":             request.url.path,
        "endpointId":       f"{request.method}:{request.url.path}",
        "statusCode":       response.status_code,
        "userId":           getattr(request.state, "user_id", None),
        "requestDurationMs": duration_ms,
    }

    asyncio.create_task(publish_event(event))
    return response

async def publish_event(event: dict):
    async with httpx.AsyncClient() as client:
        try:
            await client.post(
                "http://gateway:3000/platform/api/security-events",
                json=event,
                headers={"X-API-Key": "my-api-key", "X-Application-Id": "my-fastapi-app"},
                timeout=2.0,
            )
        except Exception:
            pass  # Non-blocking; platform failure must not affect app
```

---

## Go Integration Example

```go
func SecurityEventMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        start := time.Now()
        wrapped := &responseWriter{ResponseWriter: w, statusCode: 200}
        next.ServeHTTP(wrapped, r)

        go publishEvent(map[string]interface{}{
            "requestId":        uuid.New().String(),
            "applicationId":    "my-go-app",
            "timestamp":        time.Now().UTC().Format(time.RFC3339Nano),
            "sourceIp":         r.RemoteAddr,
            "httpMethod":       r.Method,
            "path":             r.URL.Path,
            "endpointId":       r.Method + ":" + r.URL.Path,
            "statusCode":       wrapped.statusCode,
            "requestDurationMs": time.Since(start).Milliseconds(),
        })
    })
}
```

---

## Adding a New Analyzer

1. Create `analyzers/src/analyzers/MyNewAnalyzer.js` extending `ThreatAnalyzer`
2. Implement `async analyze(event) → ThreatDetectionResult`
3. Register in `AnalyzerOrchestrator.initialize()`
4. Add config key in `analyzers/src/config.js`
5. Write unit tests in `tests/unit/MyNewAnalyzer.test.js`

No changes needed to the gateway, Kafka topics, or Redis schema.
