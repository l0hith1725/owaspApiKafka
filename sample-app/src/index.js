'use strict';

/**
 * Sample Demo Application
 *
 * A small Express app that demonstrates integration with the threat platform
 * via BOTH integration mechanisms:
 *   1. It sits behind the reverse proxy gateway (all traffic goes through gateway first).
 *   2. It also enriches events via req.securityMetadata (added by gateway middleware).
 *
 * INTENTIONALLY VULNERABLE endpoints are included ONLY for demonstration.
 * DO NOT use this in production.
 *
 * The same integration pattern works for Spring Boot, Python/FastAPI, Go, .NET:
 *   - Run each behind the gateway proxy, OR
 *   - POST events to /platform/api/security-events using your framework's middleware.
 */

require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.set('trust proxy', true);

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-prod';
const PORT = process.env.PORT || 4000;

// ── Simulated user database ───────────────────────────────────────────────────
const USERS = {
  'user-1': { id: 'user-1', email: 'alice@example.com', password: 'password123', balance: 1000 },
  'user-2': { id: 'user-2', email: 'bob@example.com',   password: 'pass456',     balance: 500  },
  'user-3': { id: 'user-3', email: 'carol@example.com', password: 'carol789',    balance: 750  },
};

const ORDERS = {
  '1': { id: '1', userId: 'user-1', amount: 50,  item: 'Widget' },
  '2': { id: '2', userId: 'user-1', amount: 120, item: 'Gadget' },
  '3': { id: '3', userId: 'user-2', amount: 30,  item: 'Doohickey' },
  '4': { id: '4', userId: 'user-3', amount: 200, item: 'Thingamajig' },
};

// ── Auth middleware ───────────────────────────────────────────────────────────
function optionalAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return next();
  try {
    const token = header.replace('Bearer ', '');
    req.user = jwt.verify(token, JWT_SECRET);
  } catch {}
  next();
}

function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

app.use(optionalAuth);

// ── Authentication endpoints ──────────────────────────────────────────────────
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  const user = Object.values(USERS).find(u => u.email === email);

  if (!user || user.password !== password) {
    // Tag for the gateway middleware — enriches the security event
    req.securityMetadata = { targetEmail: email, isAuthEndpoint: true };
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
  req.securityMetadata = { isAuthEndpoint: true };
  res.json({ token, userId: user.id });
});

// ── Orders — intentionally missing authorization check (BOLA demo) ────────────
app.get('/api/orders/:orderId', requireAuth, (req, res) => {
  const order = ORDERS[req.params.orderId];
  if (!order) return res.status(404).json({ error: 'Order not found' });

  // BOLA: No ownership check! Any authenticated user can read any order.
  // The platform detects this by tracking cross-ownership access.
  req.resourceType   = 'order';
  req.resourceId     = req.params.orderId;
  req.resourceAction = 'READ';
  req.securityMetadata = { ownerUserId: order.userId };

  res.json(order);
});

app.get('/api/orders', requireAuth, (req, res) => {
  const myOrders = Object.values(ORDERS).filter(o => o.userId === req.user.id);
  res.json(myOrders);
});

// ── Payment methods ───────────────────────────────────────────────────────────
const paymentMethods = {};
app.post('/api/payment-methods', requireAuth, (req, res) => {
  const { cardLast4, cardType } = req.body || {};
  if (!paymentMethods[req.user.id]) paymentMethods[req.user.id] = [];
  paymentMethods[req.user.id].push({ cardLast4, cardType, id: Date.now().toString() });
  res.status(201).json({ added: true });
});

// ── Account update ────────────────────────────────────────────────────────────
app.patch('/api/account', requireAuth, (req, res) => {
  res.json({ updated: true, userId: req.user.id });
});

// ── Transfers (business flow demo) ───────────────────────────────────────────
app.post('/api/transfers', requireAuth, (req, res) => {
  const { toUserId, amount } = req.body || {};
  const user = USERS[req.user.id];
  if (!user || user.balance < amount) {
    return res.status(400).json({ error: 'Insufficient balance' });
  }
  user.balance -= amount;
  res.json({ transferred: amount, toUserId, newBalance: user.balance });
});

// ── OTP endpoints (OTP abuse flow demo) ──────────────────────────────────────
app.post('/api/otp/generate', requireAuth, (req, res) => {
  res.json({ sent: true, to: req.user.email });
});

app.post('/api/otp/verify', requireAuth, (req, res) => {
  const { otp } = req.body || {};
  res.json({ valid: otp === '123456' });
});

// ── Health ────────────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', service: 'sample-app' }));

app.listen(PORT, () => {
  console.log(JSON.stringify({ level: 'info', msg: `Sample app listening on :${PORT}`, time: new Date().toISOString() }));
});
