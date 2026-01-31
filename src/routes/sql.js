const express = require('express');
const router = express.Router();

/**
 * ============================================
 * SQL INJECTION VULNERABILITIES
 * ============================================
 * 
 * These endpoints demonstrate classic SQL injection attacks.
 * 
 * WHY THEY SUCCEED WITHOUT FIREWALL:
 * - Direct string concatenation into SQL queries
 * - No input validation or sanitization
 * - No parameterized queries
 * 
 * WHY FIREWALL/WAF BLOCKS THEM:
 * - Detects SQL keywords (UNION, SELECT, OR, --)
 * - Identifies SQL comment patterns
 * - Recognizes UNION-based injection signatures
 * - Catches boolean-based injection patterns
 */

// ============================================
// ENDPOINT 1: Search Users (Classic SQLi)
// ============================================
// Attack: GET /api/sql/users?username=admin' OR '1'='1
// Result: Returns all users bypassing authentication logic
router.get('/users', (req, res) => {
  const username = req.query.username;
  const db = req.app.locals.db;

  // VULNERABLE: Direct string concatenation
  const query = `SELECT * FROM users WHERE username = '${username}'`;

  console.log(`[SQL INJECTION ATTEMPT] Query: ${query}`);

  db.all(query, [], (err, rows) => {
    if (err) {
      return res.status(500).json({ 
        error: err.message,
        note: 'SQL error exposed - information leakage'
      });
    }
    res.json({ 
      success: true, 
      users: rows,
      vulnerability: 'SQL Injection via username parameter',
      example_attack: "?username=admin' OR '1'='1"
    });
  });
});

// ============================================
// ENDPOINT 2: Login (Authentication Bypass)
// ============================================
// Attack: POST /api/sql/login with {"username": "admin' --", "password": "anything"}
// Result: Bypasses password check via SQL comment
router.post('/login', (req, res) => {
  const { username, password } = req.body;
  const db = req.app.locals.db;

  // VULNERABLE: No prepared statements
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

  console.log(`[SQL INJECTION ATTEMPT] Login query: ${query}`);

  db.get(query, [], (err, row) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (row) {
      res.json({ 
        success: true, 
        message: 'Login successful',
        user: row,
        vulnerability: 'Authentication bypass via SQL injection',
        example_attack: '{"username": "admin\' --", "password": "anything"}'
      });
    } else {
      res.status(401).json({ 
        success: false, 
        message: 'Invalid credentials'
      });
    }
  });
});

// ============================================
// ENDPOINT 3: Product Search (UNION-based SQLi)
// ============================================
// Attack: GET /api/sql/products?id=1 UNION SELECT id,username,password,email FROM users--
// Result: Extracts user data through product search
router.get('/products', (req, res) => {
  const productId = req.query.id;
  const db = req.app.locals.db;

  // VULNERABLE: Perfect for UNION-based injection
  const query = `SELECT id, name, price, stock FROM products WHERE id = ${productId}`;

  console.log(`[SQL INJECTION ATTEMPT] Product query: ${query}`);

  db.all(query, [], (err, rows) => {
    if (err) {
      return res.status(500).json({ 
        error: err.message,
        note: 'Error reveals table structure'
      });
    }
    res.json({ 
      success: true, 
      products: rows,
      vulnerability: 'UNION-based SQL injection',
      example_attack: '?id=1 UNION SELECT id,username,password,email FROM users--'
    });
  });
});

// ============================================
// ENDPOINT 4: Order Lookup (Error-based SQLi)
// ============================================
// Attack: GET /api/sql/order?id=1' AND 1=CAST((SELECT password FROM users LIMIT 1) AS INT)--
// Result: Extracts data through error messages
router.get('/order', (req, res) => {
  const orderId = req.query.id;
  const db = req.app.locals.db;

  // VULNERABLE: Exposes detailed errors
  const query = `SELECT * FROM products WHERE id = '${orderId}'`;

  console.log(`[SQL INJECTION ATTEMPT] Order query: ${query}`);

  db.all(query, [], (err, rows) => {
    if (err) {
      // VULNERABLE: Detailed error disclosure
      return res.status(500).json({ 
        error: err.message,
        query: query, // Exposes the actual query
        vulnerability: 'Error-based SQL injection with info leakage',
        example_attack: "?id=1' AND 1=CAST((SELECT password FROM users LIMIT 1) AS INT)--"
      });
    }
    res.json({ 
      success: true, 
      results: rows
    });
  });
});

// ============================================
// ENDPOINT 5: Blind SQLi (Time-based)
// ============================================
// Attack: GET /api/sql/check?user=admin' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE (1/0) END)--
// Result: Boolean-based blind SQL injection
router.get('/check', (req, res) => {
  const user = req.query.user;
  const db = req.app.locals.db;

  // VULNERABLE: Enables blind SQL injection
  const query = `SELECT COUNT(*) as count FROM users WHERE username = '${user}'`;

  console.log(`[SQL INJECTION ATTEMPT] Blind SQLi query: ${query}`);

  db.get(query, [], (err, row) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ 
      exists: row.count > 0,
      vulnerability: 'Blind SQL injection (boolean-based)',
      example_attack: "?user=admin' AND '1'='1",
      note: 'Attackers can extract data bit by bit'
    });
  });
});

// Info endpoint
router.get('/', (req, res) => {
  res.json({
    category: 'SQL Injection Vulnerabilities',
    description: 'Demonstrates various SQL injection attack vectors',
    endpoints: {
      'GET /api/sql/users?username=': 'Classic SQLi - authentication bypass',
      'POST /api/sql/login': 'Login bypass with comment injection',
      'GET /api/sql/products?id=': 'UNION-based data extraction',
      'GET /api/sql/order?id=': 'Error-based SQL injection',
      'GET /api/sql/check?user=': 'Blind SQL injection'
    },
    example_payloads: {
      classic: "admin' OR '1'='1",
      comment: "admin' --",
      union: "1 UNION SELECT id,username,password,email FROM users--",
      boolean: "admin' AND '1'='1"
    },
    firewall_detection: [
      'SQL keywords (SELECT, UNION, OR)',
      'SQL comment patterns (-- , /*)',
      'Boolean expressions',
      'String concatenation patterns'
    ]
  });
});

module.exports = router;
