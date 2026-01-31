const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();

// Import vulnerable routes
const sqlRoutes = require('./routes/sql');
const xssRoutes = require('./routes/xss');
const commandRoutes = require('./routes/command');
const traversalRoutes = require('./routes/traversal');
const uploadRoutes = require('./routes/upload');
const bruteRoutes = require('./routes/brute');

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================
// INTENTIONALLY INSECURE MIDDLEWARE CONFIGURATION
// ============================================
// WARNING: No security headers, no CORS restrictions, no rate limiting
// This application is DESIGNED to be vulnerable for demo purposes

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static files (HTML, CSS, JS)
app.use(express.static(path.join(__dirname, '../public')));

// Initialize SQLite database
const db = new sqlite3.Database(':memory:');

// Seed vulnerable database
db.serialize(() => {
  // Users table with sensitive data
  db.run(`CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT,
    password TEXT,
    email TEXT,
    ssn TEXT,
    credit_card TEXT
  )`);

  db.run(`INSERT INTO users VALUES 
    (1, 'admin', 'admin123', 'admin@company.com', '123-45-6789', '4532-1234-5678-9010'),
    (2, 'john', 'password', 'john@company.com', '987-65-4321', '4716-5432-1098-7654'),
    (3, 'jane', 'letmein', 'jane@company.com', '555-12-3456', '5500-0000-0000-0004')`);

  // Products table
  db.run(`CREATE TABLE products (
    id INTEGER PRIMARY KEY,
    name TEXT,
    price REAL,
    stock INTEGER
  )`);

  db.run(`INSERT INTO products VALUES
    (1, 'Laptop', 999.99, 50),
    (2, 'Phone', 699.99, 100),
    (3, 'Tablet', 399.99, 75)`);

  // Comments table for stored XSS
  db.run(`CREATE TABLE comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    comment TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

// Make database available to routes
app.locals.db = db;

// ============================================
// VULNERABLE ROUTES
// ============================================
app.use('/api/sql', sqlRoutes);
app.use('/api/xss', xssRoutes);
app.use('/api/command', commandRoutes);
app.use('/api/traversal', traversalRoutes);
app.use('/api/upload', uploadRoutes);
app.use('/api/brute', bruteRoutes);

// API info endpoint
app.get('/api', (req, res) => {
  res.json({
    name: 'PreFirewall Lab API',
    tagline: 'See the risk before the firewall exists.',
    warning: '⚠️  This application is INTENTIONALLY VULNERABLE. Use only in isolated demo environments.',
    version: '1.0.0',
    endpoints: {
      sql_injection: '/api/sql/*',
      xss: '/api/xss/*',
      command_injection: '/api/command/*',
      path_traversal: '/api/traversal/*',
      file_upload: '/api/upload/*',
      brute_force: '/api/brute/*'
    },
    documentation: {
      readme: 'See README.md for setup instructions',
      demo_guide: 'See docs/demo-guide.md for demonstration workflow',
      postman: 'Import postman/PreFirewallLab.postman_collection.json'
    }
  });
});

// Start server
app.listen(PORT, () => {
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log('║          🔥 PreFirewall Lab - VULNERABLE BY DESIGN 🔥      ║');
  console.log('╠════════════════════════════════════════════════════════════╣');
  console.log(`║  Server running on http://localhost:${PORT}                   ║`);
  console.log('║                                                            ║');
  console.log('║  ⚠️  WARNING: This application contains intentional        ║');
  console.log('║     security vulnerabilities for demonstration purposes    ║');
  console.log('║                                                            ║');
  console.log('║  🛡️  Deploy firewall/WAF to block attacks                  ║');
  console.log('╚════════════════════════════════════════════════════════════╝');
  console.log('');
  console.log('Available attack endpoints:');
  console.log('  • SQL Injection:     /api/sql/*');
  console.log('  • XSS:               /api/xss/*');
  console.log('  • Command Injection: /api/command/*');
  console.log('  • Path Traversal:    /api/traversal/*');
  console.log('  • File Upload:       /api/upload/*');
  console.log('  • Brute Force:       /api/brute/*');
  console.log('');
});
