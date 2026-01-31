const express = require('express');
const router = express.Router();

/**
 * ============================================
 * BRUTE FORCE & RATE LIMITING VULNERABILITIES
 * ============================================
 * 
 * These endpoints demonstrate lack of rate limiting and brute force protection.
 * 
 * WHY THEY SUCCEED WITHOUT FIREWALL:
 * - No rate limiting on login attempts
 * - No account lockout mechanisms
 * - No CAPTCHA or anti-automation
 * - No request throttling
 * 
 * WHY FIREWALL/WAF BLOCKS THEM:
 * - Detects high request rates from single IP
 * - Identifies automated scanner patterns
 * - Blocks rapid repeated login attempts
 * - Recognizes credential stuffing patterns
 */

// Track login attempts (in-memory for demo)
const loginAttempts = {};
const apiCalls = {};

// ============================================
// ENDPOINT 1: Login Without Rate Limiting
// ============================================
// Attack: Automated brute force with tools like Hydra or Burp Intruder
// Result: Unlimited login attempts allowed
router.post('/login', (req, res) => {
  const { username, password } = req.body;
  const ip = req.ip;

  // Track attempts but don't enforce limits (VULNERABLE)
  if (!loginAttempts[ip]) {
    loginAttempts[ip] = { count: 0, attempts: [] };
  }
  loginAttempts[ip].count++;
  loginAttempts[ip].attempts.push({ username, timestamp: new Date() });

  console.log(`[BRUTE FORCE] Login attempt ${loginAttempts[ip].count} from ${ip}: ${username}`);

  // Hardcoded credentials for demo
  const validCredentials = [
    { username: 'admin', password: 'admin123' },
    { username: 'user', password: 'password' },
    { username: 'test', password: '12345' }
  ];

  const isValid = validCredentials.some(
    cred => cred.username === username && cred.password === password
  );

  if (isValid) {
    res.json({
      success: true,
      message: 'Login successful',
      token: 'demo-token-' + Date.now(),
      vulnerability: 'No rate limiting - brute force possible',
      attempts_from_your_ip: loginAttempts[ip].count
    });
  } else {
    // VULNERABLE: No lockout after failed attempts
    res.status(401).json({
      success: false,
      message: 'Invalid credentials',
      vulnerability: 'Unlimited login attempts allowed',
      attempts_from_your_ip: loginAttempts[ip].count,
      note: 'Tools like Hydra can try thousands of passwords'
    });
  }
});

// ============================================
// ENDPOINT 2: Password Reset Without CAPTCHA
// ============================================
// Attack: Automated password reset requests
// Result: Email flooding or account enumeration
router.post('/reset-password', (req, res) => {
  const { email } = req.body;
  const ip = req.ip;

  console.log(`[BRUTE FORCE] Password reset from ${ip}: ${email}`);

  // VULNERABLE: No CAPTCHA, no rate limiting
  const userExists = ['admin@company.com', 'user@company.com'].includes(email);

  // VULNERABLE: Reveals if user exists (account enumeration)
  if (userExists) {
    res.json({
      success: true,
      message: 'Password reset email sent',
      vulnerability: 'No CAPTCHA - automated requests possible',
      risk: 'Email flooding and account enumeration',
      note: 'Firewall can detect high request rate patterns'
    });
  } else {
    res.status(404).json({
      success: false,
      message: 'Email not found',
      vulnerability: 'Account enumeration - confirms user existence',
      note: 'Attacker can validate email addresses'
    });
  }
});

// ============================================
// ENDPOINT 3: API Without Rate Limiting
// ============================================
// Attack: Excessive API calls to cause DoS
// Result: No throttling, resource exhaustion possible
router.get('/api-call', (req, res) => {
  const ip = req.ip;

  if (!apiCalls[ip]) {
    apiCalls[ip] = { count: 0, first: new Date() };
  }
  apiCalls[ip].count++;

  const secondsElapsed = (new Date() - apiCalls[ip].first) / 1000;
  const callsPerSecond = (apiCalls[ip].count / secondsElapsed).toFixed(2);

  console.log(`[RATE LIMITING] API calls from ${ip}: ${apiCalls[ip].count} (${callsPerSecond}/sec)`);

  // VULNERABLE: No rate limiting enforcement
  res.json({
    success: true,
    data: { random: Math.random() },
    stats: {
      total_calls: apiCalls[ip].count,
      calls_per_second: callsPerSecond,
      elapsed_seconds: secondsElapsed.toFixed(2)
    },
    vulnerability: 'No rate limiting',
    note: 'Can be called unlimited times for DoS',
    firewall_would: 'Detect high request rate and block the IP'
  });
});

// ============================================
// ENDPOINT 4: User Enumeration
// ============================================
// Attack: Check if usernames exist by timing or error messages
// Result: Reveals valid usernames
router.post('/check-username', (req, res) => {
  const { username } = req.body;

  console.log(`[ENUMERATION] Username check: ${username}`);

  // VULNERABLE: Different responses for existing vs non-existing users
  const existingUsers = ['admin', 'john', 'jane', 'user', 'test'];
  const exists = existingUsers.includes(username);

  if (exists) {
    res.json({
      available: false,
      message: 'Username already taken',
      vulnerability: 'User enumeration - confirms username exists',
      note: 'Attacker can build list of valid usernames'
    });
  } else {
    res.json({
      available: true,
      message: 'Username available',
      vulnerability: 'User enumeration vulnerability',
      note: 'Different response times/messages reveal user existence'
    });
  }
});

// ============================================
// ENDPOINT 5: OTP/2FA Brute Force
// ============================================
// Attack: Brute force 6-digit OTP codes
// Result: No rate limiting on OTP verification
router.post('/verify-otp', (req, res) => {
  const { username, otp } = req.body;
  const ip = req.ip;

  console.log(`[BRUTE FORCE] OTP attempt from ${ip}: ${otp}`);

  // Hardcoded OTP for demo (NEVER do this in production)
  const validOTP = '123456';

  // VULNERABLE: No rate limiting on OTP attempts
  if (otp === validOTP) {
    res.json({
      success: true,
      message: 'OTP verified',
      vulnerability: '6-digit OTP can be brute forced (1 million combinations)',
      note: 'Without rate limiting, can try all codes quickly'
    });
  } else {
    res.status(401).json({
      success: false,
      message: 'Invalid OTP',
      vulnerability: 'No rate limiting on OTP verification',
      note: 'Attacker can try all 000000-999999',
      firewall_would: 'Block after suspicious number of attempts'
    });
  }
});

// ============================================
// ENDPOINT 6: Scanner Detection Test
// ============================================
// Attack: Automated security scanners (sqlmap, nikto, etc.)
// Result: No detection or blocking of scanner patterns
router.get('/admin', (req, res) => {
  const userAgent = req.get('User-Agent') || '';
  
  console.log(`[SCANNER] Access attempt with UA: ${userAgent}`);

  // Check for common scanner user agents (but don't block - VULNERABLE)
  const scannerPatterns = ['sqlmap', 'nikto', 'nmap', 'masscan', 'burp', 'acunetix', 'nessus'];
  const isScanner = scannerPatterns.some(pattern => 
    userAgent.toLowerCase().includes(pattern)
  );

  res.json({
    message: 'Admin panel',
    detected_scanner: isScanner,
    user_agent: userAgent,
    vulnerability: 'No scanner detection or blocking',
    note: isScanner ? 'Scanner detected but not blocked!' : 'Normal user agent',
    firewall_would: 'Block known scanner user-agents and patterns'
  });
});

// ============================================
// ENDPOINT 7: View Attack Statistics
// ============================================
router.get('/stats', (req, res) => {
  res.json({
    title: 'Attack Statistics (In-Memory)',
    login_attempts: Object.keys(loginAttempts).map(ip => ({
      ip: ip,
      attempts: loginAttempts[ip].count,
      latest_attempts: loginAttempts[ip].attempts.slice(-5)
    })),
    api_calls: Object.keys(apiCalls).map(ip => ({
      ip: ip,
      total_calls: apiCalls[ip].count,
      started: apiCalls[ip].first
    })),
    note: 'Without firewall, all this activity goes undetected and unblocked'
  });
});

// Info endpoint
router.get('/', (req, res) => {
  res.json({
    category: 'Brute Force & Rate Limiting Vulnerabilities',
    description: 'Demonstrates lack of rate limiting and brute force protection',
    endpoints: {
      'POST /api/brute/login': 'Login without rate limiting',
      'POST /api/brute/reset-password': 'Password reset without CAPTCHA',
      'GET /api/brute/api-call': 'API endpoint without throttling',
      'POST /api/brute/check-username': 'User enumeration',
      'POST /api/brute/verify-otp': 'OTP brute force',
      'GET /api/brute/admin': 'No scanner detection',
      'GET /api/brute/stats': 'View attack statistics'
    },
    attack_scenarios: {
      credential_stuffing: 'Test leaked username/password combinations',
      password_spraying: 'Try common passwords against many accounts',
      otp_brute_force: 'Try all 6-digit OTP combinations',
      account_enumeration: 'Identify valid usernames',
      api_abuse: 'Overwhelm API with requests',
      scanner_abuse: 'Automated vulnerability scanning'
    },
    tools: {
      hydra: 'THC-Hydra for brute force attacks',
      burp_intruder: 'Burp Suite Intruder for automated attacks',
      sqlmap: 'Automated SQL injection scanner',
      nikto: 'Web server scanner',
      ffuf: 'Fast web fuzzer'
    },
    firewall_detection: [
      'High request rate from single IP',
      'Repeated failed login attempts',
      'Known scanner user-agents',
      'Automated tool patterns',
      'Credential stuffing patterns'
    ]
  });
});

module.exports = router;
