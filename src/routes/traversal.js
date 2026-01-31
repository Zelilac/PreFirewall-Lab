const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');

/**
 * ============================================
 * PATH TRAVERSAL VULNERABILITIES
 * ============================================
 * 
 * These endpoints demonstrate directory traversal attacks.
 * 
 * WHY THEY SUCCEED WITHOUT FIREWALL:
 * - No path sanitization or validation
 * - Direct use of user input in file system operations
 * - No restriction on directory access
 * 
 * WHY FIREWALL/WAF BLOCKS THEM:
 * - Detects ../ and ..\ patterns
 * - Identifies encoded traversal sequences (%2e%2e%2f)
 * - Catches absolute path attempts
 * - Recognizes sensitive file access patterns (/etc/passwd, etc.)
 */

// ============================================
// ENDPOINT 1: File Download (Classic Traversal)
// ============================================
// Attack: GET /api/traversal/download?file=../../../../etc/passwd
// Result: Access files outside intended directory
router.get('/download', (req, res) => {
  const filename = req.query.file || 'sample.txt';

  console.log(`[PATH TRAVERSAL ATTEMPT] Download: ${filename}`);

  // VULNERABLE: No path validation
  const filePath = path.join(__dirname, '../data/', filename);

  console.log(`[PATH TRAVERSAL] Resolved path: ${filePath}`);

  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      return res.status(404).json({ 
        error: 'File not found',
        attempted_path: filePath,
        vulnerability: 'Path traversal - attempted to read: ' + filename,
        example_attack: '?file=../../../../etc/passwd'
      });
    }
    res.json({
      filename: filename,
      content: data,
      vulnerability: 'Path Traversal - unrestricted file access',
      note: 'Can read any file the process has access to'
    });
  });
});

// ============================================
// ENDPOINT 2: View File (Absolute Path)
// ============================================
// Attack: GET /api/traversal/view?path=/etc/passwd
// Result: Direct absolute path access
router.get('/view', (req, res) => {
  const filePath = req.query.path;

  if (!filePath) {
    return res.status(400).json({ error: 'path parameter required' });
  }

  console.log(`[PATH TRAVERSAL ATTEMPT] View: ${filePath}`);

  // VULNERABLE: Allows absolute paths
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      return res.status(404).json({ 
        error: err.message,
        attempted_path: filePath,
        vulnerability: 'Direct file system access'
      });
    }
    res.send(`
      <html>
        <head><title>File Viewer</title></head>
        <body>
          <h1>File: ${filePath}</h1>
          <p style="color: red;">⚠️ Path Traversal Vulnerability</p>
          <pre>${data}</pre>
        </body>
      </html>
    `);
  });
});

// ============================================
// ENDPOINT 3: Log Viewer (Encoded Traversal)
// ============================================
// Attack: GET /api/traversal/logs?name=....//....//etc/passwd
// Result: Double encoding and alternate separators
router.get('/logs', (req, res) => {
  const logName = req.query.name || 'app.log';

  console.log(`[PATH TRAVERSAL ATTEMPT] Logs: ${logName}`);

  // VULNERABLE: No decoding or normalization
  const logPath = path.join(__dirname, '../data/logs/', logName);

  console.log(`[PATH TRAVERSAL] Log path: ${logPath}`);

  fs.readFile(logPath, 'utf8', (err, data) => {
    if (err) {
      return res.json({ 
        error: 'Log file not found',
        path: logPath,
        vulnerability: 'Path traversal with alternate encoding',
        example_attack: '?name=....//....//etc/passwd'
      });
    }
    res.json({
      log: logName,
      content: data,
      vulnerability: 'Path traversal - no encoding detection'
    });
  });
});

// ============================================
// ENDPOINT 4: Backup File Access
// ============================================
// Attack: GET /api/traversal/backup?file=../../../../../../etc/shadow
// Result: Access to sensitive system files
router.get('/backup', (req, res) => {
  const backupFile = req.query.file || 'backup.zip';

  console.log(`[PATH TRAVERSAL ATTEMPT] Backup: ${backupFile}`);

  // VULNERABLE: Path concatenation without validation
  const backupPath = './backups/' + backupFile;

  fs.stat(backupPath, (err, stats) => {
    if (err) {
      return res.status(404).json({
        error: 'Backup file not found',
        path: backupPath,
        vulnerability: 'Path traversal via file parameter',
        example_attack: '?file=../../../etc/shadow',
        note: 'Could access sensitive backup files or system files'
      });
    }
    res.json({
      file: backupFile,
      size: stats.size,
      vulnerability: 'Unrestricted backup file access',
      note: 'Firewall would detect ../ pattern'
    });
  });
});

// ============================================
// ENDPOINT 5: Config File Reader
// ============================================
// Attack: POST /api/traversal/config with {"filename": "../../../package.json"}
// Result: Read configuration files
router.post('/config', (req, res) => {
  const configFile = req.body.filename || 'app.conf';

  console.log(`[PATH TRAVERSAL ATTEMPT] Config: ${configFile}`);

  // VULNERABLE: POST parameter path traversal
  const configPath = path.join(__dirname, '../data/config/', configFile);

  console.log(`[PATH TRAVERSAL] Config path: ${configPath}`);

  fs.readFile(configPath, 'utf8', (err, data) => {
    if (err) {
      return res.status(404).json({
        error: 'Config file not found',
        path: configPath,
        vulnerability: 'Path traversal in POST body',
        example_attack: '{"filename": "../../../package.json"}'
      });
    }
    res.json({
      config: configFile,
      content: data,
      vulnerability: 'Configuration file traversal',
      note: 'Can read any accessible configuration file'
    });
  });
});

// ============================================
// ENDPOINT 6: Directory Listing
// ============================================
// Attack: GET /api/traversal/list?dir=../../
// Result: List contents of parent directories
router.get('/list', (req, res) => {
  const directory = req.query.dir || '.';

  console.log(`[PATH TRAVERSAL ATTEMPT] List directory: ${directory}`);

  // VULNERABLE: Directory traversal
  const dirPath = path.join(__dirname, '../data/', directory);

  console.log(`[PATH TRAVERSAL] Directory path: ${dirPath}`);

  fs.readdir(dirPath, (err, files) => {
    if (err) {
      return res.status(404).json({
        error: 'Directory not found',
        path: dirPath,
        vulnerability: 'Directory traversal',
        example_attack: '?dir=../../'
      });
    }
    res.json({
      directory: directory,
      files: files,
      full_path: dirPath,
      vulnerability: 'Unrestricted directory listing',
      note: 'Reveals directory structure'
    });
  });
});

// Info endpoint
router.get('/', (req, res) => {
  res.json({
    category: 'Path Traversal Vulnerabilities',
    description: 'Demonstrates directory traversal and unauthorized file access',
    endpoints: {
      'GET /api/traversal/download?file=': 'File download with path traversal',
      'GET /api/traversal/view?path=': 'Direct file viewer with absolute paths',
      'GET /api/traversal/logs?name=': 'Log viewer with encoded traversal',
      'GET /api/traversal/backup?file=': 'Backup file access',
      'POST /api/traversal/config': 'Configuration file reader',
      'GET /api/traversal/list?dir=': 'Directory listing'
    },
    example_payloads: {
      basic: '../../../etc/passwd',
      windows: '..\\..\\..\\windows\\system32\\config\\sam',
      encoded: '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
      double_encoded: '%252e%252e%252f',
      alternate: '....//....//etc/passwd',
      absolute_linux: '/etc/passwd',
      absolute_windows: 'C:\\Windows\\System32\\config\\sam'
    },
    sensitive_files: [
      '/etc/passwd (Linux users)',
      '/etc/shadow (Linux passwords)',
      '~/.ssh/id_rsa (SSH keys)',
      'C:\\Windows\\System32\\config\\SAM (Windows passwords)',
      '/var/www/html/.htpasswd (Web passwords)',
      'package.json (Application config)',
      '.env (Environment variables)'
    ],
    firewall_detection: [
      '../ (dot-dot-slash)',
      '..\\ (dot-dot-backslash)',
      'Encoded traversal sequences',
      'Absolute path attempts',
      'Sensitive file patterns'
    ]
  });
});

module.exports = router;
