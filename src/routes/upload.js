const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');

/**
 * ============================================
 * INSECURE FILE UPLOAD VULNERABILITIES
 * ============================================
 * 
 * These endpoints demonstrate unrestricted file upload attacks.
 * 
 * WHY THEY SUCCEED WITHOUT FIREWALL:
 * - No file type validation
 * - No file size restrictions
 * - Executable files allowed
 * - No content inspection
 * 
 * WHY FIREWALL/WAF BLOCKS THEM:
 * - Detects executable file extensions (.php, .jsp, .asp, .sh)
 * - Identifies webshell patterns
 * - Checks file content for malicious code
 * - Blocks double extension tricks
 */

// VULNERABLE: No file type restrictions
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, '../../uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    // VULNERABLE: Preserves original filename without sanitization
    cb(null, file.originalname);
  }
});

const upload = multer({ storage: storage });

// ============================================
// ENDPOINT 1: Unrestricted File Upload
// ============================================
// Attack: Upload file with .php, .jsp, .sh extension containing webshell
// Result: Executable code uploaded to server
router.post('/unrestricted', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  console.log(`[FILE UPLOAD] Unrestricted upload: ${req.file.originalname}`);

  res.json({
    success: true,
    message: 'File uploaded successfully',
    file: {
      name: req.file.originalname,
      size: req.file.size,
      path: req.file.path,
      mimetype: req.file.mimetype
    },
    vulnerability: 'Unrestricted file upload - any file type accepted',
    example_attack: 'Upload webshell.php or malicious.sh',
    note: 'Without firewall, this could be a webshell or backdoor',
    access_url: `/api/upload/files/${req.file.filename}`
  });
});

// ============================================
// ENDPOINT 2: Profile Picture Upload (Extension Bypass)
// ============================================
// Attack: Upload shell.php.jpg (double extension)
// Result: Bypasses weak client-side validation
router.post('/profile', upload.single('avatar'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No avatar uploaded' });
  }

  const filename = req.file.originalname;
  console.log(`[FILE UPLOAD] Profile upload: ${filename}`);

  // VULNERABLE: Only checks for image extension, not content
  const hasImageExtension = /\.(jpg|jpeg|png|gif)$/i.test(filename);

  res.json({
    success: true,
    message: hasImageExtension ? 'Avatar updated' : 'File uploaded (not an image)',
    file: {
      name: filename,
      size: req.file.size,
      appears_safe: hasImageExtension
    },
    vulnerability: 'Weak validation - checks extension only, not content',
    example_attack: 'Upload shell.php.jpg (double extension)',
    note: 'File extension checks are insufficient',
    access_url: `/api/upload/files/${req.file.filename}`
  });
});

// ============================================
// ENDPOINT 3: Document Upload (No Size Limit)
// ============================================
// Attack: Upload extremely large file to cause DoS
// Result: No size restrictions, can exhaust disk space
const unlimitedUpload = multer({ 
  storage: storage,
  limits: { fileSize: Infinity } // VULNERABLE: No size limit
});

router.post('/document', unlimitedUpload.single('doc'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No document uploaded' });
  }

  console.log(`[FILE UPLOAD] Document upload: ${req.file.originalname} (${req.file.size} bytes)`);

  res.json({
    success: true,
    message: 'Document uploaded',
    file: {
      name: req.file.originalname,
      size: req.file.size,
      size_mb: (req.file.size / 1024 / 1024).toFixed(2)
    },
    vulnerability: 'No file size restrictions - DoS possible',
    example_attack: 'Upload multi-GB file to exhaust disk space',
    note: 'Could fill up server storage'
  });
});

// ============================================
// ENDPOINT 4: Batch Upload (Multiple Files)
// ============================================
// Attack: Upload multiple malicious files at once
// Result: Multiple backdoors in one request
router.post('/batch', upload.array('files', 100), (req, res) => {
  if (!req.files || req.files.length === 0) {
    return res.status(400).json({ error: 'No files uploaded' });
  }

  console.log(`[FILE UPLOAD] Batch upload: ${req.files.length} files`);

  const uploadedFiles = req.files.map(file => ({
    name: file.originalname,
    size: file.size,
    path: file.path
  }));

  res.json({
    success: true,
    message: `${req.files.length} files uploaded`,
    files: uploadedFiles,
    vulnerability: 'Unrestricted batch upload',
    example_attack: 'Upload multiple webshells simultaneously',
    note: 'No rate limiting on uploads'
  });
});

// ============================================
// ENDPOINT 5: Access Uploaded Files
// ============================================
// Result: Direct access to uploaded files (including malicious ones)
router.get('/files/:filename', (req, res) => {
  const filename = req.params.filename;
  const filePath = path.join(__dirname, '../../uploads/', filename);

  console.log(`[FILE ACCESS] Accessing: ${filename}`);

  // VULNERABLE: Serves any uploaded file without restrictions
  if (fs.existsSync(filePath)) {
    res.sendFile(filePath);
  } else {
    res.status(404).json({ error: 'File not found' });
  }
});

// ============================================
// ENDPOINT 6: List Uploaded Files
// ============================================
// Result: Reveals all uploaded files
router.get('/list', (req, res) => {
  const uploadsDir = path.join(__dirname, '../../uploads');

  if (!fs.existsSync(uploadsDir)) {
    return res.json({ files: [] });
  }

  fs.readdir(uploadsDir, (err, files) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    const fileList = files.map(file => {
      const filePath = path.join(uploadsDir, file);
      const stats = fs.statSync(filePath);
      return {
        name: file,
        size: stats.size,
        uploaded: stats.birthtime,
        url: `/api/upload/files/${file}`
      };
    });

    res.json({
      count: fileList.length,
      files: fileList,
      vulnerability: 'Directory listing exposes uploaded files',
      note: 'Reveals all uploaded content including potential backdoors'
    });
  });
});

// Info endpoint
router.get('/', (req, res) => {
  res.json({
    category: 'Insecure File Upload Vulnerabilities',
    description: 'Demonstrates unrestricted file upload attacks',
    endpoints: {
      'POST /api/upload/unrestricted': 'Upload any file type',
      'POST /api/upload/profile': 'Upload with weak extension check',
      'POST /api/upload/document': 'Upload with no size limit',
      'POST /api/upload/batch': 'Upload multiple files',
      'GET /api/upload/files/:filename': 'Access uploaded files',
      'GET /api/upload/list': 'List all uploaded files'
    },
    dangerous_extensions: [
      '.php, .php3, .php4, .phtml (PHP webshells)',
      '.jsp, .jspx (Java webshells)',
      '.asp, .aspx (ASP webshells)',
      '.sh, .bash (Shell scripts)',
      '.py, .rb (Script interpreters)',
      '.exe, .bat (Windows executables)',
      '.war, .jar (Java archives)'
    ],
    example_attacks: {
      webshell: 'Upload backdoor.php with command execution code',
      double_extension: 'Upload shell.php.jpg to bypass validation',
      dos: 'Upload 10GB file to exhaust disk space',
      content_sniffing: 'Upload HTML/JS disguised as image',
      null_byte: 'Upload shell.php%00.jpg (null byte injection)'
    },
    webshell_example: '<?php system($_GET["cmd"]); ?>',
    firewall_detection: [
      'Executable file extensions',
      'Webshell code patterns',
      'Suspicious file content',
      'Double extensions',
      'Unusual MIME types',
      'Oversized uploads'
    ]
  });
});

module.exports = router;
