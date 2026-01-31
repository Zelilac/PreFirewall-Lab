# PreFirewall Lab

> **"See the risk before the firewall exists."**

<p align="center">
  <img src="https://img.shields.io/badge/purpose-security%20demo-red" alt="Purpose: Security Demo">
  <img src="https://img.shields.io/badge/status-intentionally%20vulnerable-critical" alt="Intentionally Vulnerable">
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="License">
</p>

## ⚠️ CRITICAL WARNING

**PreFirewall Lab is an INTENTIONALLY VULNERABLE web application created exclusively for:**

- ✅ Pre-firewall security demonstrations
- ✅ SOC team training
- ✅ Security awareness presentations
- ✅ Firewall/WAF effectiveness demonstrations
- ✅ Security consulting and education

**DO NOT:**
- ❌ Deploy on production networks
- ❌ Expose to the internet without isolation
- ❌ Use in environments with sensitive data
- ❌ Assume any security best practices are followed

**You are responsible for:**
- Using this application only in isolated lab environments
- Ensuring compliance with all applicable laws and regulations
- Obtaining proper authorization before demonstrating attacks
- Understanding that this code violates security principles by design

---

## 🎯 Project Overview

PreFirewall Lab is a deliberately vulnerable Node.js web application designed to showcase what happens to unprotected systems **BEFORE** firewall or WAF deployment. 

This is **NOT** about bypassing security controls. This is about demonstrating the **necessity** of firewalls and WAFs by showing dramatic before-and-after scenarios.

### Key Features

- **Realistic Attack Vectors**: SQL injection, XSS, command injection, path traversal, insecure uploads, and brute force
- **Firewall-Friendly Design**: Attacks generate obvious, noisy patterns that firewalls/WAFs easily detect
- **Demo-Ready**: Simple, repeatable attacks via browser, curl, or Postman
- **Vendor-Neutral**: Works with FortiGate, Palo Alto, Check Point, SonicWall, ModSecurity, etc.
- **Educational**: Each endpoint includes comments explaining the vulnerability and why firewalls block it

---

## 🏗️ Architecture

```
PreFirewall-Lab/
├── src/
│   ├── index.js              # Main server
│   └── routes/
│       ├── sql.js            # SQL Injection vulnerabilities
│       ├── xss.js            # Cross-Site Scripting
│       ├── command.js        # Command Injection
│       ├── traversal.js      # Path Traversal
│       ├── upload.js         # Insecure File Upload
│       └── brute.js          # Brute Force / No Rate Limiting
├── docs/
│   └── demo-guide.md         # Step-by-step demo instructions
├── postman/
│   └── PreFirewallLab.postman_collection.json
├── package.json
└── README.md
```

---

## 🚀 Quick Start

### Prerequisites

- Node.js (v14 or higher)
- npm or yarn
- Isolated lab environment

### Installation

```bash
# Clone or download the repository
cd PreFirewall-Lab

# Install dependencies
npm install

# Start the vulnerable application
npm start
```

The application will start on `http://localhost:3000`

### Docker Deployment (Optional)

```bash
# Build image
docker build -t prefirewall-lab .

# Run container
docker run -p 3000:3000 prefirewall-lab
```

---

## 🎭 Attack Categories

### 1. SQL Injection
**Endpoints**: `/api/sql/*`

- Classic `OR '1'='1` bypass
- Comment-based authentication bypass (`admin' --`)
- UNION-based data extraction
- Error-based SQL injection
- Blind SQL injection

**Why Firewall Blocks**: Detects SQL keywords, comment patterns, UNION operators

### 2. Cross-Site Scripting (XSS)
**Endpoints**: `/api/xss/*`

- Reflected XSS via search parameters
- Stored XSS in comments
- DOM-based XSS
- JavaScript context injection

**Why Firewall Blocks**: Detects `<script>` tags, event handlers (`onerror`, `onload`), `javascript:` protocol

### 3. Command Injection
**Endpoints**: `/api/command/*`

- Semicolon command chaining
- Pipe operator injection
- Backtick substitution
- `$()` command substitution

**Why Firewall Blocks**: Recognizes shell metacharacters, command patterns

### 4. Path Traversal
**Endpoints**: `/api/traversal/*`

- `../` directory traversal
- Absolute path access
- Encoded traversal sequences
- Configuration file access

**Why Firewall Blocks**: Detects `../` patterns, encoded versions, sensitive file paths

### 5. Insecure File Upload
**Endpoints**: `/api/upload/*`

- Unrestricted file types (webshells)
- No size limits
- Executable content
- Direct file access

**Why Firewall Blocks**: Detects executable extensions (`.php`, `.jsp`), webshell patterns

### 6. Brute Force / No Rate Limiting
**Endpoints**: `/api/brute/*`

- Unlimited login attempts
- No CAPTCHA
- OTP brute force
- Scanner detection failure

**Why Firewall Blocks**: Identifies high request rates, scanner user-agents, automated patterns

---

## 📬 Postman Collection

A complete Postman collection with pre-filled attack payloads is included:

1. Import `postman/PreFirewallLab.postman_collection.json` into Postman
2. Set the `baseUrl` variable to `http://localhost:3000`
3. Execute requests to trigger vulnerabilities
4. Each request includes descriptions and example attacks

**Collection Features**:
- 30+ attack requests
- Pre-configured malicious payloads
- Organized by vulnerability category
- Ready for demo presentations

---

## 🎪 Demo Workflow

### Phase 1: Pre-Firewall (Vulnerable)

1. **Deploy PreFirewall Lab** in isolated environment
2. **Execute attacks** using Postman or browser:
   - SQL injection successfully extracts passwords
   - XSS executes malicious scripts
   - Command injection runs OS commands
   - Path traversal reads `/etc/passwd`
3. **Show the impact**: Data breach, system compromise, account takeover

### Phase 2: Post-Firewall (Protected)

1. **Deploy firewall/WAF** in front of the application
2. **Re-run identical attacks**
3. **Demonstrate blocking**:
   - Attacks blocked with 403 Forbidden
   - Firewall logs show attack attempts
   - Alerts generated in SIEM
   - Application remains protected

### Phase 3: Analysis

- Review firewall logs and alerts
- Correlate attacks with signatures
- Show before/after metrics
- Discuss ROI and risk reduction

**See [docs/demo-guide.md](docs/demo-guide.md) for detailed instructions**

---

## 📊 Example Attacks

### SQL Injection
```bash
# Browser/curl
curl "http://localhost:3000/api/sql/users?username=admin' OR '1'='1"

# Result: Returns all users bypassing authentication
```

### XSS
```bash
curl "http://localhost:3000/api/xss/search?q=<script>alert('XSS')</script>"

# Result: JavaScript executes in response
```

### Command Injection
```bash
curl -X POST http://localhost:3000/api/command/ping \
  -H "Content-Type: application/json" \
  -d '{"host": "127.0.0.1; whoami"}'

# Result: Executes whoami command
```

### Path Traversal
```bash
curl "http://localhost:3000/api/traversal/download?file=../../../../etc/passwd"

# Result: Returns /etc/passwd contents
```

---

## 🛡️ Firewall Integration Examples

### FortiGate
- Enable IPS signatures for SQL injection, XSS
- Configure WAF profiles
- Set up attack logs and alerts

### Palo Alto
- Enable Threat Prevention
- Configure security profiles
- Review threat logs

### ModSecurity (OWASP Core Rule Set)
```apache
SecRuleEngine On
Include /path/to/owasp-crs/crs-setup.conf
Include /path/to/owasp-crs/rules/*.conf
```

### AWS WAF
- Create rules for SQL injection
- Add XSS protection rules
- Configure rate limiting

---

## 📖 Documentation

- **[Demo Guide](docs/demo-guide.md)**: Complete demo walkthrough with talking points
- **[API Documentation](http://localhost:3000/)**: Interactive endpoint overview (when server is running)
- **Postman Collection**: Pre-built attack requests

---

## 🔧 Configuration

### Environment Variables

```bash
PORT=3000                    # Server port (default: 3000)
```

### Customization

- Modify route files in `src/routes/` to add custom vulnerabilities
- Update database seed data in `src/index.js`
- Adjust attack payloads in Postman collection

---

## ⚖️ Legal & Ethical Disclaimer

**READ THIS CAREFULLY**

This application is provided for **LEGAL SECURITY TESTING AND EDUCATION ONLY**.

By using PreFirewall Lab, you agree:

1. **Authorization**: You will only use this tool on systems you own or have explicit written permission to test
2. **Compliance**: You are responsible for complying with all applicable laws, regulations, and organizational policies
3. **No Warranty**: This software is provided "AS IS" without any warranties
4. **Liability**: The authors are not responsible for any misuse or damage caused by this tool
5. **Intended Use**: This tool is for demonstrating firewall effectiveness, NOT for malicious purposes

**Unauthorized access to computer systems is illegal in most jurisdictions (Computer Fraud and Abuse Act in the USA, Computer Misuse Act in the UK, etc.)**

**Use responsibly and ethically.**

---

## 🤝 Contributing

This is an educational project. Contributions that enhance its demo/training value are welcome:

- Additional vulnerability examples
- Improved documentation
- Firewall configuration guides
- Demo scenarios

---

## 📜 License

MIT License - See LICENSE file for details

**Remember**: This license applies to the code, not permission to attack systems.

---

## 🙏 Acknowledgments

This project is inspired by the need for effective security demonstrations that:
- Show real risks to management
- Train SOC teams
- Prove firewall/WAF value
- Educate developers on secure coding

Built with educational intent and defensive security in mind.

---

## 📞 Support

For questions about using PreFirewall Lab for security training or demos:

- Review the [Demo Guide](docs/demo-guide.md)
- Check endpoint documentation at `http://localhost:3000/`
- Examine route files for vulnerability details

---

## 🎓 Educational Value

PreFirewall Lab teaches:

1. **Common Web Vulnerabilities**: OWASP Top 10 attack vectors
2. **Attack Techniques**: How attackers exploit weaknesses
3. **Detection Patterns**: What firewalls/WAFs look for
4. **Defense Strategies**: Why layered security matters
5. **Risk Communication**: Demonstrating impact to stakeholders

**Use this knowledge to build more secure systems, not to attack them.**

---

<p align="center">
  <strong>🔥 PreFirewall Lab - Because Security Should Be Obvious 🔥</strong>
</p>

<p align="center">
  <em>Demonstrate the risk. Deploy the firewall. Protect the assets.</em>
</p>
