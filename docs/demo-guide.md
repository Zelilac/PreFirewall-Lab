# PreFirewall Lab - Complete Demo Guide

## 🎯 Demo Overview

This guide provides a complete walkthrough for demonstrating PreFirewall Lab to showcase firewall/WAF effectiveness in protecting vulnerable applications.

**Target Audience**: Security teams, management, clients, SOC analysts, security consultants

**Duration**: 15-30 minutes (adjustable based on audience)

**Goal**: Prove the dramatic difference between an unprotected application and one protected by a firewall/WAF

---

## 📋 Pre-Demo Preparation

### Environment Setup

#### Option 1: Single Host Demo
```
[Attacker Machine] -----> [PreFirewall Lab Server]
                          (vulnerable, no firewall)
```

Then add firewall:
```
[Attacker Machine] -----> [Firewall/WAF] -----> [PreFirewall Lab Server]
                          (blocks attacks)
```

#### Option 2: Virtual Lab
- VM1: PreFirewall Lab application
- VM2: Firewall/WAF (FortiGate, Palo Alto VM, ModSecurity)
- VM3: Attacker workstation with Postman/browser

### Pre-Demo Checklist

- [ ] PreFirewall Lab installed and running (`npm start`)
- [ ] Application accessible at `http://[IP]:3000`
- [ ] Postman collection imported and tested
- [ ] Firewall/WAF ready but NOT deployed yet
- [ ] Screen recording/presentation tools ready
- [ ] Network diagram prepared
- [ ] Backup demo environment available

### Test Your Setup

```bash
# Verify application is running
curl http://localhost:3000/

# Quick vulnerability test
curl "http://localhost:3000/api/sql/users?username=admin' OR '1'='1"
```

---

## 🎬 Demo Script

### Phase 1: Introduction (2 minutes)

**Talking Points**:

> "Today I'll demonstrate what happens when a web application is exposed WITHOUT firewall protection, and the dramatic improvement we see AFTER deploying a firewall or WAF."

> "PreFirewall Lab represents a typical web application with common vulnerabilities—the kind that exist in many environments before security controls are properly implemented."

> "We'll execute real attacks against this application, then show how a firewall blocks the same attacks."

**Screen**: Show network diagram without firewall

---

### Phase 2: Pre-Firewall Attack Demonstrations (10-15 minutes)

#### Attack 1: SQL Injection - Authentication Bypass

**Setup**:
```bash
# Open browser or use curl
curl "http://localhost:3000/api/sql/users?username=admin' OR '1'='1"
```

**Or use Postman**: Run "SQLi - Classic (OR bypass)"

**Expected Result**: Returns all users including sensitive data (passwords, SSNs, credit cards)

**Talking Points**:

> "Without a firewall, I can inject SQL code into the username parameter. The classic payload `admin' OR '1'='1` bypasses authentication logic and returns all database records."

> "Notice the response includes sensitive data: passwords, social security numbers, credit card numbers. This is a critical data breach."

> "Firewalls detect SQL injection by identifying SQL keywords like OR, UNION, SELECT, and comment patterns like --."

**For Management Audience**: "This represents a complete authentication bypass and data exposure—exactly what happened in the [recent breach example]."

**For Technical Audience**: "The application concatenates user input directly into SQL queries without parameterization. The payload closes the string with a single quote, adds OR '1'='1' which is always true, effectively bypassing the WHERE clause."

---

#### Attack 2: SQL Injection - Data Extraction

**Setup**:
```bash
curl "http://localhost:3000/api/sql/products?id=1 UNION SELECT id,username,password,email FROM users--"
```

**Or Postman**: "SQLi - UNION (data extraction)"

**Expected Result**: Product query returns user credentials instead

**Talking Points**:

> "UNION-based SQL injection allows an attacker to extract data from other database tables. Here, I'm using a product search endpoint to steal user credentials."

> "The UNION keyword combines the results of the original query with my injected query, revealing password hashes and emails."

**Key Risk**: Data exfiltration, credential theft

---

#### Attack 3: Cross-Site Scripting (XSS)

**Setup - Reflected XSS**:
```
http://localhost:3000/api/xss/search?q=<script>alert('XSS')</script>
```

**Or Postman**: "XSS - Reflected (script tag)"

**Expected Result**: JavaScript executes in browser

**Talking Points**:

> "Cross-Site Scripting allows injection of malicious JavaScript into web pages. In a real scenario, this could steal session cookies, redirect users to phishing sites, or inject keyloggers."

> "The application reflects my input without sanitization. Watch as the alert box executes."

**For Technical Audience**: Show the HTML source: "Notice the `<script>` tag is rendered directly in the HTML response. No encoding or filtering occurred."

**Setup - Stored XSS**:
```bash
# Post malicious comment
curl -X POST http://localhost:3000/api/xss/comment \
  -H "Content-Type: application/json" \
  -d '{"username": "Attacker", "comment": "<script>alert(\"Stored XSS\")</script>"}'

# View comments to trigger
curl http://localhost:3000/api/xss/comments
```

**Talking Points**:

> "Stored XSS is more dangerous because the malicious script is saved in the database and executes for every user who views the page. This is how attackers compromise entire user bases."

---

#### Attack 4: Command Injection

**Setup**:
```bash
curl -X POST http://localhost:3000/api/command/ping \
  -H "Content-Type: application/json" \
  -d '{"host": "127.0.0.1; whoami"}'
```

**Or Postman**: "Command Injection - Ping (semicolon)"

**Expected Result**: Shows output of both `ping` and `whoami` commands

**Talking Points**:

> "Command injection allows execution of arbitrary operating system commands on the server. By injecting a semicolon, I can chain multiple commands."

> "Here I'm running `whoami`, but this could just as easily be `rm -rf /` to delete files, or download and execute a backdoor."

**Escalate the Demo**:
```bash
# Show reading sensitive files
curl -X POST http://localhost:3000/api/command/ping \
  -H "Content-Type: application/json" \
  -d '{"host": "127.0.0.1; cat /etc/passwd"}'
```

**For Management**: "This represents complete server compromise. An attacker could steal data, install ransomware, or use this server to attack other systems."

---

#### Attack 5: Path Traversal

**Setup**:
```bash
curl "http://localhost:3000/api/traversal/download?file=../../../../etc/passwd"
```

**Or Postman**: "Path Traversal - Download /etc/passwd"

**Expected Result**: Returns contents of `/etc/passwd`

**Talking Points**:

> "Path traversal attacks use `../` sequences to navigate outside the intended directory. Here, I'm reading `/etc/passwd` which contains user account information."

> "This could expose configuration files, encryption keys, environment variables with credentials, or source code."

**Key Files to Demonstrate**:
- `/etc/passwd` - User accounts
- `package.json` - Application configuration
- `.env` files - Database credentials (if present)

---

#### Attack 6: Brute Force Login

**Setup**:
```bash
# Run multiple times rapidly
for i in {1..10}; do
  curl -X POST http://localhost:3000/api/brute/login \
    -H "Content-Type: application/json" \
    -d '{"username": "admin", "password": "attempt'$i'"}' &
done
```

**Or Postman**: Run "Brute Force - Login" repeatedly with Runner

**Expected Result**: All attempts processed, no blocking

**Talking Points**:

> "Without rate limiting, I can attempt unlimited login combinations. Watch as I send 10 login attempts simultaneously—all are processed."

> "A real attacker would use tools like Hydra or Burp Intruder to try thousands of passwords per minute."

> "Firewalls detect this by monitoring request rates and blocking IPs with suspicious patterns."

---

### Phase 3: Deploy Firewall/WAF (2 minutes)

**Action**: 
1. Insert firewall/WAF into network path
2. Enable security profiles:
   - SQL Injection protection
   - XSS protection  
   - Command injection detection
   - Path traversal blocking
   - Rate limiting

**Firewall Configuration Examples**:

**FortiGate**:
```
config firewall policy
    edit 1
        set utm-status enable
        set av-profile "default"
        set webfilter-profile "default"
        set ips-sensor "default"
        set application-list "default"
        set waf-profile "default"
    next
end
```

**ModSecurity (CRS)**:
```apache
SecRuleEngine On
SecRequestBodyAccess On
Include /etc/modsecurity/crs-setup.conf
Include /etc/modsecurity/rules/*.conf
```

**Talking Points**:

> "Now I'm deploying [FortiGate/Palo Alto/ModSecurity] in front of the application. The application code hasn't changed—it's still vulnerable. But now we have a security layer."

> "I'm enabling IPS signatures for SQL injection, XSS, command injection, and enabling rate limiting."

**Screen**: Show updated network diagram with firewall

---

### Phase 4: Post-Firewall Attack Demonstrations (5-8 minutes)

#### Re-run Each Attack

**SQL Injection**:
```bash
curl "http://localhost:3000/api/sql/users?username=admin' OR '1'='1"
```

**Expected Result**: 
```
403 Forbidden
Blocked by WAF - SQL Injection signature detected
```

**Talking Points**:

> "The exact same attack that succeeded before is now blocked. The firewall detected the SQL keywords and blocked the request."

> "Let me show you the firewall logs..."

**Show Firewall Logs**:
- Alert ID/Signature: SQL Injection Detected
- Source IP: [Attacker IP]
- Payload: `admin' OR '1'='1`
- Action: Blocked

---

**XSS Attack**:
```
http://localhost:3000/api/xss/search?q=<script>alert('XSS')</script>
```

**Expected Result**: 403 Forbidden - XSS pattern detected

**Talking Points**:

> "The firewall detected the `<script>` tag and blocked it. Even if I try variations like encoded XSS, modern WAFs can detect them."

---

**Command Injection**:
```bash
curl -X POST http://localhost:3000/api/command/ping \
  -H "Content-Type: application/json" \
  -d '{"host": "127.0.0.1; whoami"}'
```

**Expected Result**: 403 Forbidden - Command injection blocked

**Talking Points**:

> "The semicolon and command chaining pattern triggered the IPS signature. The server never received the malicious input."

---

**Brute Force**:
```bash
# Attempt rapid login
for i in {1..10}; do
  curl -X POST http://localhost:3000/api/brute/login \
    -H "Content-Type: application/json" \
    -d '{"username": "admin", "password": "attempt'$i'"}'
done
```

**Expected Result**: First few succeed, then 429 Rate Limit Exceeded

**Talking Points**:

> "After 3-5 rapid attempts, the firewall's rate limiting kicked in and blocked subsequent requests from my IP address."

> "This prevents automated brute force tools from being effective."

---

### Phase 5: Analysis & Metrics (3-5 minutes)

**Show Firewall Dashboard**:

Metrics to display:
- Total attacks blocked: [count]
- Attack categories:
  - SQL Injection: [count]
  - XSS: [count]  
  - Command Injection: [count]
  - Rate Limit Violations: [count]
- Top attacking IPs
- Attack timeline

**Talking Points**:

> "In just a few minutes of testing, the firewall blocked [X] attack attempts. In a real environment, you'd see thousands of automated attacks daily."

> "The firewall logged every attempt with full details—payload, source, signature matched. This feeds into your SIEM for correlation and incident response."

**Cost-Benefit Discussion** (for management):

> "The application remains vulnerable in code—fixing these issues would require:
> - Extensive code review
> - Developer training  
> - Weeks of development time
> - Regression testing
> - Deployment coordination
>
> The firewall provided immediate protection without any application changes. This is defense in depth."

---

### Phase 6: Conclusion (2 minutes)

**Summary Points**:

✅ **Before Firewall**:
- SQL injection succeeded - complete database compromise
- XSS executed - user account takeover risk
- Command injection succeeded - server compromise
- Path traversal succeeded - sensitive file disclosure
- Brute force unlimited - credential compromise

❌ **After Firewall**:
- All attacks blocked
- Detailed logging and alerting
- No application changes required
- Immediate protection

**Final Talking Points**:

> "This demonstrates why firewalls and WAFs are critical components of defense in depth. They provide immediate protection while you work on fixing application vulnerabilities."

> "Modern threats are automated. Without rate limiting and signature detection, even a patched application can be overwhelmed or exploited through zero-day vulnerabilities."

> "The firewall doesn't just block—it provides visibility. Security teams can see attack patterns, identify targeted systems, and respond to threats."

**Call to Action** (for sales/consulting):

> "I recommend implementing [specific firewall/WAF solution] for [client environment]. We can provide:
> - Initial configuration and tuning
> - Integration with existing SIEM
> - Custom rule development
> - Ongoing monitoring and optimization"

---

## 🎓 Audience-Specific Talking Points

### For Executive/Management Audience

**Focus On**:
- Business impact (data breach, downtime, reputation)
- Compliance requirements (PCI DSS, GDPR, HIPAA)
- Cost comparison: Firewall vs. breach remediation
- Industry examples of similar attacks
- ROI and risk reduction

**Avoid**:
- Deep technical details
- Tool-specific terminology
- Extended attack demonstrations

**Key Messages**:
- "This represents a [$ amount] data breach risk"
- "Compliance standards require firewall protection"
- "Competitors have been breached via these exact vulnerabilities"

---

### For Technical/SOC Audience

**Focus On**:
- Attack techniques and variations
- Signature development and tuning
- False positive management
- Log analysis and SIEM integration
- Incident response workflows

**Dive Deeper**:
- Show attack tool usage (sqlmap, Burp Suite)
- Demonstrate signature bypass attempts
- Discuss WAF rule customization
- Review actual attack logs in detail

**Key Messages**:
- "Here's how this appears in [SIEM solution]"
- "We can create custom signatures for your environment"
- "This integrates with your existing security stack"

---

### For Developer Audience

**Focus On**:
- Root cause vulnerabilities in code
- Secure coding best practices
- How to fix each vulnerability properly
- Defense in depth importance

**Educational Points**:
- Show the vulnerable code snippets
- Explain proper input validation
- Discuss parameterized queries
- Review output encoding

**Key Messages**:
- "Firewall is a compensating control while you fix the code"
- "Here's how to prevent SQL injection with prepared statements"
- "Security should be built in, not bolted on"

---

## 🛠️ Troubleshooting

### Common Issues

**Application won't start**:
```bash
# Check if port 3000 is in use
lsof -i :3000

# Install dependencies
npm install

# Check Node.js version
node --version  # Should be v14+
```

**Attacks not working as expected**:
- Verify you're testing WITHOUT firewall first
- Check URL encoding in curl/browser
- Review application logs: `console.log` output
- Test with Postman collection

**Firewall not blocking attacks**:
- Verify firewall is in network path: `traceroute [IP]`
- Check security profiles are enabled
- Review firewall policy order
- Verify signature updates are current

---

## 📊 Demo Variations

### Quick Demo (5 minutes)
- Show 2-3 attacks only (SQL injection, XSS)
- Deploy firewall
- Show blocks
- Quick metrics review

### Extended Demo (45 minutes)
- All attack categories
- Multiple payloads per category
- Detailed log analysis
- Custom signature development
- Q&A session

### Hands-On Workshop (2-4 hours)
- Participants execute attacks themselves
- Configure firewall in breakout groups
- Tune signatures to reduce false positives
- Build detection rules

---

## 📝 Demo Checklist

### Before Demo
- [ ] Application running and accessible
- [ ] Postman collection imported and tested
- [ ] Firewall/WAF ready (but disabled)
- [ ] Network diagram prepared
- [ ] Presentation slides ready
- [ ] Screen recording tool configured
- [ ] Backup demo environment tested
- [ ] Audience research completed
- [ ] Talking points reviewed

### During Demo
- [ ] Introduction delivered
- [ ] Network topology explained
- [ ] Pre-firewall attacks demonstrated
- [ ] Impact clearly articulated
- [ ] Firewall deployed
- [ ] Post-firewall blocks shown
- [ ] Logs and metrics reviewed
- [ ] Conclusion delivered

### After Demo
- [ ] Q&A addressed
- [ ] Materials shared (slides, docs)
- [ ] Follow-up meeting scheduled
- [ ] Demo recording shared
- [ ] Feedback collected

---

## 🎯 Success Metrics

A successful demo should result in:

- ✅ Audience understands vulnerability impact
- ✅ Clear before/after comparison demonstrated
- ✅ Firewall effectiveness proven
- ✅ Business value articulated
- ✅ Next steps identified (purchase, implementation, training)
- ✅ Questions answered satisfactorily

---

## 📚 Additional Resources

### Recommended Reading
- OWASP Top 10 Web Application Security Risks
- CWE/SANS Top 25 Most Dangerous Software Errors
- Firewall vendor documentation
- CVE database for real-world examples

### Tools
- Postman (API testing)
- Burp Suite (web security testing)
- sqlmap (SQL injection automation)
- OWASP ZAP (web app scanner)

### Related Topics
- Secure Software Development Lifecycle (SSDLC)
- DevSecOps practices
- Web Application Firewalls (WAF) comparison
- SIEM integration and correlation

---

## 🔒 Reminder: Responsible Use

Always remember:
- Only test in authorized environments
- Never deploy PreFirewall Lab on production networks
- Obtain proper authorization before demonstrations
- Follow responsible disclosure practices
- Comply with all applicable laws and regulations

---

<p align="center">
  <strong>End of Demo Guide</strong><br>
  <em>Demonstrate. Educate. Protect.</em>
</p>
