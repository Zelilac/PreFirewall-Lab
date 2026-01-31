# PreFirewall Lab - Demo Checklist

Use this checklist to ensure successful security demonstrations.

---

## 📋 Pre-Demo Setup

### Environment Preparation

- [ ] PreFirewall Lab application deployed
- [ ] Application accessible at `http://[IP]:3000`
- [ ] Dependencies installed (`npm install` completed)
- [ ] Application starts without errors (`npm start`)
- [ ] Firewall/WAF ready but NOT deployed yet
- [ ] Network connectivity verified (ping, traceroute)
- [ ] Isolated lab environment confirmed (no production access)

### Testing & Validation

- [ ] Root endpoint accessible (`curl http://localhost:3000/`)
- [ ] SQL injection test successful
  - `curl "http://localhost:3000/api/sql/users?username=admin' OR '1'='1"`
- [ ] XSS test successful
  - `curl "http://localhost:3000/api/xss/search?q=<script>alert('XSS')</script>"`
- [ ] Command injection test successful
  - `curl -X POST http://localhost:3000/api/command/ping -d '{"host":"127.0.0.1; whoami"}'`
- [ ] Postman collection imported
- [ ] Postman `baseUrl` variable set correctly
- [ ] Sample Postman requests tested and working

### Presentation Materials

- [ ] Network diagram prepared (before/after firewall)
- [ ] Slides/talking points reviewed
- [ ] Audience research completed (technical level, interests)
- [ ] Screen recording tool ready (if recording demo)
- [ ] Backup demo environment available
- [ ] Demo script printed or accessible

### Firewall/WAF Configuration

- [ ] Firewall/WAF installed and accessible
- [ ] Security profiles configured:
  - [ ] SQL Injection protection enabled
  - [ ] XSS protection enabled
  - [ ] Command injection detection enabled
  - [ ] Path traversal blocking enabled
  - [ ] Rate limiting configured
- [ ] Logging and alerting configured
- [ ] Dashboard/monitoring accessible
- [ ] Firewall can be enabled/disabled quickly during demo

---

## 🎬 Demo Execution

### Phase 1: Introduction

- [ ] Welcome and introductions completed
- [ ] Demo objectives explained
- [ ] Disclaimer provided (educational use only)
- [ ] Network topology shown (without firewall)
- [ ] Questions invited

### Phase 2: Pre-Firewall Attacks

- [ ] **SQL Injection - Authentication Bypass**
  - [ ] Attack executed successfully
  - [ ] Sensitive data exposed (passwords, SSNs)
  - [ ] Impact explained to audience
  - [ ] Response captured/logged

- [ ] **SQL Injection - UNION Data Extraction**
  - [ ] UNION attack successful
  - [ ] User credentials extracted
  - [ ] Technique explained

- [ ] **Cross-Site Scripting (XSS)**
  - [ ] Reflected XSS demonstrated
  - [ ] JavaScript execution shown
  - [ ] Cookie theft risk explained
  - [ ] OR Stored XSS posted and triggered

- [ ] **Command Injection**
  - [ ] OS command executed successfully
  - [ ] `whoami` or similar command shown
  - [ ] Server compromise risk explained
  - [ ] Escalation potential discussed

- [ ] **Path Traversal**
  - [ ] `/etc/passwd` or config file accessed
  - [ ] Sensitive file disclosure demonstrated
  - [ ] Impact explained

- [ ] **Brute Force / Rate Limiting**
  - [ ] Multiple rapid login attempts successful
  - [ ] No blocking observed
  - [ ] Automated attack potential explained

- [ ] Impact summary delivered:
  - [ ] Data breach potential
  - [ ] System compromise risk
  - [ ] Business impact articulated
  - [ ] Compliance violations noted

### Phase 3: Firewall Deployment

- [ ] Firewall/WAF deployment announced
- [ ] Network path updated (show diagram)
- [ ] Security profiles activated
- [ ] Configuration explained briefly
- [ ] No application changes mentioned (code still vulnerable)

### Phase 4: Post-Firewall Attack Attempts

- [ ] **SQL Injection blocked**
  - [ ] Same payload attempted
  - [ ] 403 Forbidden response received
  - [ ] Firewall log shown
  - [ ] Signature ID noted

- [ ] **XSS blocked**
  - [ ] `<script>` tag detected and blocked
  - [ ] Block confirmed in logs

- [ ] **Command Injection blocked**
  - [ ] Shell metacharacters detected
  - [ ] Attack prevented

- [ ] **Path Traversal blocked**
  - [ ] `../` pattern detected
  - [ ] Access denied

- [ ] **Brute Force blocked**
  - [ ] Rate limit enforced
  - [ ] IP blocked after threshold
  - [ ] 429 Rate Limit Exceeded shown

### Phase 5: Analysis & Metrics

- [ ] Firewall dashboard shown
- [ ] Attack statistics displayed:
  - [ ] Total blocks
  - [ ] Attack categories
  - [ ] Top signatures
  - [ ] Timeline shown
- [ ] Logs reviewed and explained
- [ ] SIEM integration mentioned (if applicable)
- [ ] Before/after comparison summarized

### Phase 6: Conclusion

- [ ] Key findings summarized
- [ ] Business value articulated
- [ ] ROI discussed (for management)
- [ ] Technical benefits explained (for SOC)
- [ ] Next steps outlined
- [ ] Questions invited and answered
- [ ] Call to action delivered (if sales/consulting)

---

## ✅ Post-Demo Tasks

### Immediate Follow-Up

- [ ] Thank audience for participation
- [ ] Collect feedback
- [ ] Answer remaining questions
- [ ] Share presentation materials
- [ ] Provide demo recording (if recorded)
- [ ] Share Postman collection and documentation
- [ ] Schedule follow-up meeting (if applicable)

### Documentation

- [ ] Demo notes documented
- [ ] Issues/challenges recorded
- [ ] Improvements identified
- [ ] Audience feedback captured
- [ ] Success metrics recorded:
  - [ ] Audience engagement level
  - [ ] Questions asked
  - [ ] Follow-up interest
  - [ ] Action items identified

### Environment Cleanup

- [ ] PreFirewall Lab stopped (if not needed)
- [ ] Firewall rules reset (if shared environment)
- [ ] Test data cleared (if sensitive)
- [ ] Logs archived (for reference)
- [ ] Resources deallocated (if cloud-based)

---

## 🎯 Success Criteria

Mark as successful if:

- [ ] All planned attacks demonstrated successfully (pre-firewall)
- [ ] All attacks blocked successfully (post-firewall)
- [ ] Audience understood the before/after difference
- [ ] Business value clearly communicated
- [ ] Technical concepts explained appropriately for audience
- [ ] Questions answered satisfactorily
- [ ] Next steps identified and agreed upon
- [ ] No technical failures during demo
- [ ] Time management successful (demo on schedule)
- [ ] Overall audience feedback positive

---

## ⚠️ Contingency Plans

### If Application Fails to Start

- [ ] Backup environment ready
- [ ] Can demonstrate via recording
- [ ] Slides/screenshots prepared as fallback

### If Network Connectivity Issues

- [ ] Local-only demo possible (localhost)
- [ ] Pre-recorded demo available
- [ ] Screenshots and documentation ready

### If Firewall Doesn't Block

- [ ] Troubleshooting steps documented
- [ ] Alternative firewall configuration ready
- [ ] Can demonstrate logs showing what *would* block
- [ ] Vendor documentation available

### If Attacks Don't Work

- [ ] Postman collection as reliable fallback
- [ ] Pre-validated payloads documented
- [ ] Alternative attack vectors prepared
- [ ] Can discuss theoretically if needed

---

## 📊 Demo Metrics (Fill During/After Demo)

**Date**: ________________  
**Audience**: ________________  
**Size**: ________________  
**Duration**: ________________  

**Attacks Demonstrated**:
- [ ] SQL Injection
- [ ] XSS
- [ ] Command Injection
- [ ] Path Traversal
- [ ] File Upload
- [ ] Brute Force

**Firewall/WAF Used**: ________________

**Blocks Successful**: _____/_____

**Questions Asked**: ________________

**Engagement Level** (1-5): ________________

**Follow-Up Actions**: 
- [ ] Purchase/procurement discussion
- [ ] Technical deep-dive scheduled
- [ ] POC/trial requested
- [ ] Training requested
- [ ] None (informational only)

**Notes**:
```
________________________________________
________________________________________
________________________________________
________________________________________
```

---

## 🔄 Continuous Improvement

After each demo, consider:

- [ ] What went well?
- [ ] What could be improved?
- [ ] Were any attacks unclear?
- [ ] Did firewall block as expected?
- [ ] Was audience engagement high?
- [ ] Were talking points effective?
- [ ] Did we stay on time?
- [ ] Any technical issues to fix?

**Action Items for Next Demo**:
```
1. _________________________________
2. _________________________________
3. _________________________________
```

---

## 📞 Emergency Contacts

**Technical Support**: ________________  
**Firewall Vendor**: ________________  
**Network Admin**: ________________  
**Backup Presenter**: ________________  

---

<p align="center">
  <strong>✅ Checklist Complete</strong><br>
  <em>Ready to demonstrate firewall effectiveness!</em>
</p>

---

## Quick Reference: Essential Commands

```bash
# Start application
npm start

# Test SQL Injection
curl "http://localhost:3000/api/sql/users?username=admin' OR '1'='1"

# Test XSS
curl "http://localhost:3000/api/xss/search?q=<script>alert('XSS')</script>"

# Test Command Injection
curl -X POST http://localhost:3000/api/command/ping \
  -H "Content-Type: application/json" \
  -d '{"host": "127.0.0.1; whoami"}'

# Test Path Traversal
curl "http://localhost:3000/api/traversal/download?file=../../../../etc/passwd"

# View application info
curl http://localhost:3000/
```

---

**Version**: 1.0  
**Last Updated**: 2026-01-31
