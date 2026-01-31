You are a senior security engineer and open-source maintainer.

Your task is to design and implement an OPEN-SOURCE, intentionally vulnerable web application
specifically created for LIVE SECURITY DEMOS BEFORE firewall / WAF deployment
(e.g. FortiGate, SonicWall, Palo Alto, Check Point, ModSecurity).

This project is for DEFENSIVE SECURITY DEMONSTRATION, SOC TRAINING,
and SECURITY CONSULTING ONLY.

================================
PROJECT IDENTITY
================================
Project Name: PreFirewall Lab
Tagline: "See the risk before the firewall exists."

PreFirewall Lab is a deliberately vulnerable application designed to:
- Represent a realistic web app BEFORE firewall protection
- Be extremely easy to attack without firewall
- Generate noisy, obvious, repeatable attacks
- Clearly show dramatic improvement AFTER firewall deployment
- Remain vendor-neutral and enterprise-demo friendly

================================
PRIMARY GOAL
================================
Create an application that acts as a perfect DEMO TARGET
to showcase how exposed systems look BEFORE firewall protection.

This project is NOT about firewall bypass or gaps.
This project is about PRE-PROTECTION VISIBILITY.

================================
TARGET DEMO SCENARIOS
================================
The application must be vulnerable to common attack classes
that network firewalls and WAFs typically detect and block:

- SQL Injection (classic, noisy payloads)
- Command Injection
- Reflected and Stored XSS
- Path Traversal
- Insecure File Upload (webshell-like behavior)
- Automated scanner patterns (sqlmap / nikto)
- Parameter tampering
- Excessive request rate (no rate limiting)

Attacks must be:
- Simple
- Highly visible
- Reproducible via browser, curl, and Postman
- Easy to correlate with firewall logs and alerts

================================
TECH STACK
================================
- Node.js + Express
- REST API based
- SQLite or in-memory database
- Minimal frontend (optional)
- Intentionally insecure defaults
- No input validation
- No authentication hardening
- No rate limiting

================================
PROJECT STRUCTURE
================================
Design a clean and simple structure:

/src
  /routes
    sql.js
    xss.js
    command.js
    traversal.js
    upload.js
    brute.js
  /data
/docs
/postman
README.md

Each route file must represent ONE clear attack category.

================================
CODE REQUIREMENTS
================================
For every vulnerable endpoint:
- Keep code short and readable
- Add comments explaining:
  - What the attack is
  - Why it succeeds without firewall
  - Why firewall/WAF typically blocks it
- Do NOT fix vulnerabilities
- Do NOT hide or obfuscate payloads
- Do NOT add mitigations

================================
POSTMAN SUPPORT
================================
Create a Postman collection with:
- One request per vulnerability type
- Pre-filled attack payloads
- Clear naming (e.g. "SQLi - UNION SELECT")
- Environment variables for host and port

Store under:
/postman/PreFirewallLab.postman_collection.json

================================
DOCUMENTATION REQUIREMENTS
================================
Generate professional demo documentation.

README.md must include:
- Project overview
- Intended use (pre-firewall demo target)
- Supported attack types
- Quick start instructions
- Strong ethical & legal disclaimer

/docs/demo-guide.md must include:
- Step-by-step demo flow:
  1. Deploy PreFirewall Lab without firewall
  2. Execute attacks (browser / Postman)
  3. Observe successful exploitation
  4. Deploy firewall / WAF
  5. Re-run identical attacks
  6. Observe blocks, alerts, and logs
- Suggested firewall alert categories
- Talking points for:
  - Management audience
  - SOC / technical audience

================================
DEMO CHECKLIST
================================
Include a reusable demo checklist:

[ ] Application deployed and reachable
[ ] SQL Injection succeeds
[ ] XSS executes
[ ] File upload succeeds
[ ] Scanner traffic visible
[ ] Postman collection tested
[ ] Firewall deployed
[ ] Same attacks blocked
[ ] Firewall logs / alerts visible
[ ] Demo conclusion delivered

================================
OUTPUT EXPECTATION
================================
Provide:
- Full project structure
- Representative vulnerable routes
- Postman collection outline
- Demo checklist
- Clear, enterprise-ready documentation

This project must feel like:
"A system you would never expose to the internet without a firewall."

Begin by confirming the project structure,
then implement representative vulnerable endpoints.
