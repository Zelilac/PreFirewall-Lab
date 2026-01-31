# Security Policy

## Reporting Vulnerabilities

### Wait... This Application is INTENTIONALLY Vulnerable!

PreFirewall Lab is designed to be vulnerable for security demonstration purposes. 

**Expected "Vulnerabilities"** (by design):
- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection
- Path Traversal
- Insecure File Upload
- No Rate Limiting

These are **features, not bugs**.

## What Should Be Reported?

Only report issues that are **NOT** intentional vulnerabilities:

### Please Report:
- Security issues in the development/build process
- Vulnerabilities in dependencies that create unintended risks
- Issues that could affect the host system beyond the application
- Documentation errors that could mislead users about safety

### Do NOT Report:
- SQL Injection, XSS, or any intentionally vulnerable endpoint
- Lack of input validation
- Missing security headers
- Absence of authentication/authorization
- Any vulnerability listed in the README

## How to Report

If you find a legitimate security issue (not an intentional vulnerability):

1. **Do NOT** open a public GitHub issue
2. Email: [your-security-contact@example.com]
3. Include:
   - Description of the issue
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Responsible Disclosure

We are committed to responsible disclosure:
- We will acknowledge your report within 48 hours
- We will investigate and respond within 7 days
- We will credit researchers in our security acknowledgments (unless you prefer anonymity)

## Security Best Practices for Users

If you're using PreFirewall Lab:

1. **NEVER deploy on production networks**
2. **ALWAYS use isolated lab environments**
3. **NEVER expose to the internet without proper isolation**
4. **ALWAYS obtain authorization before testing**
5. **COMPLY with all applicable laws and regulations**

## Dependencies

We use automated dependency scanning to ensure:
- Development dependencies are current
- Runtime dependencies don't introduce unintended risks
- Known CVEs in dependencies are addressed

While the application itself is vulnerable by design, we don't want to introduce additional risks through outdated dependencies.

## Disclaimer

This application is provided "AS IS" for educational purposes. The authors are not responsible for misuse or any damage caused by this software.

---

**Remember**: The vulnerabilities in this application are INTENTIONAL. Use responsibly and legally.
