# Contributing to PreFirewall Lab

Thank you for your interest in contributing to PreFirewall Lab!

## 🎯 Project Mission

PreFirewall Lab exists to demonstrate the effectiveness of firewalls and WAFs by providing a realistic, intentionally vulnerable application for security demonstrations, training, and education.

## 🤝 How to Contribute

### Types of Contributions Welcome

1. **Additional Vulnerability Examples**
   - New attack vectors that firewalls commonly block
   - Variations of existing vulnerabilities
   - Real-world attack patterns

2. **Documentation Improvements**
   - Clearer explanations
   - Better demo scripts
   - Additional firewall configuration examples
   - Translation to other languages

3. **Demo Enhancements**
   - Better Postman collections
   - Additional test cases
   - Improved talking points for different audiences

4. **Firewall Integration Guides**
   - Configuration examples for specific firewalls/WAFs
   - Integration with SIEM platforms
   - Custom signature development

### What We DON'T Want

- ❌ Security fixes (the app is supposed to be vulnerable!)
- ❌ Input validation or sanitization
- ❌ Authentication mechanisms
- ❌ Rate limiting implementations
- ❌ Any actual security improvements to the vulnerable code

## 📝 Contribution Process

### 1. Fork & Clone

```bash
git clone https://github.com/yourusername/PreFirewall-Lab.git
cd PreFirewall-Lab
```

### 2. Create a Branch

```bash
git checkout -b feature/your-feature-name
```

### 3. Make Changes

- Follow existing code style
- Add comments explaining:
  - What the vulnerability is
  - Why it succeeds without firewall
  - Why firewall/WAF blocks it
- Test your changes

### 4. Test Thoroughly

```bash
npm install
npm start

# Test your new vulnerability
# Verify it works as expected
```

### 5. Update Documentation

- Update README.md if adding new endpoints
- Add to Postman collection
- Update demo-guide.md with new attacks

### 6. Submit Pull Request

- Clear description of changes
- Explanation of the vulnerability added
- Demo scenario included
- Firewall detection patterns documented

## 🎨 Code Style Guidelines

### JavaScript

```javascript
// Good: Clear vulnerability with explanation
router.get('/endpoint', (req, res) => {
  const input = req.query.param;
  
  // VULNERABLE: No input validation
  const query = `SELECT * FROM users WHERE id = ${input}`;
  
  db.query(query, (err, results) => {
    res.json({
      results: results,
      vulnerability: 'SQL Injection via parameter',
      example_attack: '?param=1 OR 1=1',
      firewall_would: 'Block SQL keywords and patterns'
    });
  });
});
```

### Comments

Every vulnerable endpoint should include:

```javascript
/**
 * ============================================
 * [VULNERABILITY TYPE]
 * ============================================
 * 
 * WHY THEY SUCCEED WITHOUT FIREWALL:
 * - Specific reason 1
 * - Specific reason 2
 * 
 * WHY FIREWALL/WAF BLOCKS THEM:
 * - Detection method 1
 * - Detection method 2
 */
```

## 📚 Adding New Vulnerabilities

When adding a new vulnerability category:

1. **Create Route File**: `src/routes/your-category.js`
2. **Implement Endpoints**: Multiple examples of the vulnerability
3. **Add Info Endpoint**: GET endpoint with category documentation
4. **Update Main Server**: Import and use the route in `src/index.js`
5. **Add to Postman**: Create collection folder with example attacks
6. **Document**: Update README.md and demo-guide.md

### Template for New Route

```javascript
const express = require('express');
const router = express.Router();

/**
 * ============================================
 * [VULNERABILITY CATEGORY NAME]
 * ============================================
 * 
 * Description...
 * 
 * WHY THEY SUCCEED WITHOUT FIREWALL:
 * - ...
 * 
 * WHY FIREWALL/WAF BLOCKS THEM:
 * - ...
 */

// ENDPOINT 1: Description
router.get('/endpoint1', (req, res) => {
  // Vulnerable code with comments
});

// Info endpoint
router.get('/', (req, res) => {
  res.json({
    category: 'Category Name',
    description: 'Description',
    endpoints: { /* ... */ },
    example_payloads: { /* ... */ },
    firewall_detection: [ /* ... */ ]
  });
});

module.exports = router;
```

## 🧪 Testing Guidelines

Before submitting:

- [ ] Application starts without errors
- [ ] All endpoints return expected vulnerable responses
- [ ] Postman collection updated and tested
- [ ] Documentation updated
- [ ] No security fixes accidentally introduced
- [ ] Comments explain the vulnerability clearly

## 📖 Documentation Standards

### README Updates

- Keep it concise but complete
- Include example attacks with curl commands
- Explain firewall detection patterns
- Maintain consistent formatting

### Demo Guide Updates

- Audience-appropriate language
- Step-by-step instructions
- Expected results documented
- Troubleshooting tips included

## 🔐 Security Considerations

### Remember:

- This project is INTENTIONALLY insecure
- Do NOT fix vulnerabilities
- Do NOT add authentication/authorization
- Do NOT add input validation
- DO add clear warnings and documentation
- DO explain why something is vulnerable

### Dependencies

- Keep dependencies up to date
- Use `npm audit` to check for issues
- Update dependencies that have security vulnerabilities
- We want the APP to be vulnerable, not the framework

## 📋 Pull Request Checklist

Before submitting your PR:

- [ ] Code follows project style
- [ ] Comments explain vulnerabilities
- [ ] Tests pass (vulnerability works as expected)
- [ ] Documentation updated
- [ ] Postman collection updated
- [ ] No actual security improvements
- [ ] Clear PR description
- [ ] Demo scenario included

## 🎓 Educational Value

Contributions should prioritize:

1. **Clarity**: Easy to understand vulnerabilities
2. **Realism**: Real-world attack patterns
3. **Detectability**: Obvious firewall signatures
4. **Demo-Friendly**: Quick and repeatable

## 💬 Questions?

- Open an issue for discussion
- Tag it with `question` or `discussion`
- Be specific about your contribution idea

## 🏆 Recognition

Contributors will be:
- Listed in project acknowledgments
- Credited in release notes
- Appreciated by the security community! 🎉

## ⚖️ Legal & Ethical

By contributing, you agree:

1. Your contribution is for educational/demo purposes
2. You won't introduce malicious code
3. You understand this is for authorized testing only
4. You comply with all applicable laws

## 🚀 Getting Started

Ready to contribute?

1. Check existing issues for ideas
2. Open an issue to discuss your idea
3. Fork the repository
4. Make your changes
5. Submit a pull request

Thank you for helping make security demonstrations more effective!

---

<p align="center">
  <em>Build vulnerable code responsibly, for education and defense.</em>
</p>
