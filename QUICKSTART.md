# Quick Start Guide - PreFirewall Lab

Get up and running in 5 minutes!

## ⚡ Fast Track Installation

### Option 1: Local Installation (Recommended)

```bash
# 1. Navigate to project directory
cd /Users/macbookair/Documents/PreFirewall-Lab

# 2. Install dependencies
npm install

# 3. Start the application
npm start

# 4. Verify it's running
curl http://localhost:3000/
```

**Application will be available at: `http://localhost:3000`**

### Option 2: Docker

```bash
# Build and run with Docker Compose
docker-compose up -d

# Check logs
docker-compose logs -f

# Stop when done
docker-compose down
```

## 🎯 Quick Test

### Test 1: SQL Injection
```bash
curl "http://localhost:3000/api/sql/users?username=admin' OR '1'='1"
```

**Expected**: Returns all users with passwords and sensitive data ✅

### Test 2: XSS
Open in browser:
```
http://localhost:3000/api/xss/search?q=<script>alert('XSS')</script>
```

**Expected**: JavaScript alert box appears ✅

### Test 3: Command Injection
```bash
curl -X POST http://localhost:3000/api/command/ping \
  -H "Content-Type: application/json" \
  -d '{"host": "127.0.0.1; whoami"}'
```

**Expected**: Shows output of both ping and whoami commands ✅

## 📬 Import Postman Collection

1. Open Postman
2. Click **Import**
3. Select `postman/PreFirewallLab.postman_collection.json`
4. Set variable `baseUrl` to `http://localhost:3000`
5. Try requests in any order

## 🔥 First Demo (5 minutes)

### Step 1: Show the vulnerable app
```bash
curl "http://localhost:3000/api/sql/users?username=admin' OR '1'='1"
```
→ **Point out**: "See? SQL injection succeeds, passwords exposed!"

### Step 2: Deploy your firewall/WAF
- Place firewall in network path
- Enable SQL injection protection

### Step 3: Try the same attack
```bash
curl "http://localhost:3000/api/sql/users?username=admin' OR '1'='1"
```
→ **Point out**: "Now it's blocked! 403 Forbidden. Check the firewall logs."

### Done! 🎉
You've just demonstrated firewall effectiveness.

## 📖 Next Steps

- Read [README.md](README.md) for complete documentation
- Review [docs/demo-guide.md](docs/demo-guide.md) for detailed demo script
- Use [docs/DEMO_CHECKLIST.md](docs/DEMO_CHECKLIST.md) for preparation

## 🛠️ Troubleshooting

### Port already in use?
```bash
# Change port
PORT=3001 npm start
```

### Dependencies failing?
```bash
# Clear cache and reinstall
rm -rf node_modules package-lock.json
npm install
```

### Can't connect?
```bash
# Check if running
ps aux | grep node

# Check port
lsof -i :3000

# Check firewall
curl http://localhost:3000/
```

## ⚠️ Important Reminders

- **ONLY use in isolated lab environments**
- **DO NOT expose to the internet**
- **Obtain authorization before demos**
- This application is INTENTIONALLY vulnerable

## 🎓 Resources

| Resource | Purpose |
|----------|---------|
| [README.md](README.md) | Complete project documentation |
| [docs/demo-guide.md](docs/demo-guide.md) | Detailed demo walkthrough |
| [docs/DEMO_CHECKLIST.md](docs/DEMO_CHECKLIST.md) | Pre-demo preparation checklist |
| [postman/](postman/) | Pre-built attack collection |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute |

## 🚀 You're Ready!

Your PreFirewall Lab is now running and ready for security demonstrations.

**Happy (ethical) hacking!** 🛡️

---

<p align="center">
  <strong>Questions?</strong> Check the <a href="README.md">README</a> or open an issue.
</p>
