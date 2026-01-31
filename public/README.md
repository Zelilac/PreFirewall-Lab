# PreFirewall Lab - Web UI

Beautiful, interactive web interface for demonstrating vulnerabilities and firewall protection.

## 📁 Structure

```
public/
├── index.html              # Landing page with overview and stats
├── demos/
│   ├── attacks.html       # Interactive attack execution interface
│   └── dashboard.html     # Live vulnerability monitoring dashboard
├── css/
│   └── style.css          # Complete design system with dark theme
└── js/
    └── app.js             # Utility functions for API calls
```

## 🎨 Features

### Landing Page (`/`)
- **Hero Section**: Eye-catching introduction with warning banner
- **Statistics Dashboard**: Real-time vulnerability metrics (36 endpoints, 6 categories)
- **Attack Category Cards**: Visual cards for each vulnerability type with descriptions
- **API Documentation Table**: Quick reference for all endpoints
- **Resources Section**: Links to documentation and guides

### Interactive Attacks Page (`/demos/attacks.html`)
- **Tab-Based Navigation**: Switch between 6 attack categories
- **Pre-filled Payloads**: Example exploits ready to execute
- **Execute Buttons**: One-click vulnerability testing
- **Real-time Results**: JSON responses displayed with syntax highlighting
- **Educational Explanations**: Each attack includes descriptions and expected outcomes

#### Attack Categories:
1. **💉 SQL Injection**
   - Classic OR bypass (`admin' OR '1'='1`)
   - Comment injection (`admin' --`)
   - UNION-based extraction

2. **🔴 Cross-Site Scripting (XSS)**
   - Reflected XSS with `<script>` tags
   - Stored XSS in comments
   - Event handler injection

3. **⚡ Command Injection**
   - Semicolon command chaining
   - Pipe operator exploitation
   - Backgrounded commands

4. **📁 Path Traversal**
   - Directory traversal (`../../../../etc/passwd`)
   - Encoded traversal sequences
   - Absolute path injection

5. **📤 File Upload**
   - Unrestricted file upload (any extension)
   - Webshell creation and upload
   - Double extension bypass (.php.jpg)

6. **🔓 Brute Force**
   - Unlimited login attempts
   - Rapid-fire password testing
   - No rate limiting demonstration

### Vulnerability Dashboard (`/demos/dashboard.html`)
- **System Status Metrics**: Real-time firewall status and risk level
- **Vulnerability List**: All 36 endpoints with exploit status
- **Attack Statistics**: Simulated attack counts (SQL injection, XSS, etc.)
- **Before/After Comparison**: Visual comparison of protected vs unprotected systems
- **Endpoint Status Table**: Detailed view of each vulnerable endpoint
- **Risk Indicators**: Color-coded severity levels (CRITICAL, HIGH, MEDIUM)

## 🎨 Design System

### Color Scheme
```css
--bg-dark: #0a0a1a           /* Deep space background */
--bg-card: #1a1a2e           /* Card backgrounds */
--primary-color: #ff4444     /* Red accent for danger */
--secondary-color: #0f3460   /* Blue accent for tech */
--text-color: #e0e0e0        /* Light text */
--text-muted: #a0a0a0        /* Muted text */
--border-color: #2a2a3e      /* Subtle borders */
--success: #00ff88           /* Success green */
--warning: #ffaa00           /* Warning orange */
--danger: #ff4444            /* Danger red */
```

### Typography
- **Font**: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif
- **Code**: Consolas, Monaco, 'Courier New', monospace
- **Headings**: Bold with gradient text effects
- **Body**: 16px base, 1.6 line height

### Components

#### Cards
- Gradient backgrounds with red/blue accents
- Hover animations (scale, shadow, glow)
- Border highlighting on interaction
- Smooth transitions (0.3s)

#### Buttons
- Primary: Red gradient with glow effect
- Secondary: Blue gradient
- Hover: Brightness increase + scale
- Active: Scale down feedback

#### Forms
- Dark input backgrounds
- Blue focus borders with glow
- Smooth transitions
- Consistent padding and spacing

#### Tables
- Striped rows for readability
- Hover highlighting
- Responsive design
- Monospace code cells

#### Alerts
- Color-coded by severity (danger, warning, success)
- Left border accent
- Icon support
- Dismissible option

### Animations
```css
/* Fade in on load */
.fade-in { animation: fadeIn 0.6s }

/* Slide up from bottom */
.slide-up { animation: slideUp 0.6s }

/* Pulse effect for alerts */
.pulse { animation: pulse 2s infinite }

/* Gradient animation */
.gradient-animate { animation: gradient 3s infinite }
```

## 🚀 Usage

### Starting the Server
```bash
npm start
# Server runs on http://localhost:3000
```

### Accessing the UI
- **Landing Page**: http://localhost:3000/
- **Try Attacks**: http://localhost:3000/demos/attacks.html
- **Dashboard**: http://localhost:3000/demos/dashboard.html

### Testing Vulnerabilities

1. Navigate to the Attacks page
2. Select an attack category (SQL, XSS, Command, etc.)
3. Review the pre-filled payload
4. Click "🚀 Execute Attack"
5. View the response in real-time

### Example Workflow

```plaintext
1. Visit Landing Page
   └─ Review 6 vulnerability categories
   └─ See statistics (36 endpoints)
   └─ Read API documentation

2. Go to Dashboard
   └─ View system status (UNPROTECTED)
   └─ Check vulnerability list (ALL EXPLOITABLE)
   └─ Review before/after comparison

3. Try Attacks Page
   └─ Select SQL Injection
   └─ Execute "Classic OR Bypass" attack
   └─ See database dump in response
   └─ Try other attack categories
```

## 🛡️ Before vs After Firewall

### Without Firewall (Current State)
- ❌ SQL injection succeeds instantly
- ❌ XSS scripts execute in browser
- ❌ Commands run on server
- ❌ Files can be read from anywhere
- ❌ Webshells upload successfully
- ❌ Unlimited brute force attempts
- ❌ No logging or monitoring
- ❌ Complete exposure to attacks

### With Firewall (Post-Deployment)
- ✅ SQL keywords detected and blocked
- ✅ `<script>` tags stripped/escaped
- ✅ Command metacharacters filtered
- ✅ Path traversal sequences blocked
- ✅ Malicious file extensions rejected
- ✅ Rate limiting enforced (max 100 req/min)
- ✅ All attacks logged and alerted
- ✅ Application protected in real-time

## 📊 Technical Details

### Frontend Stack
- **HTML5**: Semantic markup
- **CSS3**: Modern animations, grid, flexbox
- **Vanilla JavaScript**: No frameworks, pure JS
- **Fetch API**: For AJAX requests

### Key JavaScript Functions

```javascript
// Make API calls with error handling
makeAPICall(endpoint, method, data)

// Format JSON with syntax highlighting
formatJSON(json)

// Display results in response boxes
displayResult(elementId, data, isError)

// Show toast notifications
showNotification(message, type)

// Loading indicator
showLoading(elementId)
```

### Responsive Design
- Mobile-first approach
- Breakpoints: 768px (tablet), 1024px (desktop)
- Flexible grid layouts
- Touch-friendly buttons (min 44px)

### Browser Compatibility
- Chrome 90+ ✅
- Firefox 88+ ✅
- Safari 14+ ✅
- Edge 90+ ✅

## 🎓 Educational Value

### For Security Training
- Visual demonstration of real vulnerabilities
- Interactive learning experience
- Before/after firewall comparison
- Real-time attack execution

### For Sales Demos
- Professional, polished interface
- Clear value proposition
- Live vulnerability showcase
- Immediate impact visualization

### For Developers
- See vulnerable code patterns
- Understand attack vectors
- Learn proper input validation
- Study firewall detection patterns

## 🔧 Customization

### Adding New Attack Types

1. **Update HTML** (attacks.html):
```html
<div id="new-category" class="attack-category" style="display:none;">
    <h2>🆕 New Attack Type</h2>
    <!-- Add form and buttons -->
</div>
```

2. **Add JavaScript Function**:
```javascript
async function testNewAttack() {
    const result = await makeAPICall('/api/new/endpoint');
    displayResult('new-result', result);
}
```

3. **Add Tab Button**:
```html
<button class="btn" onclick="showCategory('new')">🆕 New Attack</button>
```

### Customizing Colors

Edit CSS variables in `style.css`:
```css
:root {
    --primary-color: #your-color;
    --bg-dark: #your-background;
}
```

### Adding Analytics

Add tracking to button clicks:
```javascript
function trackAttack(type) {
    // Your analytics code
    console.log(`Attack executed: ${type}`);
}
```

## 🚨 Security Notes

⚠️ **This UI demonstrates INTENTIONAL vulnerabilities**

- Do NOT deploy to production
- Use ONLY in isolated lab environments
- All attacks are REAL and functional
- No actual firewall protection exists
- Educational purposes ONLY

## 📝 Future Enhancements

- [ ] Real-time attack logs with WebSockets
- [ ] Firewall simulation toggle (show blocked attacks)
- [ ] Attack success/failure metrics
- [ ] Export vulnerability reports (PDF)
- [ ] Video tutorials for each attack type
- [ ] Dark/light theme toggle
- [ ] Mobile app version
- [ ] Multi-language support
- [ ] Interactive firewall configuration builder
- [ ] Comparison with competitor products

## 📄 License

MIT License - See LICENSE file for details

## 🤝 Contributing

See CONTRIBUTING.md for guidelines on:
- Adding new vulnerability types
- Improving UI/UX
- Adding animations
- Writing documentation

---

**PreFirewall Lab** - Making security vulnerabilities visible, demonstrable, and fixable.
