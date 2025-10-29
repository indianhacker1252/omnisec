# OmniSec Integration Guide

## 🚀 Complete Integration & Setup Manual

This guide will help you integrate all OmniSec modules with real security tools and APIs for production-ready cybersecurity operations.

---

## 📋 Table of Contents

1. [System Requirements](#system-requirements)
2. [API Keys & Credentials](#api-keys--credentials)
3. [Module Integration](#module-integration)
4. [Security Best Practices](#security-best-practices)
5. [Troubleshooting](#troubleshooting)

---

## 🖥️ System Requirements

### Minimum Requirements
- **OS**: Linux (Ubuntu 20.04+), macOS, or Windows 10/11
- **RAM**: 8GB minimum, 16GB recommended
- **Storage**: 20GB free space
- **Network**: Stable internet connection
- **Browser**: Chrome, Firefox, or Edge (latest versions)

### Backend Requirements
- **Node.js**: v18+ 
- **Supabase Account**: For Lovable Cloud backend
- **API Access**: Active subscriptions to security services

---

## 🔑 API Keys & Credentials

### Required API Keys

#### 1. **Shodan API** (for Reconnaissance Module)
- **Purpose**: Real-time network reconnaissance and asset discovery
- **Get Your Key**: https://account.shodan.io/
- **Pricing**: Free tier (100 queries/month), Paid tiers available
- **Setup**:
  1. Create Shodan account
  2. Navigate to "My Account" → "API Key"
  3. Copy your API key
  4. In OmniSec: Go to Settings → Add `SHODAN_API_KEY`

**Example Usage**:
```bash
# Test your Shodan key
curl https://api.shodan.io/api-info?key=YOUR_API_KEY
```

#### 2. **NVD API** (for Vulnerability Intelligence Module)
- **Purpose**: CVE database and vulnerability correlation
- **Get Your Key**: https://nvd.nist.gov/developers/request-an-api-key
- **Pricing**: Free (no rate limits with API key)
- **Setup**:
  1. Request API key from NVD
  2. Check your email for activation
  3. In OmniSec: Go to Settings → Add `NVD_API_KEY`

**Example Usage**:
```bash
# Test NVD API
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=5" \
  -H "apiKey: YOUR_API_KEY"
```

#### 3. **OpenAI API** (Optional - for Enhanced AI Features)
- **Purpose**: Advanced threat analysis and natural language processing
- **Get Your Key**: https://platform.openai.com/api-keys
- **Pricing**: Pay-as-you-go
- **Setup**:
  1. Create OpenAI account
  2. Add payment method
  3. Generate API key
  4. In OmniSec: Settings → Add `OPENAI_API_KEY`

**Note**: OmniSec uses built-in AI (Lovable AI) by default. OpenAI is optional for enhanced capabilities.

---

## 🔧 Module Integration

### 1. **Reconnaissance Module**

#### Integration Steps:
```bash
# 1. Add Shodan API key in Settings
SHODAN_API_KEY=your_shodan_key_here

# 2. Test the module
# Navigate to: /recon
# Enter target: example.com
# Click "Start Scan"
```

#### What It Does:
- DNS resolution
- Port scanning via Shodan
- Service fingerprinting
- IP geolocation
- Historical data lookup

#### Real-World Usage:
```javascript
// Example API call structure
POST /functions/v1/recon
{
  "target": "scanme.nmap.org"
}

// Response includes:
{
  "host": "scanme.nmap.org",
  "ip": "45.33.32.156",
  "status": "online",
  "ports": [
    { "port": 22, "service": "ssh", "product": "OpenSSH" },
    { "port": 80, "service": "http", "product": "Apache" }
  ]
}
```

---

### 2. **Vulnerability Intelligence Module**

#### Integration Steps:
```bash
# 1. Add NVD API key in Settings (optional but recommended)
NVD_API_KEY=your_nvd_key_here

# 2. Test the module
# Navigate to: /vuln
# Enter CVE: CVE-2024-1234 or search by keyword
# Click "Search"
```

#### What It Does:
- CVE database search
- CVSS score analysis
- Exploit database correlation
- Affected products lookup
- Remediation suggestions

#### Advanced Integration:
```javascript
// Integrate with vulnerability scanners
// Example: Export scan results from Nessus/OpenVAS
// Import to OmniSec for correlation

// API structure
POST /functions/v1/vulnintel
{
  "query": "Apache Log4j",
  "limit": 10
}
```

---

### 3. **Web & App Analysis Module**

#### Tool Integration:

##### **OWASP ZAP Integration**:
```bash
# 1. Install ZAP
wget https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2.14.0_Linux.tar.gz
tar -xvf ZAP_2.14.0_Linux.tar.gz

# 2. Start ZAP in daemon mode
./ZAP_2.14.0/zap.sh -daemon -port 8080 -config api.key=YOUR_ZAP_API_KEY

# 3. Configure OmniSec
# Settings → Add ZAP_API_KEY and ZAP_URL (http://localhost:8080)
```

##### **Burp Suite Integration**:
```bash
# 1. Start Burp Suite Professional
# 2. Enable REST API: User Options → Misc → REST API
# 3. Note the API URL and key
# 4. In OmniSec: Settings → Add BURP_API_KEY and BURP_URL
```

#### Scanning Workflow:
1. Enter target URL
2. Select scan profile (Quick, Standard, Deep)
3. Review findings with CVSS scores
4. Export reports

---

### 4. **Red Team Operations Module**

#### Metasploit Integration:

```bash
# 1. Install Metasploit Framework
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod +x msfinstall
./msfinstall

# 2. Start Metasploit RPC server
msfrpcd -P YOUR_PASSWORD -U msf -a 127.0.0.1

# 3. Configure OmniSec
# Settings → Add MSF_RPC_URL, MSF_RPC_USER, MSF_RPC_PASS
```

#### Empire Framework Integration:
```bash
# 1. Install Empire
git clone https://github.com/BC-SECURITY/Empire.git
cd Empire
./setup/install.sh

# 2. Start Empire with API
./empire --rest --username empireadmin --password YOUR_PASSWORD

# 3. Configure in OmniSec
# Settings → Add EMPIRE_API_URL and EMPIRE_API_TOKEN
```

**⚠️ WARNING**: Only use Red Team tools on systems you own or have explicit written permission to test!

---

### 5. **Blue Team Defense Module**

#### SIEM Integration:

##### **Splunk**:
```bash
# 1. Install Splunk forwarder on your hosts
# 2. Configure data inputs
# 3. Create API token in Splunk: Settings → Tokens
# 4. In OmniSec: Settings → Add SPLUNK_URL and SPLUNK_TOKEN
```

##### **Elastic Stack (ELK)**:
```bash
# 1. Setup Elasticsearch, Logstash, Kibana
# 2. Create API key in Kibana: Stack Management → API Keys
# 3. Configure in OmniSec: Settings → Add ELASTIC_URL and ELASTIC_API_KEY
```

#### MITRE ATT&CK Integration:
- Built-in mapping to MITRE ATT&CK framework
- Automatically correlates alerts to tactics/techniques
- No additional setup required

---

### 6. **Wireless Security Module**

#### Prerequisites:
```bash
# Linux only - requires wireless adapter with monitor mode

# 1. Check if your adapter supports monitor mode
iwconfig

# 2. Install aircrack-ng suite
sudo apt-get install aircrack-ng

# 3. Put adapter in monitor mode
sudo airmon-ng start wlan0

# 4. In OmniSec: Configure wireless interface
# Settings → Add WIRELESS_INTERFACE=wlan0mon
```

#### Supported Operations:
- WiFi network discovery
- WPA/WPA2 security analysis
- Bluetooth LE scanning (requires `bluez` tools)
- RF signal analysis (requires SDR hardware)

---

### 7. **Forensics & Incident Response Module**

#### Tool Integration:

##### **Volatility**:
```bash
# 1. Install Volatility 3
pip3 install volatility3

# 2. No API key needed - local analysis
# 3. Upload memory dumps directly in OmniSec UI
```

##### **Autopsy**:
```bash
# 1. Install Autopsy
wget https://github.com/sleuthkit/autopsy/releases/download/autopsy-4.21.0/autopsy-4.21.0.zip
unzip autopsy-4.21.0.zip
cd autopsy-4.21.0
./bin/autopsy

# 2. Create case in Autopsy
# 3. Export timeline to CSV
# 4. Import in OmniSec for correlation
```

---

### 8. **Reverse Engineering Module**

#### Ghidra Integration:
```bash
# 1. Download Ghidra
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0_build/ghidra_11.0_PUBLIC_20231222.zip

# 2. Extract and run
unzip ghidra_11.0_PUBLIC_20231222.zip
cd ghidra_11.0_PUBLIC
./ghidraRun

# 3. Enable Ghidra Bridge for API access
pip install ghidra-bridge

# 4. In OmniSec: Upload binaries directly for analysis
```

#### radare2 Integration:
```bash
# 1. Install radare2
git clone https://github.com/radareorg/radare2
cd radare2
sys/install.sh

# 2. No additional setup - OmniSec calls r2 CLI
```

---

### 9. **AI Threat Intelligence Engine**

#### Built-In Features:
- **Lovable AI** (Google Gemini models) - Pre-configured, no API key needed
- Anomaly detection using ML models
- Predictive threat analysis
- Behavioral analytics

#### Optional: Enhanced ML Models:
```python
# For advanced users: Train custom models
# 1. Export data from OmniSec
# 2. Train scikit-learn or TensorFlow models
# 3. Upload model files to OmniSec (future feature)
```

---

### 10. **Ethics & Governance Module**

#### Compliance Frameworks:
- **ISO 27001**: Automated checklist tracking
- **GDPR**: Data protection compliance monitoring
- **SOC 2**: Continuous compliance validation
- **PCI DSS**: Payment card industry standards

#### Audit Logging:
- All user actions automatically logged
- Immutable audit trail
- Export logs for compliance reporting

#### Responsible Disclosure:
- Built-in vulnerability disclosure workflow
- 90-day timeline tracking
- Automated notifications

---

## 🔒 Security Best Practices

### API Key Management
```bash
# NEVER commit API keys to version control
# Use environment variables or Lovable Cloud secrets

# Example .env.local (git-ignored)
SHODAN_API_KEY=abc123...
NVD_API_KEY=def456...
OPENAI_API_KEY=ghi789...
```

### Access Control
1. Use strong passwords (16+ characters)
2. Enable 2FA on all external services
3. Rotate API keys quarterly
4. Use separate keys for dev/staging/production

### Network Security
- Always use HTTPS for API calls
- Implement IP whitelisting where possible
- Use VPN for remote security testing
- Never expose Lovable Cloud credentials

### Legal Compliance
- **Get Written Authorization** before any security testing
- Follow scope limitations strictly
- Document all testing activities
- Report findings responsibly

---

## 🐛 Troubleshooting

### Common Issues:

#### 1. **"API Key Not Configured" Error**
```bash
# Solution: Add API key in Settings
# Navigate to: Settings → Integrations → Add Secret
```

#### 2. **"CORS Error" in Browser Console**
```bash
# Solution: Check edge function CORS headers
# All edge functions should include:
Access-Control-Allow-Origin: *
Access-Control-Allow-Headers: authorization, content-type
```

#### 3. **Slow Scan Performance**
```bash
# Optimization tips:
# 1. Use paid Shodan tier for faster queries
# 2. Reduce scan scope (fewer ports/IPs)
# 3. Run scans during off-peak hours
```

#### 4. **Edge Function Timeout**
```bash
# For long-running scans:
# 1. Use async/queue-based processing
# 2. Implement progress callbacks
# 3. Split large scans into smaller chunks
```

#### 5. **AI Assistant Not Responding**
```bash
# Check:
# 1. Lovable Cloud is active (Settings → Tools)
# 2. No firewall blocking ai.gateway.lovable.dev
# 3. Browser console for errors
```

---

## 📊 Performance Optimization

### Database Indexing:
```sql
-- If using custom database tables
CREATE INDEX idx_scan_results_timestamp ON scan_results(timestamp);
CREATE INDEX idx_vulnerabilities_cvss ON vulnerabilities(cvss_score);
```

### Caching Strategy:
```javascript
// Implement Redis caching for frequent queries
// Example: Cache NVD CVE data for 24 hours
const cacheKey = `cve:${cveId}`;
const cached = await redis.get(cacheKey);
if (cached) return JSON.parse(cached);
// ... fetch from API and cache
await redis.setex(cacheKey, 86400, JSON.stringify(data));
```

---

## 🎓 Training Resources

### Getting Started:
1. **OmniSec Academy** (Coming Soon)
2. **OWASP Testing Guide**: https://owasp.org/www-project-web-security-testing-guide/
3. **Metasploit Unleashed**: https://www.offsec.com/metasploit-unleashed/
4. **MITRE ATT&CK**: https://attack.mitre.org/

### Certification Paths:
- **OSCP** (Offensive Security Certified Professional)
- **CEH** (Certified Ethical Hacker)
- **GPEN** (GIAC Penetration Tester)
- **CISSP** (Certified Information Systems Security Professional)

---

## 🚨 Emergency Contacts

### Security Incident Response:
- **Email**: security@omnisec.local
- **PGP Key**: Available at keybase.io/omnisec

### Bug Bounty Program:
- **Scope**: All OmniSec modules
- **Rewards**: $100 - $10,000 based on severity
- **Disclosure**: security@omnisec.local

---

## 📝 License & Legal

OmniSec is provided for **authorized security testing only**.

**You are responsible for**:
- Obtaining proper authorization before testing
- Complying with local laws and regulations
- Using tools ethically and responsibly
- Reporting findings through proper channels

**Disclaimer**: Misuse of this platform may result in criminal prosecution.

---

## 🤝 Contributing

We welcome contributions! See `CONTRIBUTING.md` for guidelines.

### Development Setup:
```bash
# Clone repository
git clone https://github.com/yourusername/omnisec.git
cd omnisec

# Install dependencies
npm install

# Start development server
npm run dev

# Deploy edge functions
npm run deploy:functions
```

---

## 📞 Support

- **Documentation**: https://docs.omnisec.dev
- **Discord**: https://discord.gg/omnisec
- **Email**: support@omnisec.local
- **GitHub Issues**: https://github.com/yourusername/omnisec/issues

---

**Version**: 1.0.0  
**Last Updated**: January 2025  
**Maintainer**: OmniSec Security Team

---

## 🌟 Star Us on GitHub!

If OmniSec helps your security operations, please ⭐ star the repository!

**Happy Hacking! 🔐**
