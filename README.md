# OmniSec - Advanced Security Operations Platform

## 🎯 Overview

OmniSec is a comprehensive, AI-powered security operations platform that integrates reconnaissance, vulnerability scanning, web application analysis, red/blue team operations, wireless security, forensics, reverse engineering, and AI threat intelligence into a single unified interface.

**Built with cutting-edge AI and 100 years of hacking wisdom.**

---

## 🚀 Features

### Core Modules

1. **Reconnaissance** - Network scanning via Shodan API, DNS resolution, port enumeration
2. **Vulnerability Intelligence** - CVE database search with NVD integration
3. **Web & App Analysis** - OWASP testing, SQL injection detection, XSS scanning
4. **Red Team Operations** - Exploit frameworks, payload generation, C2 simulation
5. **Blue Team Defense** - SIEM integration, threat hunting, incident response
6. **Wireless Security** - WiFi auditing, Bluetooth scanning, RF analysis
7. **Forensics & IR** - Memory analysis, timeline reconstruction, artifact recovery
8. **Reverse Engineering** - Binary analysis, malware deobfuscation, code reconstruction
9. **AI Threat Engine** - Anomaly detection, predictive analytics, behavioral analysis
10. **Ethics & Governance** - Compliance tracking, responsible disclosure workflows

### AI Assistant

- **Command-Aware**: Understands natural language commands like "scan network 192.168.1.0/24"
- **Auto-Execute**: Triggers actual security tools based on your prompts
- **Streaming Responses**: Real-time feedback powered by Lovable AI (Google Gemini)
- **Tool Integration**: Directly interfaces with Kali Linux tools and custom Python scripts

---

## 📦 Installation

### Prerequisites

- Node.js 18+
- Lovable Cloud account (auto-configured)
- API keys for external services (optional, add as needed)

### Setup

```bash
# Clone the repository
git clone <YOUR_GIT_URL>
cd <YOUR_PROJECT_NAME>

# Install dependencies
npm install

# Start development server
npm run dev
```

---

## 🔑 API Keys

### Adding Keys (No Popups!)

Keys are added on-demand via Settings page:

1. Go to `/settings`
2. Check integration status
3. Ask AI in chat: `"Add SHODAN_API_KEY secret"`
4. Enter key securely when prompted

### Required Services

- **Shodan** (required): https://account.shodan.io/
- **NVD** (optional): https://nvd.nist.gov/developers/request-an-api-key
- **OpenAI** (optional): https://platform.openai.com/api-keys

---

## 🛠️ Tool Integration

### Kali Linux Integration

Connect OmniSec to your Kali Linux installation for direct tool execution:

```bash
# Install tools on Kali
sudo apt install nmap masscan nikto sqlmap metasploit-framework nuclei

# Configure SSH (for remote Kali)
ssh-keygen -t ed25519
ssh-copy-id user@kali-ip

# Add edge function for tool execution (see INTEGRATION.md)
```

### Python VAPT Integration

Upload your custom Python GPT VAPT scripts:

1. Place Python files in `supabase/functions/python-vapt/`
2. Create Deno wrapper (see INTEGRATION.md)
3. AI will automatically invoke your Python logic

---

## 🤖 AI Commands

The AI assistant understands security commands and executes actual tools:

```
"scan network 10.0.0.0/24" → Triggers Recon with Nmap
"find vulnerabilities in example.com" → Runs Nuclei scan
"enumerate subdomains of target.com" → Executes subfinder + amass
"check for SQL injection on https://site.com" → Runs SQLMap
"perform security audit on 192.168.1.1" → Full toolchain
```

---

## 🔒 Security Scanning

OmniSec includes project-level security scanning similar to Lovable's security scanner:

- Port scanning and service detection
- Vulnerability assessment (CVEs, misconfigurations)
- Security headers analysis
- SSL/TLS certificate validation
- OWASP Top 10 testing
- Risk scoring and prioritization

---

## 📚 Documentation

- **Full Integration Guide**: See `INTEGRATION.md`
- **API Reference**: Check edge function source in `supabase/functions/`
- **Security Best Practices**: Documented in INTEGRATION.md

---

## 🎓 Usage Examples

### Reconnaissance

```bash
1. Navigate to /recon
2. Enter target: scanme.nmap.org
3. Click "Start Scan"
4. View ports, services, and IPs
```

### Vulnerability Scanning

```bash
1. Go to /vuln
2. Search: "Apache Log4j"
3. Review CVEs with CVSS scores
4. Check remediation steps
```

### AI-Powered Analysis

```bash
1. Open AI Assistant sidebar
2. Type: "What vulnerabilities exist in Apache 2.4.49?"
3. AI fetches CVEs and provides remediation
```

---

## ⚠️ Legal Disclaimer

**USE RESPONSIBLY**: This tool is for authorized security testing only.

- Get written permission before testing any system
- Follow scope limitations strictly
- Report findings responsibly
- Comply with local laws and regulations

**Unauthorized access to computer systems is illegal.**

---

## 🏗️ Architecture

- **Frontend**: React + TypeScript + Tailwind CSS
- **Backend**: Lovable Cloud (Supabase)
- **Edge Functions**: Deno runtime
- **AI**: Lovable AI (Google Gemini 2.5 Flash)
- **Database**: PostgreSQL with RLS
- **Auth**: Supabase Auth (email + social)

---

## 🤝 Contributing

Built with love by security professionals, for security professionals.

Contributions welcome! Please read INTEGRATION.md for development guidelines.

---

## 📞 Support & Deployment

### Deploying

Open [Lovable](https://lovable.dev/projects/34cdafdb-f0ec-442b-9ad9-6ea6de98b1d8) and click Share → Publish.

### Custom Domain

Navigate to Project > Settings > Domains and click Connect Domain.

Read more: [Setting up a custom domain](https://docs.lovable.dev/features/custom-domain#custom-domain)

### Support

- Check `/settings` for integration status
- View edge function logs in Lovable Cloud console
- All functions auto-deploy on code changes

---

## What technologies are used for this project?

This project is built with:

- Vite
- TypeScript
- React
- shadcn-ui
- Tailwind CSS
- Lovable Cloud (Supabase backend)

---

## 📄 License

This project is provided as-is for educational and authorized security testing purposes only.

---

**"Built with 100 years of hacking wisdom. Zero laziness. Pure excellence."** 🚀🔥

**URL**: https://lovable.dev/projects/34cdafdb-f0ec-442b-9ad9-6ea6de98b1d8
