# 🛡️ Advanced Honeypot Security Analysis System

A comprehensive honeypot deployment with advanced threat analysis capabilities, featuring MITRE ATT&CK classification, behavioral analysis, and professional security dashboards.

## 🚀 Features

### Core Honeypot Services
- **HTTP Honeypot** (Port 8080) - Web application attack simulation
- **SSH-like Service** (Port 2222) - Brute force attack detection
- **FTP Service** (Port 2121) - File transfer protocol monitoring

### Advanced Analysis Capabilities
- **🎯 MITRE ATT&CK Framework Integration** - Classify attacks using industry-standard techniques
- **📊 Multi-dimensional Visualization** - Professional charts and graphs
- **🔍 Behavioral Analysis** - Attack sophistication scoring and pattern recognition
- **📋 Threat Intelligence Reports** - Detailed security assessments
- **🌐 Interactive Dashboard** - Professional HTML dashboard with all analysis results

## 📦 Installation & Setup

### Method 1: Local Installation (Recommended for Windows)

1. **Create virtual environment**:
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

2. **Install dependencies**:
   ```powershell
   pip install -r requirements.txt
   ```

3. **Run the honeypot**:
   ```powershell
   python -m honeypot.main
   ```

### Method 2: Docker Deployment

1. **Create environment file** (`.env`):
   ```
   HP_HTTP_PORT=8080
   HP_SSH_PORT=2222
   HP_FTP_PORT=2121
   ```

2. **Build and run**:
   ```bash
   docker compose build
   docker compose up
   ```

## 🎯 Usage

### 1. Start Honeypot Services
```powershell
python -m honeypot.main
```

The honeypot will start three services:
- HTTP honeypot on `127.0.0.1:8080`
- SSH-like honeypot on `127.0.0.1:2222`
- FTP honeypot on `127.0.0.1:2121`

### 2. Simulate Attacks (Testing)
```powershell
python attacker_sim/simulate.py --target 127.0.0.1
```

This comprehensive simulator includes:
- SQL injection attempts
- XSS (Cross-Site Scripting) attacks
- Directory traversal probes
- Brute force login attempts
- Webshell deployment attempts
- FTP credential testing
- SSH brute force attacks

### 3. Advanced Analysis

#### Comprehensive Attack Analysis
```powershell
python analysis/comprehensive_attack_analysis.py logs/honeypot_events.jsonl
```

Generates:
- Attack timeline analysis
- HTTP attack patterns
- Service targeting distribution
- Attack persistence metrics

#### MITRE ATT&CK Threat Analysis
```powershell
python analysis/advanced_threat_analysis.py logs/honeypot_events.jsonl
```

Features:
- **8 MITRE ATT&CK techniques** classification
- Behavioral sophistication scoring
- Threat intelligence correlation
- Security recommendations

#### Interactive Security Dashboard
```powershell
python analysis/dashboard_generator.py logs/honeypot_events.jsonl
```

Creates a professional HTML dashboard with:
- All visualizations embedded
- Executive summary
- Key findings and recommendations
- Interactive navigation

## 📊 Analysis Outputs

### Generated Visualizations
1. **`attack_timeline_analysis.png`** - Comprehensive 4-panel timeline
2. **`http_attack_analysis.png`** - HTTP-specific attack patterns
3. **`attack_patterns_analysis.png`** - Behavioral and persistence analysis
4. **`mitre_attack_heatmap.png`** - MITRE ATT&CK technique classification
5. **`behavioral_analysis.png`** - 6-panel behavioral analysis

### Reports
- **`threat_intelligence_report.txt`** - Technical threat analysis
- **`executive_summary.txt`** - Business-focused summary
- **`security_dashboard.html`** - Interactive web dashboard

## 🔍 Sample Analysis Results

### MITRE ATT&CK Techniques Detected
- **T1190**: Exploit Public-Facing Application
- **T1212**: Exploitation for Credential Access (SQL injection)
- **T1505**: Server Software Component (webshells)
- **T1110**: Brute Force attacks
- **T1083**: File and Directory Discovery
- **T1055**: Process Injection (XSS)

### Key Metrics
- **234 attack events** analyzed in sample run
- **70.9% HTTP attacks** (primary vector)
- **19.7% SSH attacks** (brute force)
- **9.4% FTP attacks** (credential testing)

## 🛡️ Security Insights

The analysis system provides:
- **Attack sophistication scoring** (1-10 scale)
- **Threat level assessment** (LOW/MEDIUM/HIGH/CRITICAL)
- **Service targeting patterns**
- **Attack persistence analysis**
- **Professional security recommendations**

## 📋 Basic Log Analysis (Legacy)
```powershell
python -m honeypot.services.analyzer --limit 100
```

## 🌐 Viewing Results

Open the generated dashboard:
```powershell
explorer analysis\security_dashboard.html
```

Or manually navigate to: `C:\Users\[username]\HoneyPot\analysis\security_dashboard.html`

## 🎯 Use Cases

- **Security Research** - Analyze attack patterns and techniques
- **Threat Intelligence** - Understand attacker behavior
- **Security Training** - Demonstrate common attack vectors
- **Penetration Testing** - Validate security controls
- **Incident Response** - Practice threat analysis

## 📁 Project Structure

```
HoneyPot/
├── analysis/                    # Advanced analysis tools
│   ├── comprehensive_attack_analysis.py
│   ├── advanced_threat_analysis.py
│   ├── dashboard_generator.py
│   ├── charts/                 # Generated visualizations
│   └── security_dashboard.html # Interactive dashboard
├── attacker_sim/              # Attack simulation
├── honeypot/                  # Core honeypot services
├── logs/                      # Attack logs (JSON format)
└── requirements.txt          # Python dependencies
```

## 🔧 Dependencies

- **pandas** - Data analysis and manipulation
- **matplotlib** - Visualization and plotting
- **seaborn** - Statistical visualization
- **numpy** - Numerical computing
- **requests** - HTTP library for attack simulation

## ⚠️ Security Notice

This honeypot is designed for **research and educational purposes** in controlled environments. Always ensure:
- Deploy in isolated networks
- Monitor resource usage
- Follow responsible disclosure practices
- Comply with local laws and regulations

## 📈 Future Enhancements

- Real-time threat detection
- Machine learning-based anomaly detection
- Geographic attack mapping
- Advanced correlation analysis
- API integration for threat feeds