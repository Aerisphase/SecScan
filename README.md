# SecScan - Web Vulnerability Scanner

SecScan is a powerful web vulnerability scanner designed to help security professionals and developers identify and fix security issues in web applications. It combines traditional scanning techniques with modern approaches to provide accurate and efficient security testing.

## 🚀 Features

- **Comprehensive Scanning**: Detect OWASP Top 10 vulnerabilities including SQL Injection, XSS, CSRF, and more
- **Modern Interface**: Clean, intuitive web interface with real-time scanning feedback
- **Advanced Configuration**: Customize scan parameters for optimal results
- **Detailed Reporting**: Export scan results in multiple formats
- **Real-time Terminal**: Monitor scan progress with a built-in terminal interface

## 📋 Requirements

- Python 3.8 or higher
- pip (Python package manager)
- Modern web browser (Chrome, Firefox, Edge recommended)

## 🛠️ Installation

1. Clone the repository:
```bash
git clone https://github.com/Aerisphase/SecScan.git
cd SecScan
```

2. Create and activate a virtual environment:

**Windows:**
```cmd
python -m venv venv
venv\Scripts\activate
```

**Linux/macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## ⚙️ Configuration

1. Create a `.env` file in the project root with the following variables:
```bash
SECSCAN_API_KEY=your_api_key_here
SERVER_HOST=localhost
SERVER_PORT=8000
SSL_CERT_PATH=path/to/your/cert.pem
SSL_KEY_PATH=path/to/your/key.pem
```

## 🏃‍♂️ Quick Start

1. Start the server:
```bash
cd src/server
python server.py
```

2. Access the web interface:
```
https://localhost:8000/static/index.html
```

## 🔧 Usage

### Web Interface
1. Open the web interface in your browser
2. Enter the target URL
3. Configure scan settings:
   - Scan Type (Fast/Full)
   - Maximum Pages
   - Request Delay
   - Custom User-Agent
4. Click "Start Scan"
5. Monitor progress in the terminal
6. View and export results

### Command Line
```bash
python scanner.py --target https://example.com \
                 --scan-type full \
                 --delay 2.0 \
                 --max-pages 50 \
                 --verify-ssl \
                 --proxy http://proxy:8080 \
                 --auth user:pass \
                 --max-retries 5
```

## 📊 Scan Types

- **Fast Scan**: Quick analysis focusing on common vulnerabilities
- **Full Scan**: Comprehensive analysis including advanced checks

## 🔍 Supported Vulnerabilities

- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Server-Side Request Forgery (SSRF)
- XML External Entity (XXE)
- Security Misconfigurations
- Insecure Direct Object References (IDOR)
- Broken Authentication
- Sensitive Data Exposure
- Using Components with Known Vulnerabilities

## 🛡️ Security Features

- Rate limiting to prevent server overload
- Configurable retry mechanism
- SSL/TLS verification
- Proxy support
- Authentication support
- URL validation and sanitization
- Security header analysis

## 📝 Output Formats

- HTML Report
- JSON Export
- Terminal Output
- Real-time Logs






