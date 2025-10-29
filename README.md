# 🛡️ CodeGuard MCP

Real-time AI code security scanner for detecting vulnerabilities, secrets, and compliance issues in AI-generated code.

## 🎯 Overview

CodeGuard MCP is a **Model Context Protocol (MCP) server** that provides comprehensive security scanning capabilities for AI coding assistants like Claude Desktop, Cursor, VS Code, and any MCP-compatible tool.

### Why CodeGuard MCP?

AI coding tools are powerful but can generate code with security vulnerabilities. CodeGuard addresses this critical gap by:

- 🔍 **Real-time vulnerability detection** - Catches security issues as code is generated
- 🔐 **Secret detection** - Finds exposed API keys, passwords, and credentials
- 📋 **Compliance checking** - Validates against GDPR, HIPAA, SOC2, PCI DSS
- 💡 **Instant fixes** - Provides secure code alternatives
- ⚡ **Fast scanning** - Results in < 2 seconds
- 🎯 **OWASP Top 10** - Detects all major security risks

## 🚀 Quick Start

### Installation

```bash
npm install -g codeguard-mcp
```

### Usage with Claude Desktop

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "CodeGuard": {
      "command": "npx",
      "args": ["-y", "codeguard-mcp"]
    }
  }
}
```

### Usage with Cursor

1. Open Cursor settings
2. Navigate to MCP Servers
3. Add CodeGuard MCP
4. Restart Cursor

## 📊 Features

### Core Scanning Tool

**`scanCode`** - Comprehensive security scan

```typescript
// Example usage in AI assistant
scanCode({
  code: "const user = db.query(`SELECT * FROM users WHERE id = ${userId}`);",
  language: "javascript",
  securityLevel: "standard"
})

// Returns:
{
  score: {
    overall: 45,
    breakdown: {
      vulnerabilities: 30,
      secrets: 100,
      compliance: 75
    },
    grade: "F"
  },
  vulnerabilities: {
    critical: [
      {
        type: "sql_injection",
        severity: "critical",
        line: 1,
        message: "SQL Injection vulnerability: Using template literals in SQL queries",
        cwe: "CWE-89",
        owasp: "A03:2021 – Injection",
        recommendation: "Use parameterized queries or prepared statements..."
      }
    ]
  },
  suggestedFixes: [...]
}
```

### Quick Scans

**`scanVulnerabilities`** - Fast vulnerability-only scan

```typescript
scanVulnerabilities({ code, language })
```

**`detectSecrets`** - Find exposed secrets

```typescript
detectSecrets({ code })
// Detects: API keys, passwords, tokens, private keys, connection strings, etc.
```

**`checkCompliance`** - Regulatory compliance check

```typescript
checkCompliance({ 
  code, 
  securityLevel: "strict",
  standards: ["GDPR", "HIPAA"]
})
```

### Security Fixes

**`suggestSecureFix`** - Generate secure code alternatives

```typescript
suggestSecureFix({ vulnerability, context })
// Returns step-by-step fix with explanation
```

## 🛡️ Detected Vulnerabilities

### OWASP Top 10 Coverage

✅ **A01** - Broken Access Control  
✅ **A02** - Cryptographic Failures  
✅ **A03** - Injection (SQL, XSS, Command)  
✅ **A04** - Insecure Design  
✅ **A05** - Security Misconfiguration  
✅ **A06** - Vulnerable Components  
✅ **A07** - Authentication Failures  
✅ **A08** - Data Integrity Failures  
✅ **A09** - Logging Failures  
✅ **A10** - Server-Side Request Forgery  

### Secret Detection

- API Keys (Generic, AWS, Azure, GCP)
- Passwords & Credentials
- Private Keys (RSA, EC, SSH)
- Database Connection Strings
- OAuth & JWT Tokens
- Webhook URLs (Slack, Discord)

### Compliance Standards

- **GDPR** - Data privacy & protection
- **HIPAA** - Healthcare data security
- **SOC2** - Security controls
- **PCI DSS** - Payment card security

## 📖 Examples

### Example 1: Detecting SQL Injection

**Vulnerable Code:**
```javascript
const getUserById = (userId) => {
  return db.query(`SELECT * FROM users WHERE id = ${userId}`);
};
```

**CodeGuard Response:**
```json
{
  "vulnerabilities": {
    "critical": [{
      "type": "sql_injection",
      "severity": "critical",
      "message": "SQL Injection vulnerability",
      "recommendation": "Use parameterized queries"
    }]
  },
  "suggestedFix": {
    "fixed": "const getUserById = (userId) => {\n  return db.query('SELECT * FROM users WHERE id = ?', [userId]);\n};"
  }
}
```

### Example 2: Detecting Exposed Secrets

**Vulnerable Code:**
```javascript
const API_KEY = "sk_live_51H7xY2eZvKYlo2C8Nz9";
const config = {
  databaseUrl: "mongodb://admin:password123@localhost:27017"
};
```

**CodeGuard Response:**
```json
{
  "secrets": [
    {
      "type": "api_key",
      "line": 1,
      "masked": "sk_l***************2C8Nz9",
      "confidence": 95
    },
    {
      "type": "connection_string",
      "line": 3,
      "masked": "mongodb://***",
      "confidence": 95
    }
  ]
}
```

### Example 3: GDPR Compliance Check

**Code:**
```javascript
app.post('/signup', (req, res) => {
  const email = req.body.email;
  db.users.insert({ email, password: req.body.password });
});
```

**CodeGuard Response:**
```json
{
  "compliance": {
    "failed": [{
      "standard": "GDPR",
      "severity": "critical",
      "issue": "Collecting personal data (email) without explicit consent",
      "requirement": "Article 7: Conditions for consent",
      "remediation": "Implement explicit consent collection before gathering personal data"
    }]
  }
}
```

## 🎓 Resources

### MCP Resources

- **`security://score`** - Real-time security score dashboard
- **`security://owasp-top-10`** - OWASP Top 10 reference

### MCP Prompts

- **`securityReview`** - Generate comprehensive security review
- **`fixVulnerability`** - Get step-by-step vulnerability fixes

## 📊 Security Scoring

CodeGuard uses a weighted scoring system:

- **Vulnerabilities**: 40% weight
- **Secrets**: 35% weight
- **Compliance**: 25% weight

**Grading Scale:**
- **A+**: 97-100 (Excellent)
- **A**: 90-96 (Very Good)
- **B**: 80-89 (Good)
- **C**: 70-79 (Fair)
- **D**: 60-69 (Poor)
- **F**: <60 (Critical Issues)

## 🏢 Enterprise Features

(Coming in v2.0)

- Custom security rules
- Team dashboards
- Audit logs
- SSO integration
- CI/CD integration
- On-premise deployment

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🔗 Links


- **GitHub**: [https://github.com/RaheesAhmed/CodeGuard](https://github.com/RaheesAhmed/CodeGuard)
- **Issues**: [https://github.com/RaheesAhmed/CodeGuard/issues](https://github.com/RaheesAhmed/CodeGuard/issues)

## 💡 Support

- 📧 Email: rahesahmed37@gmail.com
- 🐛 Bug Reports: [GitHub Issues](https://github.com/RaheesAhmed/CodeGuard/issues)

---

**Built with ❤️ using [QuickMCP SDK](https://github.com/RaheesAhmed/QuickMCP)**

*Making AI coding safer, one scan at a time.* 🛡️