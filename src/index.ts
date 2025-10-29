#!/usr/bin/env node

/**
 * CodeGuard MCP Server
 * Real-time AI code security scanner
 */

import { createServer, Responses, Resources, Prompts, Schema } from 'quickmcp-sdk';
import { VulnerabilityScanner } from './scanners/vulnerability-scanner.js';
import { SecretDetector } from './scanners/secret-detector.js';
import { ComplianceChecker } from './scanners/compliance-checker.js';
import { SecurityScorer } from './utils/security-scorer.js';
import { ScanResult, Vulnerability, SecurityLevel } from './types.js';

// Create MCP server
const server = createServer({
  name: 'codeguard-mcp',
  debug: true
});

console.log("🛡️  CodeGuard MCP Server starting...");

/**
 * Main Tool: Comprehensive Security Scan
 */
server.tool('scanCode', async (args) => {
  const { code, language, securityLevel = 'standard' } = args as {
    code: string;
    language: string;
    securityLevel?: SecurityLevel;
  };

  try {
    const startTime = Date.now();

    // Run all scans in parallel for performance
    const [vulnerabilities, secrets, compliance] = await Promise.all([
      VulnerabilityScanner.scan(code, language),
      SecretDetector.findSecrets(code),
      ComplianceChecker.check(code, securityLevel)
    ]);

    // Calculate scores
    const vulnScore = VulnerabilityScanner.calculateSeverityScore(vulnerabilities);
    const secretScore = SecretDetector.calculateSecretScore(secrets);
    const complianceScore = ComplianceChecker.calculateComplianceScore(compliance);
    
    const score = SecurityScorer.calculateOverallScore(vulnScore, secretScore, complianceScore);

    // Generate fixes for critical issues
    const suggestedFixes = SecurityScorer.generateFixes(vulnerabilities);

    // Categorize vulnerabilities by severity
    const categorizedVulns = {
      critical: vulnerabilities.filter(v => v.severity === 'critical'),
      high: vulnerabilities.filter(v => v.severity === 'high'),
      medium: vulnerabilities.filter(v => v.severity === 'medium'),
      low: vulnerabilities.filter(v => v.severity === 'low'),
      info: vulnerabilities.filter(v => v.severity === 'info')
    };

    const scanTime = ((Date.now() - startTime) / 1000).toFixed(2);
    const linesScanned = code.split('\n').length;

    const result: ScanResult = {
      score,
      vulnerabilities: categorizedVulns,
      secrets: secrets.map(s => ({
        type: s.type,
        line: s.line,
        column: s.column,
        value: s.value,
        masked: s.masked,
        confidence: s.confidence
      })),
      compliance: {
        passed: compliance.passed,
        failed: compliance.failed,
        warnings: compliance.warnings
      },
      suggestedFixes,
      scanTime: new Date().toISOString(),
      language,
      linesScanned
    };

    // Generate summary message
    const totalIssues = vulnerabilities.length + secrets.length + compliance.failed.length;
    const criticalCount = categorizedVulns.critical.length + 
      secrets.filter(s => s.confidence >= 90).length + 
      compliance.failed.filter(i => i.severity === 'critical').length;

    let message = `Security scan complete in ${scanTime}s | Score: ${score.overall}/100 (${score.grade}) | `;
    message += `${totalIssues} issues found`;
    if (criticalCount > 0) {
      message += ` | ⚠️  ${criticalCount} CRITICAL`;
    }

    return Responses.success(result, message);

  } catch (error) {
    return Responses.error(`Security scan failed: ${(error as Error).message}`);
  }
}, {
  description: 'Scan code for security vulnerabilities, secrets, and compliance issues',
  schema: Schema.build({
    code: 'string',
    language: 'string',
    securityLevel: 'string'
  })
});

/**
 * Tool: Quick Vulnerability Scan
 */
server.tool('scanVulnerabilities', async (args) => {
  const { code, language } = args as { code: string; language: string };

  try {
    const vulnerabilities = await VulnerabilityScanner.scan(code, language);
    const score = VulnerabilityScanner.calculateSeverityScore(vulnerabilities);

    const categorized = {
      critical: vulnerabilities.filter(v => v.severity === 'critical'),
      high: vulnerabilities.filter(v => v.severity === 'high'),
      medium: vulnerabilities.filter(v => v.severity === 'medium'),
      low: vulnerabilities.filter(v => v.severity === 'low')
    };

    return Responses.success({
      score,
      total: vulnerabilities.length,
      bySeverity: {
        critical: categorized.critical.length,
        high: categorized.high.length,
        medium: categorized.medium.length,
        low: categorized.low.length
      },
      vulnerabilities: categorized
    }, `Found ${vulnerabilities.length} vulnerabilities | Score: ${score}/100`);

  } catch (error) {
    return Responses.error(`Vulnerability scan failed: ${(error as Error).message}`);
  }
}, {
  description: 'Quick scan for code vulnerabilities only',
  schema: { code: 'string', language: 'string' }
});

/**
 * Tool: Secret Detection
 */
server.tool('detectSecrets', async (args) => {
  const { code } = args as { code: string };

  try {
    const secrets = await SecretDetector.findSecrets(code);
    const score = SecretDetector.calculateSecretScore(secrets);

    const byType = secrets.reduce((acc, secret) => {
      acc[secret.type] = (acc[secret.type] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    return Responses.success({
      score,
      total: secrets.length,
      byType,
      secrets: secrets.map(s => ({
        type: s.type,
        line: s.line,
        masked: s.masked,
        confidence: s.confidence
      }))
    }, `Found ${secrets.length} potential secrets | Score: ${score}/100`);

  } catch (error) {
    return Responses.error(`Secret detection failed: ${(error as Error).message}`);
  }
}, {
  description: 'Detect exposed secrets, API keys, and credentials',
  schema: { code: 'string' }
});

/**
 * Tool: Generate Security Fix
 */
server.tool('suggestSecureFix', async (args) => {
  const { vulnerability, context } = args as {
    vulnerability: Vulnerability;
    context?: string;
  };

  try {
    const fixes = SecurityScorer.generateFixes([vulnerability]);
    
    if (fixes.length === 0) {
      return Responses.error('Could not generate fix for this vulnerability type');
    }

    const fix = fixes[0];

    return Responses.success({
      original: fix.original,
      fixed: fix.fixed,
      explanation: fix.explanation,
      severity: vulnerability.severity,
      preventionTips: fix.preventionTips,
      references: {
        cwe: vulnerability.cwe,
        owasp: vulnerability.owasp
      }
    }, 'Secure fix generated');

  } catch (error) {
    return Responses.error(`Fix generation failed: ${(error as Error).message}`);
  }
}, {
  description: 'Generate secure code fixes for vulnerabilities',
  schema: Schema.build({
    vulnerability: 'object',
    context: 'string'
  })
});

/**
 * Tool: Compliance Check
 */
server.tool('checkCompliance', async (args) => {
  const { code, securityLevel = 'standard', standards } = args as {
    code: string;
    securityLevel?: SecurityLevel;
    standards?: string[];
  };

  try {
    const compliance = await ComplianceChecker.check(code, securityLevel);
    const score = ComplianceChecker.calculateComplianceScore(compliance);

    const byStandard = [...compliance.failed, ...compliance.warnings].reduce((acc, issue) => {
      acc[issue.standard] = (acc[issue.standard] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    return Responses.success({
      score,
      passed: compliance.passed.length,
      failed: compliance.failed.length,
      warnings: compliance.warnings.length,
      byStandard,
      issues: {
        failed: compliance.failed,
        warnings: compliance.warnings
      }
    }, `Compliance check complete | Score: ${score}/100 | ${compliance.failed.length} failures`);

  } catch (error) {
    return Responses.error(`Compliance check failed: ${(error as Error).message}`);
  }
}, {
  description: 'Check code for regulatory compliance (GDPR, HIPAA, SOC2, PCI DSS)',
  schema: Schema.build({
    code: 'string',
    securityLevel: 'string',
    standards: 'array'
  })
});

/**
 * Resource: Security Score Dashboard
 */
server.resource('securityScore', async ({ uri }) => {
  return Resources.json(uri, {
    description: 'Real-time security score and metrics',
    endpoint: 'security://score',
    note: 'Run scanCode to generate current security score'
  });
}, {
  uri: 'security://score',
  description: 'Current security score and metrics dashboard'
});

/**
 * Resource: OWASP Top 10 Reference
 */
server.resource('owaspTop10', async ({ uri }) => {
  return Resources.json(uri, {
    year: 2021,
    categories: [
      'A01:2021 – Broken Access Control',
      'A02:2021 – Cryptographic Failures',
      'A03:2021 – Injection',
      'A04:2021 – Insecure Design',
      'A05:2021 – Security Misconfiguration',
      'A06:2021 – Vulnerable and Outdated Components',
      'A07:2021 – Identification and Authentication Failures',
      'A08:2021 – Software and Data Integrity Failures',
      'A09:2021 – Security Logging and Monitoring Failures',
      'A10:2021 – Server-Side Request Forgery (SSRF)'
    ],
    reference: 'https://owasp.org/Top10/'
  });
}, {
  uri: 'security://owasp-top-10',
  description: 'OWASP Top 10 security risks reference'
});

/**
 * Prompt: Security Review
 */
server.prompt('securityReview', async (args) => {
  const { language, focus = 'general' } = args as {
    language: string;
    focus?: string;
  };

  const prompt = `You are a senior security engineer conducting a code review for ${language} code.

Focus areas: ${focus}

Please review the code and provide feedback on:

🔍 Security Vulnerabilities
- SQL Injection, XSS, Command Injection
- Authentication and Authorization issues
- Cryptographic failures
- Input validation problems

🔐 Secret Management
- Exposed API keys, passwords, tokens
- Hardcoded credentials
- Insecure secret storage

📋 Compliance
- GDPR data privacy
- HIPAA healthcare data protection
- PCI DSS payment card security
- SOC2 security controls

💡 Recommendations
- Provide specific, actionable fixes
- Reference OWASP Top 10 and CWE
- Suggest secure coding alternatives

Be thorough but constructive. Focus on the most critical issues first.`;

  return Prompts.user(prompt);
}, {
  description: 'Generate security review prompts for code analysis',
  schema: { language: 'string', focus: 'string' }
});

/**
 * Prompt: Fix Vulnerability
 */
server.prompt('fixVulnerability', async (args) => {
  const { vulnerabilityType, severity, code } = args as {
    vulnerabilityType: string;
    severity: string;
    code: string;
  };

  const prompt = `Fix this ${severity} ${vulnerabilityType} vulnerability:

\`\`\`
${code}
\`\`\`

Provide:
1. Secure replacement code
2. Explanation of the vulnerability
3. Why the fix works
4. Prevention tips for the future

Keep the fix practical and production-ready.`;

  return Prompts.user(prompt);
}, {
  description: 'Generate prompts for fixing specific vulnerabilities',
  schema: { vulnerabilityType: 'string', severity: 'string', code: 'string' }
});

// Start the server
await server.start();

console.log("✅ CodeGuard MCP Server running");
console.log('📊 Tools: scanCode, scanVulnerabilities, detectSecrets, suggestSecureFix, checkCompliance');
console.log('📚 Resources: securityScore, owaspTop10');
console.log('💬 Prompts: securityReview, fixVulnerability');
console.log('');
console.log('🛡️  Ready to scan AI-generated code for security issues!');