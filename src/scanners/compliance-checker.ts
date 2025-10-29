/**
 * Compliance Checker
 * Checks code for compliance with regulatory standards
 */

import { ComplianceIssue, ComplianceStandard, SeverityLevel, SecurityLevel } from '../types.js';

export class ComplianceChecker {
  /**
   * Check code for compliance issues
   */
  static async check(code: string, securityLevel: SecurityLevel): Promise<{
    passed: ComplianceIssue[];
    failed: ComplianceIssue[];
    warnings: ComplianceIssue[];
  }> {
    const issues: ComplianceIssue[] = [];
    const lines = code.split('\n');

    // Run all compliance checks
    issues.push(...await this.checkGDPR(code, lines));
    issues.push(...await this.checkHIPAA(code, lines));
    issues.push(...await this.checkSOC2(code, lines));
    issues.push(...await this.checkPCIDSS(code, lines));

    // Categorize by severity
    const failed = issues.filter(i => i.severity === 'critical' || i.severity === 'high');
    const warnings = issues.filter(i => i.severity === 'medium' || i.severity === 'low');
    const passed: ComplianceIssue[] = [];

    return { passed, failed, warnings };
  }

  /**
   * GDPR Compliance Checks
   */
  private static async checkGDPR(code: string, lines: string[]): Promise<ComplianceIssue[]> {
    const issues: ComplianceIssue[] = [];

    // Check for personal data handling
    lines.forEach((line, idx) => {
      // Check for email collection without consent
      if (line.match(/(?:email|e-mail).*=.*input/i) && !code.includes('consent') && !code.includes('gdpr')) {
        issues.push({
          standard: 'GDPR',
          severity: 'high',
          line: idx + 1,
          issue: 'Collecting personal data (email) without explicit consent mechanism',
          requirement: 'Article 7: Conditions for consent',
          remediation: 'Implement explicit consent collection before gathering personal data'
        });
      }

      // Check for data retention
      if (line.match(/delete.*user/i) || line.match(/remove.*data/i)) {
        if (!code.includes('retention') && !code.includes('delete')) {
          issues.push({
            standard: 'GDPR',
            severity: 'medium',
            line: idx + 1,
            issue: 'No clear data retention policy implementation',
            requirement: 'Article 17: Right to erasure',
            remediation: 'Implement data retention policies and automated deletion'
          });
        }
      }

      // Check for data encryption
      if (line.match(/password|creditcard|ssn|personal.*data/i)) {
        if (!code.includes('encrypt') && !code.includes('hash') && !code.includes('bcrypt')) {
          issues.push({
            standard: 'GDPR',
            severity: 'critical',
            line: idx + 1,
            issue: 'Personal data stored without encryption',
            requirement: 'Article 32: Security of processing',
            remediation: 'Encrypt all personal data at rest and in transit'
          });
        }
      }
    });

    return issues;
  }

  /**
   * HIPAA Compliance Checks
   */
  private static async checkHIPAA(code: string, lines: string[]): Promise<ComplianceIssue[]> {
    const issues: ComplianceIssue[] = [];

    lines.forEach((line, idx) => {
      // Check for PHI (Protected Health Information)
      if (line.match(/medical|health|patient|diagnosis|treatment/i)) {
        // Check for audit logs
        if (!code.includes('audit') && !code.includes('log')) {
          issues.push({
            standard: 'HIPAA',
            severity: 'critical',
            line: idx + 1,
            issue: 'PHI access without audit logging',
            requirement: 'HIPAA Security Rule §164.308(a)(1)(ii)(D)',
            remediation: 'Implement comprehensive audit logging for all PHI access'
          });
        }

        // Check for encryption
        if (!code.includes('encrypt')) {
          issues.push({
            standard: 'HIPAA',
            severity: 'critical',
            line: idx + 1,
            issue: 'PHI transmitted without encryption',
            requirement: 'HIPAA Security Rule §164.312(e)(1)',
            remediation: 'Use TLS 1.2+ for all PHI transmission'
          });
        }

        // Check for access controls
        if (!code.includes('auth') && !code.includes('permission')) {
          issues.push({
            standard: 'HIPAA',
            severity: 'high',
            line: idx + 1,
            issue: 'PHI accessible without proper authorization',
            requirement: 'HIPAA Security Rule §164.312(a)(1)',
            remediation: 'Implement role-based access control for PHI'
          });
        }
      }
    });

    return issues;
  }

  /**
   * SOC 2 Compliance Checks
   */
  private static async checkSOC2(code: string, lines: string[]): Promise<ComplianceIssue[]> {
    const issues: ComplianceIssue[] = [];

    lines.forEach((line, idx) => {
      // Check for logging
      if (line.match(/(?:login|authenticate|access)/i)) {
        if (!code.includes('log') && !code.includes('logger')) {
          issues.push({
            standard: 'SOC2',
            severity: 'high',
            line: idx + 1,
            issue: 'Security events not logged',
            requirement: 'CC6.8: Logging and Monitoring',
            remediation: 'Implement comprehensive security event logging'
          });
        }
      }

      // Check for error handling
      if (line.match(/try|catch/i)) {
        if (!line.match(/error.*handler|log.*error/i)) {
          issues.push({
            standard: 'SOC2',
            severity: 'medium',
            line: idx + 1,
            issue: 'Errors not properly handled or logged',
            requirement: 'CC7.2: System monitoring',
            remediation: 'Log all errors with appropriate detail levels'
          });
        }
      }

      // Check for change management
      if (line.match(/deploy|production|release/i)) {
        if (!code.includes('version') && !code.includes('changelog')) {
          issues.push({
            standard: 'SOC2',
            severity: 'medium',
            line: idx + 1,
            issue: 'No version control or change documentation',
            requirement: 'CC8.1: Change Management',
            remediation: 'Implement version control and change documentation'
          });
        }
      }
    });

    return issues;
  }

  /**
   * PCI DSS Compliance Checks
   */
  private static async checkPCIDSS(code: string, lines: string[]): Promise<ComplianceIssue[]> {
    const issues: ComplianceIssue[] = [];

    lines.forEach((line, idx) => {
      // Check for card data
      if (line.match(/card.*number|credit.*card|cvv|expir/i)) {
        // Check for encryption
        if (!code.includes('encrypt') && !code.includes('tokenize')) {
          issues.push({
            standard: 'PCI_DSS',
            severity: 'critical',
            line: idx + 1,
            issue: 'Cardholder data not encrypted',
            requirement: 'PCI DSS Requirement 3: Protect stored cardholder data',
            remediation: 'Encrypt or tokenize all cardholder data'
          });
        }

        // Check for logging
        if (!code.includes('log') && !code.includes('audit')) {
          issues.push({
            standard: 'PCI_DSS',
            severity: 'high',
            line: idx + 1,
            issue: 'Card data access not logged',
            requirement: 'PCI DSS Requirement 10: Track and monitor all access',
            remediation: 'Log all access to cardholder data'
          });
        }

        // Check for direct storage (should not store CVV)
        if (line.match(/cvv|cvc|card.*verification/i) && line.match(/store|save|insert/i)) {
          issues.push({
            standard: 'PCI_DSS',
            severity: 'critical',
            line: idx + 1,
            issue: 'Attempting to store CVV/CVC (prohibited)',
            requirement: 'PCI DSS Requirement 3.2: Do not store sensitive authentication data',
            remediation: 'Never store CVV/CVC codes after authorization'
          });
        }
      }
    });

    return issues;
  }

  /**
   * Calculate compliance score
   */
  static calculateComplianceScore(issues: { failed: ComplianceIssue[]; warnings: ComplianceIssue[] }): number {
    const criticalCount = issues.failed.filter(i => i.severity === 'critical').length;
    const highCount = issues.failed.filter(i => i.severity === 'high').length;
    const mediumCount = issues.warnings.filter(i => i.severity === 'medium').length;
    const lowCount = issues.warnings.filter(i => i.severity === 'low').length;

    const penalty = (criticalCount * 40) + (highCount * 25) + (mediumCount * 10) + (lowCount * 5);
    
    return Math.max(0, 100 - Math.min(penalty, 100));
  }
}