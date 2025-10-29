/**
 * CodeGuard MCP - Type Definitions
 */

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type SecurityLevel = 'basic' | 'standard' | 'strict';
export type VulnerabilityType = 'sql_injection' | 'xss' | 'path_traversal' | 'command_injection' | 
  'insecure_deserialization' | 'broken_access_control' | 'crypto_failure' | 'insecure_design' |
  'security_misconfiguration' | 'authentication_failure' | 'data_integrity_failure' | 
  'logging_failure' | 'ssrf' | 'race_condition' | 'buffer_overflow';

export type SecretType = 'api_key' | 'password' | 'token' | 'private_key' | 'connection_string' |
  'aws_key' | 'azure_key' | 'gcp_key' | 'oauth_token' | 'webhook_url' | 'jwt';

export type ComplianceStandard = 'GDPR' | 'HIPAA' | 'SOC2' | 'PCI_DSS' | 'ISO_27001';

export interface Vulnerability {
  type: VulnerabilityType;
  severity: SeverityLevel;
  line: number;
  column?: number;
  message: string;
  code: string;
  cwe?: string; // Common Weakness Enumeration ID
  owasp?: string; // OWASP category
  recommendation: string;
}

export interface Secret {
  type: SecretType;
  line: number;
  column?: number;
  value: string;
  masked: string;
  confidence: number; // 0-100
}

export interface ComplianceIssue {
  standard: ComplianceStandard;
  severity: SeverityLevel;
  line: number;
  issue: string;
  requirement: string;
  remediation: string;
}

export interface SecurityScore {
  overall: number; // 0-100
  breakdown: {
    vulnerabilities: number;
    secrets: number;
    compliance: number;
  };
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
}

export interface ScanResult {
  score: SecurityScore;
  vulnerabilities: {
    critical: Vulnerability[];
    high: Vulnerability[];
    medium: Vulnerability[];
    low: Vulnerability[];
    info: Vulnerability[];
  };
  secrets: Secret[];
  compliance: {
    passed: ComplianceIssue[];
    failed: ComplianceIssue[];
    warnings: ComplianceIssue[];
  };
  suggestedFixes: SecurityFix[];
  scanTime: string;
  language: string;
  linesScanned: number;
}

export interface SecurityFix {
  vulnerability: Vulnerability;
  original: string;
  fixed: string;
  explanation: string;
  preventionTips: string[];
}

export interface ScanOptions {
  code: string;
  language: string;
  securityLevel?: SecurityLevel;
  checkCompliance?: boolean;
  complianceStandards?: ComplianceStandard[];
}