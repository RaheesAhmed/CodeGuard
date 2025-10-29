/**
 * Secret Detector
 * Detects exposed secrets, API keys, passwords, and credentials
 */

import { Secret, SecretType } from '../types.js';

export class SecretDetector {
  private static readonly PATTERNS = {
    // API Keys
    api_key: [
      {
        pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*['"`]([a-zA-Z0-9_\-]{20,})['"`]/gi,
        type: 'api_key' as SecretType,
        confidence: 90
      },
      {
        pattern: /AKIA[0-9A-Z]{16}/g,
        type: 'aws_key' as SecretType,
        confidence: 95
      }
    ],

    // Passwords
    password: [
      {
        pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"`]([^'"`\s]{6,})['"`]/gi,
        type: 'password' as SecretType,
        confidence: 85
      }
    ],

    // Tokens
    token: [
      {
        pattern: /(?:token|auth[_-]?token|access[_-]?token)\s*[:=]\s*['"`]([a-zA-Z0-9_\-\.]{20,})['"`]/gi,
        type: 'token' as SecretType,
        confidence: 85
      },
      {
        pattern: /ghp_[a-zA-Z0-9]{36}/g,
        type: 'token' as SecretType,
        confidence: 100
      },
      {
        pattern: /gho_[a-zA-Z0-9]{36}/g,
        type: 'token' as SecretType,
        confidence: 100
      }
    ],

    // Private Keys
    private_key: [
      {
        pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
        type: 'private_key' as SecretType,
        confidence: 100
      }
    ],

    // Connection Strings
    connection_string: [
      {
        pattern: /(?:mongodb|mysql|postgresql|postgres):\/\/[^:]+:[^@]+@[^\s'"`]+/gi,
        type: 'connection_string' as SecretType,
        confidence: 95
      },
      {
        pattern: /Server=.+;Database=.+;(?:User Id|UID)=.+;Password=.+;/gi,
        type: 'connection_string' as SecretType,
        confidence: 95
      }
    ],

    // AWS Credentials
    aws_key: [
      {
        pattern: /AKIA[0-9A-Z]{16}/g,
        type: 'aws_key' as SecretType,
        confidence: 95
      },
      {
        pattern: /aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*['"`]([a-zA-Z0-9\/\+]{40})['"`]/gi,
        type: 'aws_key' as SecretType,
        confidence: 90
      }
    ],

    // Azure Keys
    azure_key: [
      {
        pattern: /(?:DefaultEndpointsProtocol=https;AccountName=.+;AccountKey=)([a-zA-Z0-9+\/=]{88})/g,
        type: 'azure_key' as SecretType,
        confidence: 95
      }
    ],

    // GCP Keys
    gcp_key: [
      {
        pattern: /"type":\s*"service_account"/g,
        type: 'gcp_key' as SecretType,
        confidence: 80
      }
    ],

    // OAuth Tokens
    oauth_token: [
      {
        pattern: /(?:oauth|bearer)\s+[a-zA-Z0-9_\-\.=]{20,}/gi,
        type: 'oauth_token' as SecretType,
        confidence: 75
      }
    ],

    // JWT
    jwt: [
      {
        pattern: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g,
        type: 'jwt' as SecretType,
        confidence: 90
      }
    ],

    // Webhook URLs
    webhook_url: [
      {
        pattern: /https:\/\/hooks\.slack\.com\/services\/[A-Z0-9]+\/[A-Z0-9]+\/[a-zA-Z0-9]+/g,
        type: 'webhook_url' as SecretType,
        confidence: 100
      },
      {
        pattern: /https:\/\/discord\.com\/api\/webhooks\/[0-9]+\/[a-zA-Z0-9_-]+/g,
        type: 'webhook_url' as SecretType,
        confidence: 100
      }
    ]
  };

  /**
   * Detect secrets in code
   */
  static async findSecrets(code: string): Promise<Secret[]> {
    const secrets: Secret[] = [];
    const lines = code.split('\n');

    // Skip comments and common false positives
    const cleanedLines = lines.map((line, idx) => ({
      text: line,
      index: idx
    })).filter(({ text }) => {
      // Skip comments
      if (text.trim().startsWith('//') || text.trim().startsWith('#') || text.trim().startsWith('*')) {
        return false;
      }
      // Skip example/placeholder strings
      if (text.includes('YOUR_API_KEY') || text.includes('example.com') || 
          text.includes('placeholder') || text.includes('TODO')) {
        return false;
      }
      return true;
    });

    // Scan for each secret type
    for (const [secretType, patterns] of Object.entries(this.PATTERNS)) {
      for (const patternDef of patterns) {
        cleanedLines.forEach(({ text, index }) => {
          const matches = text.matchAll(new RegExp(patternDef.pattern.source, patternDef.pattern.flags));
          
          for (const match of matches) {
            if (match.index !== undefined && match[0]) {
              const value = match[1] || match[0];
              secrets.push({
                type: patternDef.type,
                line: index + 1,
                column: match.index,
                value: value,
                masked: this.maskSecret(value),
                confidence: patternDef.confidence
              });
            }
          }
        });
      }
    }

    // Remove duplicates
    return this.deduplicateSecrets(secrets);
  }

  /**
   * Mask secret value for display
   */
  private static maskSecret(value: string): string {
    if (value.length <= 8) {
      return '***';
    }
    const visibleChars = Math.min(4, Math.floor(value.length * 0.2));
    const start = value.substring(0, visibleChars);
    const end = value.substring(value.length - visibleChars);
    return `${start}${'*'.repeat(Math.max(3, value.length - visibleChars * 2))}${end}`;
  }

  /**
   * Remove duplicate secrets
   */
  private static deduplicateSecrets(secrets: Secret[]): Secret[] {
    const seen = new Set<string>();
    return secrets.filter(secret => {
      const key = `${secret.type}:${secret.line}:${secret.value}`;
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    });
  }

  /**
   * Calculate secret detection score
   */
  static calculateSecretScore(secrets: Secret[]): number {
    if (secrets.length === 0) return 100;

    // High confidence secrets are more severe
    const highConfidenceCount = secrets.filter(s => s.confidence >= 90).length;
    const mediumConfidenceCount = secrets.filter(s => s.confidence >= 70 && s.confidence < 90).length;
    const lowConfidenceCount = secrets.length - highConfidenceCount - mediumConfidenceCount;

    const penalty = (highConfidenceCount * 30) + (mediumConfidenceCount * 15) + (lowConfidenceCount * 5);
    
    return Math.max(0, 100 - Math.min(penalty, 100));
  }
}