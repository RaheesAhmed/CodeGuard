/**
 * Security Scorer
 * Calculates overall security scores and generates fixes
 */

import { SecurityScore, Vulnerability, Secret, SecurityFix, SeverityLevel } from '../types.js';

export class SecurityScorer {
  /**
   * Calculate overall security score
   */
  static calculateOverallScore(
    vulnScore: number,
    secretScore: number,
    complianceScore: number
  ): SecurityScore {
    // Weighted average: vulnerabilities (40%), secrets (35%), compliance (25%)
    const overall = Math.round(
      (vulnScore * 0.4) + (secretScore * 0.35) + (complianceScore * 0.25)
    );

    return {
      overall,
      breakdown: {
        vulnerabilities: vulnScore,
        secrets: secretScore,
        compliance: complianceScore
      },
      grade: this.getGrade(overall)
    };
  }

  /**
   * Get letter grade from score
   */
  private static getGrade(score: number): 'A+' | 'A' | 'B' | 'C' | 'D' | 'F' {
    if (score >= 97) return 'A+';
    if (score >= 90) return 'A';
    if (score >= 80) return 'B';
    if (score >= 70) return 'C';
    if (score >= 60) return 'D';
    return 'F';
  }

  /**
   * Generate security fixes for vulnerabilities
   */
  static generateFixes(vulnerabilities: Vulnerability[]): SecurityFix[] {
    return vulnerabilities
      .filter(v => v.severity === 'critical' || v.severity === 'high')
      .slice(0, 5) // Top 5 most critical
      .map(vuln => this.generateFix(vuln));
  }

  /**
   * Generate a single security fix
   */
  private static generateFix(vulnerability: Vulnerability): SecurityFix {
    const fixes: Record<string, { fixed: string; explanation: string; tips: string[] }> = {
      sql_injection: {
        fixed: `// Use parameterized queries\nconst user = await db.query('SELECT * FROM users WHERE id = ?', [userId]);`,
        explanation: 'Parameterized queries prevent SQL injection by separating SQL code from data',
        tips: [
          'Always use parameterized queries or prepared statements',
          'Never concatenate user input into SQL queries',
          'Use an ORM like Prisma, TypeORM, or Sequelize',
          'Validate and sanitize all user inputs'
        ]
      },
      xss: {
        fixed: `// Use textContent or sanitize HTML\nelement.textContent = userInput;\n// Or use DOMPurify\nelement.innerHTML = DOMPurify.sanitize(userInput);`,
        explanation: 'textContent or DOMPurify prevents XSS by safely handling user input',
        tips: [
          'Use textContent instead of innerHTML when possible',
          'Sanitize HTML with DOMPurify or similar library',
          'Implement Content Security Policy (CSP) headers',
          'Validate and escape all user input before rendering'
        ]
      },
      command_injection: {
        fixed: `// Use spawn with argument array\nimport { spawn } from 'child_process';\nconst child = spawn('command', [arg1, arg2]);`,
        explanation: 'spawn with argument array prevents command injection by not invoking a shell',
        tips: [
          'Use child_process.spawn() instead of exec()',
          'Pass arguments as an array, not a string',
          'Validate all user inputs strictly',
          'Use allowlists for permitted commands/arguments'
        ]
      },
      path_traversal: {
        fixed: `// Validate and normalize paths\nimport path from 'path';\nconst safePath = path.resolve(basePath, path.normalize(userPath));\nif (!safePath.startsWith(basePath)) throw new Error('Invalid path');`,
        explanation: 'Path normalization and validation prevents directory traversal',
        tips: [
          'Use path.resolve() and path.normalize()',
          'Check that resolved path starts with expected base path',
          'Never trust user-supplied file paths',
          'Use allowlists for permitted directories'
        ]
      },
      insecure_deserialization: {
        fixed: `// Safe JSON parsing with validation\ntry {\n  const data = JSON.parse(input);\n  // Validate schema\n  if (!isValidData(data)) throw new Error('Invalid data');\n} catch (error) {\n  // Handle error\n}`,
        explanation: 'Never use eval(). Use JSON.parse with proper error handling and validation',
        tips: [
          'Never use eval() or Function() constructor',
          'Always wrap JSON.parse in try-catch',
          'Validate deserialized data against a schema',
          'Use libraries like Zod or Joi for validation'
        ]
      },
      crypto_failure: {
        fixed: `// Use strong cryptography\nimport crypto from 'crypto';\nconst hash = crypto.createHash('sha256').update(data).digest('hex');\n// For random values\nconst random = crypto.randomBytes(32).toString('hex');`,
        explanation: 'Use SHA-256 or stronger for hashing, and crypto.randomBytes for randomness',
        tips: [
          'Use SHA-256, SHA-3, or bcrypt for passwords',
          'Never use MD5 or SHA-1',
          'Use crypto.randomBytes() instead of Math.random()',
          'Keep cryptographic libraries updated'
        ]
      },
      authentication_failure: {
        fixed: `// Use bcrypt for password hashing\nimport bcrypt from 'bcrypt';\nconst hashedPassword = await bcrypt.hash(password, 10);\nconst isValid = await bcrypt.compare(inputPassword, hashedPassword);`,
        explanation: 'bcrypt properly hashes passwords with salt and makes brute-force attacks difficult',
        tips: [
          'Never store passwords in plaintext',
          'Use bcrypt, argon2, or scrypt for password hashing',
          'Implement rate limiting on login attempts',
          'Use multi-factor authentication'
        ]
      },
      security_misconfiguration: {
        fixed: `// Configure CORS properly\napp.use(cors({\n  origin: ['https://trusted-domain.com'],\n  credentials: true,\n  methods: ['GET', 'POST']\n}));`,
        explanation: 'Specific CORS configuration prevents unauthorized cross-origin requests',
        tips: [
          'Never use wildcard (*) for CORS origin in production',
          'Configure security headers (helmet.js)',
          'Disable unnecessary features and endpoints',
          'Keep all dependencies updated'
        ]
      },
      ssrf: {
        fixed: `// Validate and whitelist URLs\nconst allowedDomains = ['api.example.com'];\nconst url = new URL(userInput);\nif (!allowedDomains.includes(url.hostname)) {\n  throw new Error('Unauthorized domain');\n}`,
        explanation: 'URL validation and domain whitelisting prevents SSRF attacks',
        tips: [
          'Validate all URLs before making requests',
          'Use allowlists for permitted domains',
          'Implement network segmentation',
          'Disable unnecessary URL schemes (file://, gopher://)'
        ]
      },
      broken_access_control: {
        fixed: `// Implement proper authorization\nif (user.id !== resource.ownerId && !user.isAdmin) {\n  throw new ForbiddenError('Access denied');\n}`,
        explanation: 'Always verify user has permission to access the resource',
        tips: [
          'Implement role-based access control (RBAC)',
          'Check permissions on every request',
          'Use the principle of least privilege',
          'Log all access control failures'
        ]
      },
      data_integrity_failure: {
        fixed: `// Implement data validation\nimport { z } from 'zod';\nconst schema = z.object({ email: z.string().email() });\nconst validatedData = schema.parse(input);`,
        explanation: 'Schema validation ensures data integrity',
        tips: [
          'Validate all inputs against schemas',
          'Implement checksums for critical data',
          'Use digital signatures for sensitive operations',
          'Monitor for data integrity violations'
        ]
      },
      logging_failure: {
        fixed: `// Implement comprehensive logging\nlogger.info('User login', { userId, ip, timestamp });\n// Don't log sensitive data\nlogger.info('Password reset', { userId }); // Not the password!`,
        explanation: 'Log security events but never log sensitive data',
        tips: [
          'Log all authentication attempts',
          'Never log passwords, tokens, or secrets',
          'Include context (user, IP, timestamp)',
          'Monitor logs for suspicious activity'
        ]
      },
      race_condition: {
        fixed: `// Use proper locking\nawait db.transaction(async (trx) => {\n  const account = await trx('accounts').where({id}).forUpdate().first();\n  // Perform operations\n  await trx('accounts').where({id}).update({balance});\n});`,
        explanation: 'Database transactions with locks prevent race conditions',
        tips: [
          'Use database transactions',
          'Implement optimistic or pessimistic locking',
          'Use atomic operations when possible',
          'Test for race conditions'
        ]
      },
      buffer_overflow: {
        fixed: `// Use safe string functions\nconst buffer = Buffer.alloc(size);\n// Validate input length\nif (input.length > buffer.length) {\n  throw new Error('Input too large');\n}`,
        explanation: 'Buffer size validation prevents overflow',
        tips: [
          'Always validate buffer sizes',
          'Use safe string functions',
          'Enable stack protection',
          'Use modern languages with built-in protections'
        ]
      }
    };

    const fix = fixes[vulnerability.type as keyof typeof fixes] || {
      fixed: '// Review and fix the security issue',
      explanation: 'Manual review required',
      tips: ['Consult security documentation', 'Get security review']
    };

    return {
      vulnerability,
      original: vulnerability.code,
      fixed: fix.fixed,
      explanation: fix.explanation,
      preventionTips: fix.tips
    };
  }
}