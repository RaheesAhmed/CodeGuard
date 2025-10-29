# Contributing to CodeGuard MCP

Thanks for your interest in making CodeGuard MCP better! This guide will help you get started.

## Quick Start

### 1. Setup

```bash
# Fork and clone the repo
git clone https://github.com/RaheesAhmed/CodeGuard.git.git
cd CodeGuard-mcp

# Install dependencies
npm install

# Build the project
npm run build

# Run tests
npm test
```

### 2. Make Your Changes

- Fix bugs
- Add new security detection patterns
- Improve documentation
- Add test cases
- Optimize performance

### 3. Test Your Changes

```bash
# Run tests
npm test

# Check your code
npm run lint
```

### 4. Submit Your Changes

```bash
# Commit with a clear message
git commit -m "fix: improve SQL injection detection"

# Push to your fork
git push origin your-branch-name

# Open a Pull Request on GitHub
```

## Coding Guidelines

- Use TypeScript strict mode
- Add tests for new features
- Keep code clean and readable
- No console.log in production code
- Follow existing code style

## Commit Message Format

```
feat: add new feature
fix: fix a bug
docs: update documentation
test: add or update tests
refactor: refactor code
```

## Project Structure

```
src/
├── index.ts                    # Main entry point
├── types.ts                    # Type definitions
├── scanners/
│   ├── vulnerability-scanner.ts    # Vulnerability detection
│   ├── secret-detector.ts          # Secret detection
│   └── compliance-checker.ts       # Compliance checking
└── utils/
    └── security-scorer.ts          # Security scoring
```

## Need Help?

- Open an issue on [GitHub](https://github.com/RaheesAhmed/CodeGuard/issues)
- Email: rahesahmed37@gmail.com

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thanks for contributing! 🛡️
