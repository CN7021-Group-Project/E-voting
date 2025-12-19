# Contributing to VoteSecure E-Voting System

Thank you for considering contributing to VoteSecure! This document provides guidelines for contributing to this project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Security Guidelines](#security-guidelines)
- [Testing](#testing)

## Code of Conduct

- Be respectful and inclusive
- Accept constructive criticism gracefully
- Focus on what is best for the community
- Show empathy towards other community members

## Getting Started

1. **Fork the repository**
   ```bash
   git fork https://github.com/CN7021-Group-Project/E-voting.git
   ```

2. **Clone your fork**
   ```bash
   git clone https://github.com/YOUR_USERNAME/E-voting.git
   cd E-voting
   ```

3. **Install dependencies**
   ```bash
   npm install
   ```

4. **Set up the database**
   ```bash
   mysql -u root -p < database/setup.sql
   ```

5. **Configure environment variables**
   - Copy `.env` and update with your settings

6. **Create a new branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Commit Guidelines

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification for commit messages.

### Commit Message Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- **feat**: A new feature
- **fix**: A bug fix
- **docs**: Documentation only changes
- **style**: Changes that don't affect the meaning of the code (white-space, formatting, etc)
- **refactor**: Code change that neither fixes a bug nor adds a feature
- **perf**: Code change that improves performance
- **test**: Adding missing tests or correcting existing tests
- **chore**: Changes to the build process or auxiliary tools
- **security**: Security improvements or vulnerability fixes

### Scope (Optional)

The scope should be the name of the component affected:

- **auth**: Authentication and authorization
- **blockchain**: Blockchain integration
- **voting**: Voting system
- **prediction**: Prediction system
- **api**: API endpoints
- **ui**: User interface
- **db**: Database

### Subject

- Use imperative, present tense: "add" not "added" nor "adds"
- Don't capitalize first letter
- No period (.) at the end
- Maximum 50 characters

### Body (Optional)

- Wrap at 72 characters
- Explain what and why vs. how
- Use bullet points if needed

### Footer (Optional)

- Reference GitHub issues: `Closes #123` or `Fixes #456`
- Note breaking changes: `BREAKING CHANGE: description`

### Examples

#### Simple commit
```
feat(voting): add blockchain vote verification

Implemented SHA-256 hashing for vote integrity verification.
This ensures votes cannot be tampered with after casting.

Closes #123
```

#### Bug fix
```
fix(auth): resolve JWT token expiration issue

Fixed a bug where JWT tokens were expiring prematurely
due to incorrect timestamp calculation.

Fixes #456
```

#### Security fix
```
security(api): prevent SQL injection in voter lookup

Added parameterized queries to prevent SQL injection attacks
in the voter authentication endpoint.

Closes #789
```

### Setting Up Commit Template

To automatically use our commit template:

```bash
git config commit.template .github/.gitmessage
```

## Pull Request Process

1. **Update documentation** if you're changing functionality
2. **Add tests** for new features
3. **Ensure all tests pass**
   ```bash
   npm test
   ```
4. **Run linting**
   ```bash
   npm run lint
   ```
5. **Update the README.md** with details of changes if needed
6. **Fill out the pull request template** completely
7. **Request review** from at least one maintainer
8. **Address review comments** promptly

### Pull Request Checklist

- [ ] Code follows the project's coding standards
- [ ] Self-review of code completed
- [ ] Comments added to complex code sections
- [ ] Documentation updated
- [ ] No new warnings generated
- [ ] Tests added and passing
- [ ] Security implications considered

## Coding Standards

### JavaScript/Node.js

- Use ES6+ features
- Use `const` and `let`, avoid `var`
- Use async/await for asynchronous code
- Use meaningful variable and function names
- Add JSDoc comments for functions
- Follow existing code style

### Example
```javascript
/**
 * Verify vote integrity using blockchain hash
 * @param {string} voteId - The unique vote identifier
 * @param {string} blockchainHash - The blockchain hash to verify
 * @returns {Promise<boolean>} - True if vote is valid
 */
async function verifyVote(voteId, blockchainHash) {
    const vote = await getVoteById(voteId);
    return vote.hash === blockchainHash;
}
```

### HTML/CSS

- Use semantic HTML5 elements
- Use consistent indentation (2 spaces)
- Use meaningful class names
- Follow BEM naming convention where applicable

### SQL

- Use parameterized queries to prevent SQL injection
- Use uppercase for SQL keywords
- Use meaningful table and column names
- Add indexes for frequently queried columns

## Security Guidelines

⚠️ **Security is critical for a voting system!**

### Required Security Practices

1. **Never commit sensitive data**
   - API keys, passwords, or private keys
   - Use environment variables

2. **Input Validation**
   - Validate all user inputs
   - Sanitize data before database operations
   - Use parameterized queries

3. **Authentication & Authorization**
   - Use bcrypt for password hashing (12+ salt rounds)
   - Implement proper JWT token validation
   - Verify user roles before sensitive operations

4. **Blockchain Security**
   - Verify all blockchain hashes
   - Use cryptographically secure random number generation
   - Implement proper gas limit handling

5. **Reporting Security Issues**
   - Report security vulnerabilities privately
   - Use the security issue template
   - Contact maintainers directly for critical issues

## Testing

### Running Tests

```bash
# Run all tests
npm test

# Run specific test file
npm test path/to/test.js

# Run with coverage
npm run test:coverage
```

### Writing Tests

- Write unit tests for new functions
- Write integration tests for API endpoints
- Test both success and failure cases
- Use descriptive test names

### Example Test
```javascript
describe('Vote Verification', () => {
    it('should verify valid blockchain hash', async () => {
        const voteId = '123';
        const validHash = 'abc123...';
        const result = await verifyVote(voteId, validHash);
        expect(result).toBe(true);
    });

    it('should reject invalid blockchain hash', async () => {
        const voteId = '123';
        const invalidHash = 'invalid';
        const result = await verifyVote(voteId, invalidHash);
        expect(result).toBe(false);
    });
});
```

## Questions?

If you have questions about contributing:

1. Check the [README.md](README.md)
2. Search existing [issues](https://github.com/CN7021-Group-Project/E-voting/issues)
3. Create a new issue with your question
4. Join our discussions

## License

By contributing, you agree that your contributions will be licensed under the same license as the project (ISC License).

---

Thank you for contributing to VoteSecure! 🗳️
