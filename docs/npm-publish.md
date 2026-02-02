# npm Publish Workflow

## Prerequisites

1. npm account (create at npmjs.com)
2. Verify email
3. Enable 2FA (required for publishing)

## Steps

### 1. Check package name availability

```bash
npm search agent-guard
```

If taken, consider alternatives:
- `@agentguard/cli`
- `agentguard-scanner`
- `agent-security-scanner`

### 2. Login to npm

```bash
npm login
# Enter username, password, 2FA code
```

### 3. Verify package.json

Ensure these fields are set:
- `name`: Package name
- `version`: Semver (start with 0.1.0)
- `description`: Clear, searchable
- `main`: Entry point
- `bin`: CLI command
- `keywords`: For discoverability
- `author`: Contact info
- `license`: MIT
- `repository`: GitHub URL
- `homepage`: Landing page
- `files`: What to include

### 4. Test locally

```bash
# Pack without publishing
npm pack

# This creates agent-guard-0.1.0.tgz
# Install it locally to test
npm install -g ./agent-guard-0.1.0.tgz

# Verify CLI works
agent-guard scan .

# Cleanup
npm uninstall -g agent-guard
```

### 5. Dry run

```bash
npm publish --dry-run
```

Review what will be published.

### 6. Publish

```bash
# First release
npm publish --access public

# For scoped packages (@agentguard/cli)
npm publish --access public
```

### 7. Verify

```bash
# Should work immediately
npx agent-guard scan .
```

## Version Updates

```bash
# Patch (bug fixes): 0.1.0 → 0.1.1
npm version patch

# Minor (features): 0.1.0 → 0.2.0
npm version minor

# Major (breaking): 0.1.0 → 1.0.0
npm version major

# Then publish
npm publish
```

## Automation (GitHub Actions)

```yaml
name: Publish to npm

on:
  release:
    types: [created]

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          registry-url: 'https://registry.npmjs.org'
      
      - run: npm publish --access public
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
```

## Checklist Before Publish

- [ ] README.md is clear and helpful
- [ ] `npm test` passes
- [ ] `npm run scan` works on test fixtures
- [ ] Version bumped appropriately
- [ ] CHANGELOG updated
- [ ] No secrets in published files
- [ ] `npm pack` contents look correct
- [ ] License file included
