# Cloudflare Access Authorization Proxy

A Cloudflare Worker that provides fine-grained access control and request transformation for backend applications. Built on top of Cloudflare Access authentication.

This is particularly useful to add some basic access control to
the applications that don't support it out of box.

## Running Tests

```bash
# Run all tests
pnpm test

# Run tests in watch mode
pnpm test:watch

# Run tests with coverage
pnpm test:coverage
```

## Running Locally

```bash
# Install dependencies
pnpm install

# Start local development server
pnpm dev
```

## Deployment

```bash
# Deploy to Cloudflare Workers
pnpm deploy

# Deploy to specific environment
pnpm deploy --env staging
```
