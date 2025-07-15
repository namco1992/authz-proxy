# Cloudflare Access Authorization Proxy Design

## Overview

The Authorization Proxy is a Cloudflare Worker that sits between users and backend applications, providing fine-grained access control based on user identity and group membership from Cloudflare Access.

## Architecture

```
User → Cloudflare Access → Authorization Proxy (Worker) → Backend Application
```

## Core Components

### 1. Configuration Interface

```typescript
interface ProxyConfig {
  // Backend application configuration
  backend: {
    baseUrl: string;
    timeout?: number;
    headers?: Record<string, string>;
  };

  // Cloudflare Access configuration
  access: {
    teamDomain: string;
    applicationAud: string;
    loginUrl?: string;
  };

  // Authorization rules
  rules: AuthorizationRule[];

  // Optional: Custom user identity resolver
  userResolver?: (request: Request, jwtPayload: any) => Promise<UserIdentity>;
}

interface AuthorizationRule {
  // Rule name and description
  name: string;
  description?: string;

  // Request matching criteria
  matcher: RequestMatcher;

  // Authorization condition
  condition: Condition;

  // Authorization decision function
  allow: (request: Request, user: UserIdentity) => boolean;

  // Request transformation
  transform?: RequestTransform;

  // Rule priority (lower number = higher priority)
  priority?: number;

  // Enable/disable rule
  enabled?: boolean;
}

interface RequestMatcher {
  // HTTP method matching
  method?: string | string[];

  // Path matching (supports wildcards and regex)
  path?: string | RegExp;

  // Header matching
  headers?: Record<string, string | RegExp>;

  // Query parameter matching
  query?: Record<string, string | RegExp>;

  // Custom matcher function
  custom?: (request: Request) => boolean;
}

interface Condition {
  // Group-based conditions
  groups?: {
    // Groups that user must have (user must have ALL these groups)
    contains?: string[];

    // Groups that user must NOT have
    notContains?: string[];
  };
}

interface RequestTransform {
  // Transform request headers
  headers?: {
    add?: Record<string, string>;
    remove?: string[];
    modify?: Record<string, (value: string, user: UserIdentity) => string>;
  };

  // Transform query parameters
  query?: {
    add?: Record<string, string>;
    remove?: string[];
    modify?: Record<string, (value: string, user: UserIdentity) => string>;
  };

  // Transform JSON request body
  jsonBody?: (body: any, user: UserIdentity) => Promise<any>;

  // Transform URL path
  path?: (path: string, user: UserIdentity) => string;
}

interface UserIdentity {
  id: string;
  email: string;
  name?: string;
  groups: string[];
  customClaims?: Record<string, any>;
}
```

### 2. Main Proxy Class

```typescript
class AuthorizationProxy {
  constructor(private config: ProxyConfig) {}

  async handleRequest(request: Request): Promise<Response> {
    // 1. Validate Cloudflare Access authentication
    // 2. Find matching authorization rules
    // 3. For each rule: evaluate condition, check allow decision, apply transforms
    // 4. Proxy to backend application
    // 5. Return response
  }

  private async validateAccess(request: Request): Promise<UserIdentity> {
    // Validate CF_Authorization cookie and JWT token
  }

  private evaluateRules(request: Request): AuthorizationRule[] {
    // Find all rules that match the request, sorted by priority
  }

  private evaluateCondition(user: UserIdentity, request: Request, rule: AuthorizationRule): boolean {
    // Check if user meets rule conditions (groups, etc.)
  }

  private async applyTransform(request: Request, user: UserIdentity, transform: RequestTransform): Promise<Request> {
    // Apply single transformation to request
  }

  private async proxyToBackend(request: Request): Promise<Response> {
    // Forward request to backend application
  }
}
```

### 3. Elasticsearch-Specific Implementation

```typescript
// Example: Elasticsearch rule for department-based access
const elasticsearchDepartmentRule: AuthorizationRule = {
  name: 'Department-based document filtering',
  description: 'Restrict access to documents based on user department',

  matcher: {
    method: 'POST',
    path: /\/_search$/,
    headers: {
      'content-type': /application\/json/,
    },
  },

  condition: {
    groups: {
      contains: ['elasticsearch-users'],
    },
  },

  allow: (request, user) => {
    // Allow if user has department group
    return user.groups.some((group) => group.startsWith('department-'));
  },

  transform: {
    jsonBody: async (body, user) => {
      // Extract department ID from user groups
      const deptGroup = user.groups.find((g) => g.startsWith('department-'));
      const deptId = deptGroup?.split('-')[1];

      if (!deptId) return body;

      // Inject department filter into Elasticsearch query
      if (!body.query) {
        body.query = { bool: { must: [] } };
      } else if (!body.query.bool) {
        body.query = { bool: { must: [body.query] } };
      } else if (!body.query.bool.must) {
        body.query.bool.must = [];
      }

      // Add department filter
      body.query.bool.must.push({
        term: { department_id: parseInt(deptId) },
      });

      return body;
    },
  },
};
```

### 4. Usage Example

```typescript
// Worker main entry point
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const config: ProxyConfig = {
      backend: {
        baseUrl: 'https://elasticsearch.internal.company.com',
        timeout: 30000,
      },

      access: {
        teamDomain: 'company.cloudflareaccess.com',
        applicationAud: 'your-app-audience-id',
      },

      rules: [
        elasticsearchDepartmentRule,
        // Add more rules as needed
      ],
    };

    const proxy = new AuthorizationProxy(config);
    return await proxy.handleRequest(request);
  },
};
```

## Key Features

### 1. Authentication Integration

- Validates Cloudflare Access `CF_Authorization` cookie
- Extracts user identity from JWT token
- Redirects to Access login if not authenticated

### 2. Rule-Based Authorization

- Flexible rule matching system
- Individual rule processing with condition evaluation
- Custom allow functions for complex authorization logic
- Group-based access control with contains/notContains support
- Rule priorities and composition

### 3. Request Transformation

- Modify headers, query parameters, and JSON body
- Streamlined JSON body transformation with parsed objects
- User context injection
- Rule-specific transformations applied incrementally

### 4. Application Agnostic

- Works with any HTTP-based backend
- Configurable request/response handling
- Extensible rule system

### 5. Cloudflare Worker Optimized

- Efficient request processing
- Minimal cold start impact
- Built-in caching for user identity

## Security Considerations

1. **JWT Validation**: Proper validation of Cloudflare Access JWT tokens
2. **Rule Isolation**: Rules cannot interfere with each other
3. **Input Sanitization**: All user inputs are sanitized
4. **Audit Logging**: Optional request/response logging
5. **Rate Limiting**: Built-in rate limiting per user/group

## Error Handling

- Graceful fallback for rule failures
- Detailed error logging
- User-friendly error messages
- Configurable error responses

This design provides a solid foundation for building a flexible, secure authorization proxy that can be adapted to various applications while maintaining the benefits of Cloudflare Access authentication.
