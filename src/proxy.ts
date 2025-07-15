/**
 * Cloudflare Access Authorization Proxy
 *
 * A reusable authorization proxy that provides fine-grained access control
 * based on user identity and group membership from Cloudflare Access.
 */

import { IdentityValidator, type IdentityValidatorConfig, type UserIdentity } from './identity-validator';

// ============================================================================
// Type Definitions and Interfaces
// ============================================================================

export interface ProxyConfig {
  backend: {
    baseUrl: string;
    timeout?: number;
  };

  access: IdentityValidatorConfig;
  rules: AuthorizationRule[];
}

export interface AuthorizationRule {
  name: string;
  description?: string;
  matcher: RequestMatcher;
  condition: Condition;
  allow: (request: Request, user: UserIdentity) => boolean;
  transform?: RequestTransform;
  priority?: number;
  enabled?: boolean;
}

export interface RequestMatcher {
  method?: string | string[];
  path?: string | RegExp;
  headers?: Record<string, string | RegExp>;
  query?: Record<string, string | RegExp>;
  custom?: (request: Request) => boolean;
}

export interface Condition {
  groups?: {
    contains?: string[];
    notContains?: string[];
  };
}

export interface RequestTransform {
  headers?: {
    add?: Record<string, string>;
    remove?: string[];
    modify?: Record<string, (value: string, user: UserIdentity) => string>;
  };
  query?: {
    add?: Record<string, string>;
    remove?: string[];
    modify?: Record<string, (value: string, user: UserIdentity) => string>;
  };
  jsonBody?: (body: any, user: UserIdentity) => Promise<any>;
  path?: (path: string, user: UserIdentity) => string;
}

// ============================================================================
// Main Authorization Proxy Class
// ============================================================================

export class AuthorizationProxy {
  private identityValidator: IdentityValidator;

  constructor(private config: ProxyConfig) {
    // Initialize identity validator
    this.identityValidator = new IdentityValidator(this.config.access);
  }

  async handleRequest(request: Request): Promise<Response> {
    try {
      // 1. Validate Cloudflare Access authentication
      const user = await this.identityValidator.validateAccess(request);

      // 2. Find matching authorization rules
      const matchingRules = this.evaluateRules(request);

      // Early return if no matching rules.
      if (matchingRules.length === 0) {
        return await this.proxyToBackend(request);
      }

      // 3. Loop through rules, evaluate conditions, and apply transformations
      let transformedRequest = request;
      const appliedRules: string[] = [];

      for (const rule of matchingRules) {
        // Evaluate condition for this specific rule
        const conditionMet = this.evaluateCondition(user, request, rule);

        if (!conditionMet) {
          // Audit log the failed condition
          console.log({
            name: user.name,
            email: user.email,
            failedRule: rule.name,
            conditionMet: false,
          });

          // If condition is not met, skip this rule (don't deny access yet)
          continue;
        }

        // Condition is met, now check if the rule allows access
        if (!rule.allow(transformedRequest, user)) {
          // Audit log the denied rule
          console.log({
            name: user.name,
            email: user.email,
            deniedByRule: rule.name,
            allowed: false,
          });

          return new Response(`Access denied by rule: ${rule.name}`, { status: 403 });
        }

        // Rule allows access, apply transformation if the rule has one
        if (rule.transform) {
          transformedRequest = await this.applyTransform(transformedRequest, user, rule.transform);
          appliedRules.push(rule.name);
        }
      }

      // Audit log successful authorization and applied rules
      console.log({
        name: user.name,
        email: user.email,
        matchedRules: matchingRules.map((rule) => rule.name),
        appliedRules,
        allowed: true,
      });

      // 4. Proxy to backend application
      return await this.proxyToBackend(transformedRequest);
    } catch (error) {
      // Handle Response objects thrown for redirects and auth errors
      if (error instanceof Response) {
        return error;
      }

      console.error('Authorization proxy error:', error);
      return new Response('Internal server error', { status: 500 });
    }
  }

  private evaluateRules(request: Request): AuthorizationRule[] {
    const url = new URL(request.url);
    const enabledRules = this.config.rules.filter((rule) => rule.enabled !== false);
    const matchingRules = enabledRules.filter((rule) => this.ruleMatches(rule.matcher, request, url));

    // Sort by priority (lower number = higher priority)
    return matchingRules.sort((a, b) => (a.priority || 999) - (b.priority || 999));
  }

  private ruleMatches(matcher: RequestMatcher, request: Request, url: URL): boolean {
    // Check method
    if (matcher.method) {
      const methods = Array.isArray(matcher.method) ? matcher.method : [matcher.method];
      if (!methods.includes(request.method)) {
        return false;
      }
    }

    // Check path
    if (matcher.path) {
      if (matcher.path instanceof RegExp) {
        if (!matcher.path.test(url.pathname)) {
          return false;
        }
      } else if (url.pathname !== matcher.path) {
        return false;
      }
    }

    // Check headers
    if (matcher.headers) {
      for (const [headerName, expectedValue] of Object.entries(matcher.headers)) {
        const actualValue = request.headers.get(headerName);
        if (!actualValue) return false;

        if (expectedValue instanceof RegExp) {
          if (!expectedValue.test(actualValue)) return false;
        } else if (actualValue !== expectedValue) {
          return false;
        }
      }
    }

    // Check query parameters
    if (matcher.query) {
      for (const [paramName, expectedValue] of Object.entries(matcher.query)) {
        const actualValue = url.searchParams.get(paramName);
        if (!actualValue) return false;

        if (expectedValue instanceof RegExp) {
          if (!expectedValue.test(actualValue)) return false;
        } else if (actualValue !== expectedValue) {
          return false;
        }
      }
    }

    // Check custom matcher
    if (matcher.custom) {
      return matcher.custom(request);
    }

    return true;
  }

  private evaluateCondition(user: UserIdentity, request: Request, rule: AuthorizationRule): boolean {
    const condition = rule.condition;

    // Check group conditions
    if (condition.groups) {
      // Check contains groups (user must have all these groups)
      if (condition.groups.contains) {
        const hasAllRequired = condition.groups.contains.every((group: string) => user.groups?.includes(group));
        if (!hasAllRequired) {
          return false;
        }
      }

      // Check notContains groups (user must NOT have these groups)
      if (condition.groups.notContains) {
        const hasForbidden = condition.groups.notContains.some((group: string) => user.groups?.includes(group));
        if (hasForbidden) {
          return false;
        }
      }
    }

    return true;
  }

  private async applyTransform(request: Request, user: UserIdentity, transform: RequestTransform): Promise<Request> {
    const url = new URL(request.url);
    const headers = new Headers(request.headers);
    let body: BodyInit | null = null;

    // Transform headers
    if (transform.headers) {
      // Add headers
      if (transform.headers.add) {
        for (const [name, value] of Object.entries(transform.headers.add)) {
          headers.set(name, value);
        }
      }

      // Remove headers
      if (transform.headers.remove) {
        for (const name of transform.headers.remove) {
          headers.delete(name);
        }
      }

      // Modify headers
      if (transform.headers.modify) {
        for (const [name, transformer] of Object.entries(transform.headers.modify)) {
          const currentValue = headers.get(name);
          if (currentValue) {
            headers.set(name, transformer(currentValue, user));
          }
        }
      }
    }

    // Transform query parameters
    if (transform.query) {
      // Add query params
      if (transform.query.add) {
        for (const [name, value] of Object.entries(transform.query.add)) {
          url.searchParams.set(name, value);
        }
      }

      // Remove query params
      if (transform.query.remove) {
        for (const name of transform.query.remove) {
          url.searchParams.delete(name);
        }
      }

      // Modify query params
      if (transform.query.modify) {
        for (const [name, transformer] of Object.entries(transform.query.modify)) {
          const currentValue = url.searchParams.get(name);
          if (currentValue) {
            url.searchParams.set(name, transformer(currentValue, user));
          }
        }
      }
    }

    // Transform path
    if (transform.path) {
      url.pathname = transform.path(url.pathname, user);
    }

    // Handle body transformation
    if (transform.jsonBody && request.body) {
      try {
        const jsonBody = await request.json();
        const transformedJsonBody = await transform.jsonBody(jsonBody, user);
        body = JSON.stringify(transformedJsonBody);
      } catch (error) {
        console.error('Failed to transform JSON body:', error);
        // Fall back to original body if JSON parsing fails
        body = request.body;
      }
    } else if (request.body) {
      // Clone the body to avoid "body already read" errors
      body = request.body;
    }

    return new Request(url, {
      method: request.method,
      headers: headers,
      body: body,
    });
  }

  private async proxyToBackend(request: Request): Promise<Response> {
    const originalUrl = new URL(request.url);
    const backendUrl = new URL(this.config.backend.baseUrl);

    // Preserve the path and query parameters from the original request
    backendUrl.pathname = originalUrl.pathname;
    backendUrl.search = originalUrl.search;

    console.log(`Proxying request to: ${backendUrl.toString()}`);

    const controller = new AbortController();
    const timeout = this.config.backend.timeout || 30000;
    const timeoutId = setTimeout(() => {
      console.log(`Request timeout after ${timeout}ms`);
      controller.abort();
    }, timeout);

    try {
      const response = await fetch(backendUrl, {
        method: request.method,
        headers: request.headers,
        body: request.body,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);
      console.log(`Backend response: ${response.status} ${response.statusText}`);
      return response;
    } catch (error) {
      clearTimeout(timeoutId);

      if (error instanceof Error && error.name === 'AbortError') {
        console.error(`Backend request timed out after ${timeout}ms for URL: ${backendUrl.toString()}`);
        return new Response('Backend request timed out', { status: 504 });
      }

      console.error('Backend request failed:', error);
      return new Response('Backend request failed', { status: 502 });
    }
  }
}
