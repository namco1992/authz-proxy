import { describe, it, expect, beforeEach } from 'vitest';
import { AuthorizationProxy, type ProxyConfig, type AuthorizationRule } from '../src/proxy';
import { type UserIdentity } from '../src/identity-validator';
import { env } from 'cloudflare:test';

describe('AuthorizationProxy', () => {
  let proxy: AuthorizationProxy;
  let baseConfig: ProxyConfig;

  beforeEach(() => {
    baseConfig = {
      backend: {
        baseUrl: 'https://backend.example.com',
        timeout: 30000,
      },
      access: {
        teamDomain: 'team.cloudflareaccess.com',
        applicationAud: 'test-app-aud',
        loginUrl: 'https://team.cloudflareaccess.com/cdn-cgi/access/login',
        kv: env.AUTH,
      },
      rules: [],
    };
  });

  describe('evaluateRules', () => {
    it('should return empty array when no rules are configured', () => {
      proxy = new AuthorizationProxy(baseConfig);
      const request = new Request('https://example.com/api/test', { method: 'GET' });

      // Use type assertion to access private method for testing
      const result = (proxy as any).evaluateRules(request);

      expect(result).toEqual([]);
    });

    it('should return empty array when no rules match', () => {
      const rules: AuthorizationRule[] = [
        {
          name: 'POST only rule',
          matcher: { method: 'POST' },
          condition: { groups: { contains: ['admin'] } },
          allow: () => true,
        },
      ];

      proxy = new AuthorizationProxy({ ...baseConfig, rules });
      const request = new Request('https://example.com/api/test', { method: 'GET' });

      const result = (proxy as any).evaluateRules(request);

      expect(result).toEqual([]);
    });

    it('should return matching rules sorted by priority', () => {
      const rules: AuthorizationRule[] = [
        {
          name: 'Low priority rule',
          matcher: { method: 'GET' },
          condition: { groups: { contains: ['user'] } },
          allow: () => true,
          priority: 100,
        },
        {
          name: 'High priority rule',
          matcher: { method: 'GET' },
          condition: { groups: { contains: ['admin'] } },
          allow: () => true,
          priority: 1,
        },
        {
          name: 'Medium priority rule',
          matcher: { method: 'GET' },
          condition: { groups: { contains: ['editor'] } },
          allow: () => true,
          priority: 50,
        },
      ];

      proxy = new AuthorizationProxy({ ...baseConfig, rules });
      const request = new Request('https://example.com/api/test', { method: 'GET' });

      const result = (proxy as any).evaluateRules(request);

      expect(result).toHaveLength(3);
      expect(result[0].name).toBe('High priority rule'); // priority 1
      expect(result[1].name).toBe('Medium priority rule'); // priority 50
      expect(result[2].name).toBe('Low priority rule'); // priority 100
    });

    it('should exclude disabled rules', () => {
      const rules: AuthorizationRule[] = [
        {
          name: 'Enabled rule',
          matcher: { method: 'GET' },
          condition: { groups: { contains: ['user'] } },
          allow: () => true,
          enabled: true,
        },
        {
          name: 'Disabled rule',
          matcher: { method: 'GET' },
          condition: { groups: { contains: ['admin'] } },
          allow: () => true,
          enabled: false,
        },
        {
          name: 'Default enabled rule',
          matcher: { method: 'GET' },
          condition: { groups: { contains: ['editor'] } },
          allow: () => true,
          // enabled is undefined, should default to true
        },
      ];

      proxy = new AuthorizationProxy({ ...baseConfig, rules });
      const request = new Request('https://example.com/api/test', { method: 'GET' });

      const result = (proxy as any).evaluateRules(request);

      expect(result).toHaveLength(2);
      expect(result.find((r: AuthorizationRule) => r.name === 'Enabled rule')).toBeDefined();
      expect(result.find((r: AuthorizationRule) => r.name === 'Default enabled rule')).toBeDefined();
      expect(result.find((r: AuthorizationRule) => r.name === 'Disabled rule')).toBeUndefined();
    });

    describe('rule matching logic', () => {
      it('should match HTTP method correctly', () => {
        const rules: AuthorizationRule[] = [
          {
            name: 'GET rule',
            matcher: { method: 'GET' },
            condition: { groups: { contains: ['user'] } },
            allow: () => true,
          },
          {
            name: 'POST rule',
            matcher: { method: 'POST' },
            condition: { groups: { contains: ['user'] } },
            allow: () => true,
          },
          {
            name: 'Multiple methods rule',
            matcher: { method: ['PUT', 'PATCH'] },
            condition: { groups: { contains: ['user'] } },
            allow: () => true,
          },
        ];

        proxy = new AuthorizationProxy({ ...baseConfig, rules });

        // Test GET request
        const getRequest = new Request('https://example.com/api/test', { method: 'GET' });
        const getResult = (proxy as any).evaluateRules(getRequest);
        expect(getResult).toHaveLength(1);
        expect(getResult[0].name).toBe('GET rule');

        // Test PUT request
        const putRequest = new Request('https://example.com/api/test', { method: 'PUT' });
        const putResult = (proxy as any).evaluateRules(putRequest);
        expect(putResult).toHaveLength(1);
        expect(putResult[0].name).toBe('Multiple methods rule');

        // Test DELETE request (no match)
        const deleteRequest = new Request('https://example.com/api/test', { method: 'DELETE' });
        const deleteResult = (proxy as any).evaluateRules(deleteRequest);
        expect(deleteResult).toHaveLength(0);
      });

      it('should match path correctly', () => {
        const rules: AuthorizationRule[] = [
          {
            name: 'Exact path rule',
            matcher: { path: '/api/admin' },
            condition: { groups: { contains: ['admin'] } },
            allow: () => true,
          },
          {
            name: 'Regex path rule',
            matcher: { path: /^\/api\/users\/\d+$/ },
            condition: { groups: { contains: ['user'] } },
            allow: () => true,
          },
        ];

        proxy = new AuthorizationProxy({ ...baseConfig, rules });

        // Test exact path match
        const exactRequest = new Request('https://example.com/api/admin');
        const exactResult = (proxy as any).evaluateRules(exactRequest);
        expect(exactResult).toHaveLength(1);
        expect(exactResult[0].name).toBe('Exact path rule');

        // Test regex path match
        const regexRequest = new Request('https://example.com/api/users/123');
        const regexResult = (proxy as any).evaluateRules(regexRequest);
        expect(regexResult).toHaveLength(1);
        expect(regexResult[0].name).toBe('Regex path rule');

        // Test no match
        const noMatchRequest = new Request('https://example.com/api/posts');
        const noMatchResult = (proxy as any).evaluateRules(noMatchRequest);
        expect(noMatchResult).toHaveLength(0);
      });

      it('should match headers correctly', () => {
        const rules: AuthorizationRule[] = [
          {
            name: 'Content-Type rule',
            matcher: {
              headers: {
                'content-type': 'application/json',
                authorization: /^Bearer .+$/,
              },
            },
            condition: { groups: { contains: ['user'] } },
            allow: () => true,
          },
        ];

        proxy = new AuthorizationProxy({ ...baseConfig, rules });

        // Test matching headers
        const matchingRequest = new Request('https://example.com/api/test', {
          headers: {
            'content-type': 'application/json',
            authorization: 'Bearer token123',
          },
        });
        const matchingResult = (proxy as any).evaluateRules(matchingRequest);
        expect(matchingResult).toHaveLength(1);

        // Test missing header
        const missingHeaderRequest = new Request('https://example.com/api/test', {
          headers: {
            'content-type': 'application/json',
            // missing authorization header
          },
        });
        const missingResult = (proxy as any).evaluateRules(missingHeaderRequest);
        expect(missingResult).toHaveLength(0);

        // Test non-matching regex
        const nonMatchingRequest = new Request('https://example.com/api/test', {
          headers: {
            'content-type': 'application/json',
            authorization: 'Basic token123', // doesn't match Bearer regex
          },
        });
        const nonMatchingResult = (proxy as any).evaluateRules(nonMatchingRequest);
        expect(nonMatchingResult).toHaveLength(0);
      });

      it('should match query parameters correctly', () => {
        const rules: AuthorizationRule[] = [
          {
            name: 'Query parameter rule',
            matcher: {
              query: {
                action: 'admin',
                id: /^\d+$/,
              },
            },
            condition: { groups: { contains: ['admin'] } },
            allow: () => true,
          },
        ];

        proxy = new AuthorizationProxy({ ...baseConfig, rules });

        // Test matching query params
        const matchingRequest = new Request('https://example.com/api/test?action=admin&id=123');
        const matchingResult = (proxy as any).evaluateRules(matchingRequest);
        expect(matchingResult).toHaveLength(1);

        // Test missing query param
        const missingRequest = new Request('https://example.com/api/test?action=admin');
        const missingResult = (proxy as any).evaluateRules(missingRequest);
        expect(missingResult).toHaveLength(0);

        // Test non-matching regex
        const nonMatchingRequest = new Request('https://example.com/api/test?action=admin&id=abc');
        const nonMatchingResult = (proxy as any).evaluateRules(nonMatchingRequest);
        expect(nonMatchingResult).toHaveLength(0);
      });

      it('should use custom matcher function', () => {
        const customMatcher = (request: Request): boolean => {
          const url = new URL(request.url);
          return url.searchParams.has('special');
        };

        const rules: AuthorizationRule[] = [
          {
            name: 'Custom matcher rule',
            matcher: { custom: customMatcher },
            condition: { groups: { contains: ['user'] } },
            allow: () => true,
          },
        ];

        proxy = new AuthorizationProxy({ ...baseConfig, rules });

        // Test custom matcher returns true
        const matchingRequest = new Request('https://example.com/api/test?special=true');
        const matchingResult = (proxy as any).evaluateRules(matchingRequest);
        expect(matchingResult).toHaveLength(1);

        // Test custom matcher returns false
        const nonMatchingRequest = new Request('https://example.com/api/test');
        const nonMatchingResult = (proxy as any).evaluateRules(nonMatchingRequest);
        expect(nonMatchingResult).toHaveLength(0);
      });
    });
  });

  describe('evaluateCondition', () => {
    let mockUser: UserIdentity;
    let mockRequest: Request;

    beforeEach(() => {
      proxy = new AuthorizationProxy(baseConfig);
      mockUser = {
        id: 'user123',
        email: 'user@example.com',
        name: 'Test User',
        groups: ['user', 'editor'],
      };
      mockRequest = new Request('https://example.com/api/test');
    });

    it('should return true when no group conditions are specified', () => {
      const rule: AuthorizationRule = {
        name: 'No condition rule',
        matcher: { method: 'GET' },
        condition: {}, // Empty condition
        allow: () => true,
      };

      const result = (proxy as any).evaluateCondition(mockUser, mockRequest, rule);

      expect(result).toBe(true);
    });

    describe('group conditions', () => {
      describe('contains groups', () => {
        it('should return true when user has all required groups', () => {
          const rule: AuthorizationRule = {
            name: 'Requires user and editor',
            matcher: { method: 'GET' },
            condition: {
              groups: {
                contains: ['user', 'editor'],
              },
            },
            allow: () => true,
          };

          const result = (proxy as any).evaluateCondition(mockUser, mockRequest, rule);

          expect(result).toBe(true);
        });

        it('should return false when user missing required groups', () => {
          const rule: AuthorizationRule = {
            name: 'Requires admin',
            matcher: { method: 'GET' },
            condition: {
              groups: {
                contains: ['admin', 'superuser'],
              },
            },
            allow: () => true,
          };

          const result = (proxy as any).evaluateCondition(mockUser, mockRequest, rule);

          expect(result).toBe(false);
        });

        it('should return false when user missing some required groups', () => {
          const rule: AuthorizationRule = {
            name: 'Requires user and admin',
            matcher: { method: 'GET' },
            condition: {
              groups: {
                contains: ['user', 'admin'], // user has 'user' but not 'admin'
              },
            },
            allow: () => true,
          };

          const result = (proxy as any).evaluateCondition(mockUser, mockRequest, rule);

          expect(result).toBe(false);
        });
      });

      describe('notContains groups', () => {
        it('should return true when user does not have forbidden groups', () => {
          const rule: AuthorizationRule = {
            name: 'Forbids admin',
            matcher: { method: 'GET' },
            condition: {
              groups: {
                notContains: ['admin', 'superuser'],
              },
            },
            allow: () => true,
          };

          const result = (proxy as any).evaluateCondition(mockUser, mockRequest, rule);

          expect(result).toBe(true);
        });

        it('should return false when user has forbidden groups', () => {
          const userWithAdmin = {
            ...mockUser,
            groups: ['user', 'editor', 'admin'],
          };

          const rule: AuthorizationRule = {
            name: 'Forbids admin',
            matcher: { method: 'GET' },
            condition: {
              groups: {
                notContains: ['admin'],
              },
            },
            allow: () => true,
          };

          const result = (proxy as any).evaluateCondition(userWithAdmin, mockRequest, rule);

          expect(result).toBe(false);
        });

        it('should return false when user has any forbidden groups', () => {
          const userWithMultipleForbidden = {
            ...mockUser,
            groups: ['user', 'editor', 'admin', 'superuser'],
          };

          const rule: AuthorizationRule = {
            name: 'Forbids admin and superuser',
            matcher: { method: 'GET' },
            condition: {
              groups: {
                notContains: ['admin', 'superuser', 'banned'],
              },
            },
            allow: () => true,
          };

          const result = (proxy as any).evaluateCondition(userWithMultipleForbidden, mockRequest, rule);

          expect(result).toBe(false);
        });
      });

      describe('combined contains and notContains', () => {
        it('should return true when user meets both contains and notContains conditions', () => {
          const rule: AuthorizationRule = {
            name: 'Requires user but forbids admin',
            matcher: { method: 'GET' },
            condition: {
              groups: {
                contains: ['user'],
                notContains: ['admin'],
              },
            },
            allow: () => true,
          };

          const result = (proxy as any).evaluateCondition(mockUser, mockRequest, rule);

          expect(result).toBe(true);
        });

        it('should return false when user fails contains condition even if passes notContains', () => {
          const rule: AuthorizationRule = {
            name: 'Requires admin but forbids superuser',
            matcher: { method: 'GET' },
            condition: {
              groups: {
                contains: ['admin'], // user doesn't have admin
                notContains: ['superuser'], // user doesn't have superuser (good)
              },
            },
            allow: () => true,
          };

          const result = (proxy as any).evaluateCondition(mockUser, mockRequest, rule);

          expect(result).toBe(false);
        });

        it('should return false when user fails notContains condition even if passes contains', () => {
          const userWithBadGroup = {
            ...mockUser,
            groups: ['user', 'editor', 'banned'],
          };

          const rule: AuthorizationRule = {
            name: 'Requires user but forbids banned',
            matcher: { method: 'GET' },
            condition: {
              groups: {
                contains: ['user'], // user has user (good)
                notContains: ['banned'], // user has banned (bad)
              },
            },
            allow: () => true,
          };

          const result = (proxy as any).evaluateCondition(userWithBadGroup, mockRequest, rule);

          expect(result).toBe(false);
        });
      });
    });
  });

  describe('applyTransform', () => {
    let mockUser: UserIdentity;
    let baseRequest: Request;

    beforeEach(() => {
      proxy = new AuthorizationProxy(baseConfig);
      mockUser = {
        id: 'user123',
        email: 'user@example.com',
        name: 'Test User',
        groups: ['user', 'editor'],
      };
      baseRequest = new Request('https://example.com/api/test?existing=param', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'existing-header': 'value',
        },
        body: JSON.stringify({ existing: 'data' }),
      });
    });

    describe('header transformations', () => {
      it('should add headers', async () => {
        const transform = {
          headers: {
            add: {
              'X-User-ID': 'user123',
              'X-User-Email': 'user@example.com',
            },
          },
        };

        const result = await (proxy as any).applyTransform(baseRequest, mockUser, transform);

        expect(result.headers.get('X-User-ID')).toBe('user123');
        expect(result.headers.get('X-User-Email')).toBe('user@example.com');
        expect(result.headers.get('existing-header')).toBe('value');
      });

      it('should remove headers', async () => {
        const transform = {
          headers: {
            remove: ['existing-header'],
          },
        };

        const result = await (proxy as any).applyTransform(baseRequest, mockUser, transform);

        expect(result.headers.get('existing-header')).toBeNull();
        expect(result.headers.get('content-type')).toBe('application/json');
      });

      it('should modify headers', async () => {
        const transform = {
          headers: {
            modify: {
              'existing-header': (value: string, user: UserIdentity) => `${value}-modified-${user.id}`,
            },
          },
        };

        const result = await (proxy as any).applyTransform(baseRequest, mockUser, transform);

        expect(result.headers.get('existing-header')).toBe('value-modified-user123');
      });

      it('should skip modifying headers that do not exist', async () => {
        const transform = {
          headers: {
            modify: {
              'non-existent-header': (value: string) => `${value}-modified`,
            },
          },
        };

        const result = await (proxy as any).applyTransform(baseRequest, mockUser, transform);

        expect(result.headers.get('non-existent-header')).toBeNull();
      });

      it('should apply all header transformations together', async () => {
        const transform = {
          headers: {
            add: { 'X-New-Header': 'new' },
            remove: ['existing-header'],
            modify: {
              'content-type': (value: string) => `${value}; charset=utf-8`,
            },
          },
        };

        const result = await (proxy as any).applyTransform(baseRequest, mockUser, transform);

        expect(result.headers.get('X-New-Header')).toBe('new');
        expect(result.headers.get('existing-header')).toBeNull();
        expect(result.headers.get('content-type')).toBe('application/json; charset=utf-8');
      });
    });

    describe('query parameter transformations', () => {
      it('should add query parameters', async () => {
        const transform = {
          query: {
            add: {
              user_id: 'user123',
              role: 'editor',
            },
          },
        };

        const result = await (proxy as any).applyTransform(baseRequest, mockUser, transform);
        const url = new URL(result.url);

        expect(url.searchParams.get('user_id')).toBe('user123');
        expect(url.searchParams.get('role')).toBe('editor');
        expect(url.searchParams.get('existing')).toBe('param');
      });

      it('should remove query parameters', async () => {
        const transform = {
          query: {
            remove: ['existing'],
          },
        };

        const result = await (proxy as any).applyTransform(baseRequest, mockUser, transform);
        const url = new URL(result.url);

        expect(url.searchParams.get('existing')).toBeNull();
      });

      it('should modify query parameters', async () => {
        const transform = {
          query: {
            modify: {
              existing: (value: string, user: UserIdentity) => `${value}-${user.id}`,
            },
          },
        };

        const result = await (proxy as any).applyTransform(baseRequest, mockUser, transform);
        const url = new URL(result.url);

        expect(url.searchParams.get('existing')).toBe('param-user123');
      });

      it('should skip modifying query parameters that do not exist', async () => {
        const transform = {
          query: {
            modify: {
              'non-existent': (value: string) => `${value}-modified`,
            },
          },
        };

        const result = await (proxy as any).applyTransform(baseRequest, mockUser, transform);
        const url = new URL(result.url);

        expect(url.searchParams.get('non-existent')).toBeNull();
        expect(url.searchParams.get('existing')).toBe('param');
      });
    });

    describe('path transformation', () => {
      it('should transform the path', async () => {
        const transform = {
          path: (path: string, user: UserIdentity) => `/users/${user.id}${path}`,
        };

        const result = await (proxy as any).applyTransform(baseRequest, mockUser, transform);
        const url = new URL(result.url);

        expect(url.pathname).toBe('/users/user123/api/test');
      });
    });

    describe('JSON body transformation', () => {
      it('should transform JSON body', async () => {
        const transform = {
          jsonBody: async (body: any, user: UserIdentity) => ({
            ...body,
            user_id: user.id,
            user_email: user.email,
          }),
        };

        const result = await (proxy as any).applyTransform(baseRequest, mockUser, transform);
        const transformedBody = await result.json();

        expect(transformedBody).toEqual({
          existing: 'data',
          user_id: 'user123',
          user_email: 'user@example.com',
        });
      });

      it('should preserve other transformations when transforming JSON body', async () => {
        const transform = {
          headers: {
            add: { 'X-Transformed': 'true' },
          },
          query: {
            add: { transformed: 'yes' },
          },
          jsonBody: async (body: any, user: UserIdentity) => ({
            ...body,
            user_id: user.id,
          }),
        };

        const result = await (proxy as any).applyTransform(baseRequest, mockUser, transform);
        const url = new URL(result.url);
        const transformedBody = await result.json();

        expect(result.headers.get('X-Transformed')).toBe('true');
        expect(url.searchParams.get('transformed')).toBe('yes');
        expect(transformedBody).toEqual({
          existing: 'data',
          user_id: 'user123',
        });
      });
    });

    it('should handle empty transform object', async () => {
      const transform = {};

      const result = await (proxy as any).applyTransform(baseRequest, mockUser, transform);

      expect(result.method).toBe(baseRequest.method);
      expect(result.url).toBe(baseRequest.url);
      expect(result.headers.get('content-type')).toBe('application/json');
    });
  });
});
