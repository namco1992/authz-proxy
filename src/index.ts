/**
 * Cloudflare Access Authorization Proxy Worker
 *
 * A Cloudflare Worker that provides fine-grained access control
 * based on user identity and group membership from Cloudflare Access.
 */

import { UserIdentity } from './identity-validator';
import { AuthorizationProxy, ProxyConfig } from './proxy';

// ============================================================================
// Worker Export
// ============================================================================

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    // Load configuration from environment variables
    const config: ProxyConfig = {
      backend: {
        baseUrl: env.BACKEND_URL,
        timeout: 10000,
      },

      access: {
        teamDomain: env.CF_ACCESS_TEAM_DOMAIN,
        applicationAud: env.CF_ACCESS_APPLICATION_AUD,
        kv: env.AUTH,
      },

      rules: [
        {
          name: 'Test rule with an empty group',
          matcher: {
            path: '/internal/search/es',
          },
          condition: {
            groups: {
              notContains: ['anything'],
            },
          },
          allow: () => true,
          transform: {
            jsonBody: (body: any, user: UserIdentity) => {
              return {
                ...body,
                user,
              };
            },
          },
        },
      ],
    };

    const proxy = new AuthorizationProxy(config);
    return await proxy.handleRequest(request);
  },
} satisfies ExportedHandler<Env>;
