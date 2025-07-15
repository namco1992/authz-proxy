/**
 * Cloudflare Access Identity Validator
 *
 * Handles JWT verification and user identity extraction from Cloudflare Access tokens.
 */

import { parse } from 'cookie';
import { createRemoteJWKSet, jwtVerify } from 'jose';

// ============================================================================
// Type Definitions
// ============================================================================

export interface IdentityValidatorConfig {
  teamDomain: string;
  applicationAud: string;
  loginUrl?: string;
  kv: KVNamespace;
}

export interface UserIdentity {
  id: string;
  name: string;
  email: string;
  groups?: string[];
}

// ============================================================================
// Identity Validator Class
// ============================================================================

export class IdentityValidator {
  private jwks: ReturnType<typeof createRemoteJWKSet>;

  constructor(private config: IdentityValidatorConfig) {
    // Initialize JWKS for JWT verification
    const certsUrl = `https://${this.config.teamDomain}/cdn-cgi/access/certs`;
    this.jwks = createRemoteJWKSet(new URL(certsUrl));
  }

  async validateAccess(request: Request): Promise<UserIdentity> {
    const jwt = this.getJwtToken(request);

    if (!jwt) {
      const loginUrl = this.config.loginUrl || `https://${this.config.teamDomain}/cdn-cgi/access/login`;
      throw new Response('', {
        status: 302,
        headers: { Location: loginUrl },
      });
    }

    try {
      // Verify JWT with proper signature validation and claims verification
      const result = await jwtVerify(jwt, this.jwks, {
        issuer: `https://${this.config.teamDomain}`,
        audience: this.config.applicationAud,
      });

      const claims = result.payload;
      const sub = claims.sub as string;

      if (!sub) {
        throw new Error('JWT missing required "sub" claim');
      }

      // Check cache first
      const cacheKey = `id:${sub}`;
      const cached = await this.config.kv.get(cacheKey, 'json');
      if (cached) {
        return cached as UserIdentity;
      }

      // Get user identity and cache it
      const userIdentity = await this.getUserIdentity(jwt);

      await this.config.kv.put(cacheKey, JSON.stringify(userIdentity), {
        expiration: claims.exp,
      });

      return userIdentity;
    } catch (error) {
      console.error('JWT verification failed:', error);
      throw new Response('Invalid authentication token', { status: 401 });
    }
  }

  private getJwtToken(request: Request): string | null {
    // Get the JWT token from `cf-access-jwt-assertion` header.
    let jwt = request.headers.get('cf-access-jwt-assertion');
    if (!jwt) {
      // Otherwise get the JWT token from `CF_Authorization` cookie.
      const cookies = parse(request.headers.get('Cookie') || '');
      jwt = cookies['CF_Authorization'] || null;
    }

    return jwt;
  }

  private async getUserIdentity(jwt: string): Promise<UserIdentity> {
    const headers = new Headers();
    headers.set('cookie', `CF_Authorization=${jwt}`);

    try {
      const res = await fetch(`https://${this.config.teamDomain}/cdn-cgi/access/get-identity`, { headers });
      if (!res.ok) {
        throw new Error('Failed to get user identity');
      }
      const userIdentity = await res.json();
      return userIdentity as UserIdentity;
    } catch (err) {
      throw new Error(`Failed to get user identity: ${err}`);
    }
  }
}
