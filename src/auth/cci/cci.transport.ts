import type * as impitTypes from 'impit';
import * as toughCookie from 'tough-cookie';

import type * as cciTypes from './cci.types';

/**
 * Headers extension exposed by current Node and Impit implementations for repeated cookies.
 */
interface HeadersWithSetCookie {
  /** Returns every Set-Cookie header without combining values with commas. */
  getSetCookie?: () => string[];
}

/**
 * Impit-backed transport isolated to EU authentication requests that need a browser TLS profile.
 */
export class ImpitCciHttpTransport implements cciTypes.CciHttpTransport {
  /** Lazily created client so importing Bluelinky for another region never loads native Impit. */
  private client?: impitTypes.Impit;

  /** Cookie jar shared by all redirects and requests in one authentication operation. */
  private readonly cookieJar = new toughCookie.CookieJar();

  /**
   * Loads the optional native transport only when an EU CCI request is actually made.
   */
  private async getClient(): Promise<impitTypes.Impit> {
    if (this.client) {
      return this.client;
    }

    try {
      const impitModule = await import('impit');
      this.client = new impitModule.Impit({
        browser: 'chrome131',
        cookieJar: this.cookieJar,
        followRedirects: false,
        timeout: 15000,
      });
      return this.client;
    } catch (error) {
      const reason = error instanceof Error ? error.name : 'unknown transport error';
      throw new Error(
        `Unable to load the Impit transport required by EU CCI authentication (${reason}). ` +
          'Use Node.js 20 or newer on a supported x64/arm64 platform.'
      );
    }
  }

  /**
   * Executes one request with manual redirects so the OAuth client can inspect every Location hop.
   */
  public async request(request: cciTypes.CciHttpRequest): Promise<cciTypes.CciHttpResponse> {
    const client = await this.getClient();
    const response = await client.fetch(request.url, {
      method: request.method,
      headers: request.headers,
      body: request.body,
      redirect: 'manual',
    });
    const headers: Record<string, string | string[] | undefined> = {};

    response.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });

    const setCookies = (response.headers as Headers & HeadersWithSetCookie).getSetCookie?.() ?? [];
    if (setCookies.length > 0) {
      headers['set-cookie'] = setCookies;
    }

    return {
      statusCode: response.status,
      headers,
      body: await response.text(),
      url: response.url || request.url,
    };
  }
}

/**
 * Creates a fresh cookie and connection scope for one CCI login or refresh operation.
 */
export function createImpitCciHttpTransport(): cciTypes.CciHttpTransport {
  return new ImpitCciHttpTransport();
}
