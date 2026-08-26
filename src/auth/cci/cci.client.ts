import * as nodeCrypto from 'crypto';
import * as nodeUrl from 'url';

import * as cciConfig from './cci.config';
import * as cciTransport from './cci.transport';
import type * as cciTypes from './cci.types';

/** Mobile identity currently accepted by IDPConnect for the OneApp authorization flow. */
const IDP_USER_AGENT =
  'Mozilla/5.0 (Linux; Android 4.1.1; Galaxy Nexus Build/JRO03C) ' +
  'AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.166 ' +
  'Mobile Safari/535.19_CCS_APP_AOS';

/** Version and device profile sent by the production EU OneApp to CCI. */
const CCI_CLIENT_VERSION = '1.3.3';
const CCI_CLIENT_OS_CODE = 'ios';
const CCI_CLIENT_DEVICE_MODEL = 'iPhone';

/** Country value used by the verified EU OneApp authorization request. */
const CCI_AUTHORIZATION_COUNTRY = 'de';

/** Maximum redirect hops observed before the IDP login page is reached. */
const MAX_AUTHORIZATION_REDIRECTS = 6;

/** Safe fallback when an API response omits a token lifetime. */
const DEFAULT_TOKEN_LIFETIME_SECONDS = 3600;

/**
 * Authentication stages exposed in errors so callers can distinguish protocol failures.
 */
export type CciAuthenticationStage =
  | 'OneApp authorization'
  | 'certificate retrieval'
  | 'CCI sign-in'
  | 'CCI token processing'
  | 'CCS token exchange'
  | 'CCI token refresh';

/**
 * Stage-aware authentication error that never intentionally includes credentials or complete tokens.
 */
export class CciAuthenticationError extends Error {
  /** Protocol stage that could not complete. */
  public readonly stage: CciAuthenticationStage;

  /** HTTP response status when the failure came from a completed request. */
  public readonly statusCode?: number;

  /**
   * Creates a safe, actionable error for one CCI authentication stage.
   */
  public constructor(stage: CciAuthenticationStage, detail: string, statusCode?: number) {
    const status = statusCode === undefined ? '' : ` (HTTP ${statusCode})`;
    super(`EU CCI ${stage} failed${status}: ${redactSensitiveData(detail)}`);
    this.name = 'CciAuthenticationError';
    this.stage = stage;
    this.statusCode = statusCode;
  }
}

/**
 * Shape used internally after a successful service-specific token exchange.
 */
interface CcsTokenExchangeResult {
  /** Raw CCS access token accepted by the existing ccapi endpoints. */
  accessToken: string;
  /** Absolute token expiry expressed as Unix seconds. */
  expiresAt: number;
}

/**
 * RSA JWK subset guaranteed by the IDP certificate endpoint and required by sign-in.
 */
interface CciJsonWebKey extends nodeCrypto.JsonWebKey {
  /** Key type required by Node's JWK importer. */
  kty: 'RSA';
  /** Server key identifier returned unchanged in the sign-in form. */
  kid: string;
  /** Base64url RSA modulus. */
  n: string;
  /** Base64url RSA public exponent. */
  e: string;
}

/**
 * Optional CCI headers applied only after an initial token set exists.
 */
interface CciHeaderTokens {
  /** CCI access token sent with a Bearer prefix. */
  accessToken: string;
  /** Raw non-CCS token sent in both authentication header variants. */
  nonCcsToken: string;
  /** Token that the service exchange converts into a CCS token. */
  exchangeableAccessToken: string;
}

/**
 * Removes known credential and token representations from diagnostic text.
 */
export function redactSensitiveData(value: string): string {
  return value
    .replace(/(Bearer\s+)[A-Za-z0-9._~+/=-]+/gi, '$1[redacted]')
    .replace(
      /((?:Authentication|exchangeable-token|non-ccs-token)\s*[:=]\s*)[A-Za-z0-9._~+/=-]+/gi,
      '$1[redacted]'
    )
    .replace(
      /("(?:accessToken|refreshToken|access_token|refresh_token|exchangeableAccessToken|exchangeableRefreshToken|nonCcsToken|nonCcsRefreshToken|idToken|password)"\s*:\s*")[^"]*(")/gi,
      '$1[redacted]$2'
    )
    .replace(/([?&](?:code|access_token|refresh_token|password)=)[^&\s]+/gi, '$1[redacted]');
}

/**
 * Calculates an absolute CCS expiry from the relative expiresTime wire value.
 */
export function calculateTokenExpiresAt(expiresTime: unknown, nowMilliseconds: number): number {
  const parsedLifetime = Number(expiresTime);
  const lifetime =
    Number.isFinite(parsedLifetime) && parsedLifetime > 0
      ? Math.floor(parsedLifetime)
      : DEFAULT_TOKEN_LIFETIME_SECONDS;

  return Math.floor(nowMilliseconds / 1000) + lifetime;
}

/**
 * Parses and validates the initial token collection returned by CCI.
 */
export function parseCciTokenSet(payload: unknown, deviceId: string): cciTypes.CciTokenSet {
  const record = getJsonRecord(payload, 'CCI token response');

  return {
    accessToken: getRequiredString(record, 'accessToken'),
    refreshToken: getRequiredString(record, 'refreshToken'),
    exchangeableAccessToken: getRequiredString(record, 'exchangeableAccessToken'),
    exchangeableRefreshToken: getOptionalString(record, 'exchangeableRefreshToken'),
    nonCcsToken: getRequiredString(record, 'nonCcsToken'),
    nonCcsRefreshToken: getOptionalString(record, 'nonCcsRefreshToken'),
    idToken: getOptionalString(record, 'idToken'),
    expiresIn: getPositiveInteger(record.expiresIn, DEFAULT_TOKEN_LIFETIME_SECONDS),
    deviceId,
  };
}

/**
 * Converts an unknown JSON value into an object suitable for named wire-field access.
 */
function getJsonRecord(value: unknown, description: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${description} must be a JSON object`);
  }

  return value as Record<string, unknown>;
}

/**
 * Reads a non-empty token field that is required by the next CCI request.
 */
function getRequiredString(record: Record<string, unknown>, field: string): string {
  const value = record[field];
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`CCI token response is missing ${field}`);
  }

  return value;
}

/**
 * Reads a token field that the API may represent as missing or empty.
 */
function getOptionalString(record: Record<string, unknown>, field: string): string {
  const value = record[field];
  return typeof value === 'string' ? value : '';
}

/**
 * Normalizes a positive integer wire value while retaining a protocol-safe fallback.
 */
function getPositiveInteger(value: unknown, fallback: number): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : fallback;
}

/**
 * Extracts a short server-provided error without exposing arbitrary response payloads.
 */
function getResponseErrorDetail(body: string): string {
  if (/abusing request/i.test(body)) {
    return 'the request was classified as abusive by the IDPConnect WAF';
  }

  try {
    const record = getJsonRecord(JSON.parse(body), 'error response');
    const candidateFields = ['error_description', 'error', 'message', 'retMsg', 'errorMessage'];
    for (const field of candidateFields) {
      if (typeof record[field] === 'string' && record[field] !== '') {
        return record[field] as string;
      }
    }
  } catch {
    // Non-JSON error pages are intentionally not echoed because they may contain session data.
  }

  return 'the remote service rejected the request';
}

/**
 * Returns one response header regardless of whether the transport preserved repeated values.
 */
function getHeader(response: cciTypes.CciHttpResponse, name: string): string {
  const value = response.headers[name.toLowerCase()];
  return Array.isArray(value) ? value[0] ?? '' : value ?? '';
}

/**
 * Returns every Set-Cookie value needed to detect CCI exchange-token rotation.
 */
function getSetCookieHeaders(response: cciTypes.CciHttpResponse): string[] {
  const value = response.headers['set-cookie'];
  if (Array.isArray(value)) {
    return value;
  }

  return value ? [value] : [];
}

/**
 * Extracts the rotated exchangeable token carried by the CCI refresh cookie named t.
 */
function getExchangeableTokenCookie(response: cciTypes.CciHttpResponse): string | undefined {
  for (const cookie of getSetCookieHeaders(response)) {
    const match = cookie.match(/(?:^|[,;]\s*)t=([^;,\s]+)/);
    if (match?.[1]) {
      return match[1];
    }
  }

  return undefined;
}

/**
 * Produces the local UTC offset required by the CCI timezone header.
 */
function getTimezoneOffset(date: Date): string {
  const minutes = -date.getTimezoneOffset();
  const sign = minutes >= 0 ? '+' : '-';
  const absoluteMinutes = Math.abs(minutes);
  const hoursPart = Math.floor(absoluteMinutes / 60)
    .toString()
    .padStart(2, '0');
  const minutesPart = (absoluteMinutes % 60).toString().padStart(2, '0');
  return `${sign}${hoursPart}:${minutesPart}`;
}

/**
 * Decodes a nested redirect parameter without making malformed upstream data fatal by itself.
 */
function decodeRedirectValue(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

/**
 * Implements the current EU OneApp password login, CCI refresh, and CCS token exchange.
 */
export class CciClient {
  /** Verified constants for the selected vehicle brand. */
  private readonly config: Readonly<cciTypes.CciBrandConfig>;

  /** Two-letter language used in authorization and CCI request metadata. */
  private readonly language: string;

  /** Factory isolating cookies and connection identity between authentication operations. */
  private readonly transportFactory: cciTypes.CciHttpTransportFactory;

  /** Injectable wall clock used for deterministic expiry calculations. */
  private readonly now: () => number;

  /**
   * Creates a protocol client for one EU brand without opening a network connection.
   */
  public constructor(
    brand: cciTypes.CciBrand,
    language: string,
    transportFactory: cciTypes.CciHttpTransportFactory = cciTransport.createImpitCciHttpTransport,
    now: () => number = Date.now
  ) {
    this.config = cciConfig.getCciBrandConfig(brand);
    this.language = language.toLowerCase();
    this.transportFactory = transportFactory;
    this.now = now;
  }

  /**
   * Performs password sign-in and returns a CCS token plus all state needed for refresh.
   */
  public async login(input: cciTypes.CciLoginInput): Promise<cciTypes.CciAuthenticationResult> {
    const transport = this.transportFactory();
    await this.authorizeOneApp(transport);
    const certificate = await this.getAuthenticationCertificate(transport);
    const authorizationCode = await this.signIn(transport, input, certificate);
    const tokenSet = await this.createTokenSet(transport, authorizationCode, input.deviceId);
    const ccsToken = await this.exchangeCcsToken(transport, tokenSet);

    return {
      ccsAccessToken: ccsToken.accessToken,
      ccsTokenExpiresAt: ccsToken.expiresAt,
      tokenSet,
    };
  }

  /**
   * Rotates the complete CCI token collection and obtains a fresh CCS access token.
   */
  public async refresh(
    currentTokenSet: cciTypes.CciTokenSet
  ): Promise<cciTypes.CciAuthenticationResult> {
    const transport = this.transportFactory();
    const response = await this.request(
      transport,
      'CCI token refresh',
      `${this.config.cciBaseUrl}/domain/api/v2/auth/token-refresh`,
      'POST',
      this.createCciHeaders(currentTokenSet.deviceId, currentTokenSet, true),
      JSON.stringify({
        accessToken: currentTokenSet.accessToken.replace(/^Bearer\s+/i, ''),
        refreshToken: currentTokenSet.refreshToken,
        exchangeableAccessToken: currentTokenSet.exchangeableAccessToken,
        exchangeableRefreshToken: currentTokenSet.exchangeableRefreshToken,
        nonCcsToken: currentTokenSet.nonCcsToken,
        nonCcsRefreshToken: currentTokenSet.nonCcsRefreshToken,
        idToken: currentTokenSet.idToken,
      })
    );

    if (response.statusCode !== 200) {
      throw new CciAuthenticationError(
        'CCI token refresh',
        getResponseErrorDetail(response.body),
        response.statusCode
      );
    }

    const payload = this.parseJson(response, 'CCI token refresh');
    const refreshedTokenSet = this.mergeRefreshedTokenSet(payload, currentTokenSet);
    const cookieToken = getExchangeableTokenCookie(response);
    if (cookieToken) {
      refreshedTokenSet.exchangeableAccessToken = cookieToken;
    }

    const ccsToken = await this.exchangeCcsToken(transport, refreshedTokenSet);
    return {
      ccsAccessToken: ccsToken.accessToken,
      ccsTokenExpiresAt: ccsToken.expiresAt,
      tokenSet: refreshedTokenSet,
    };
  }

  /**
   * Walks the OneApp authorize redirects to establish the IDP cookie session.
   */
  private async authorizeOneApp(transport: cciTypes.CciHttpTransport): Promise<void> {
    const authorizationUrl = new nodeUrl.URL(
      '/auth/api/v2/user/oauth2/authorize',
      this.config.idpBaseUrl
    );
    authorizationUrl.searchParams.set('response_type', 'code');
    authorizationUrl.searchParams.set('client_id', this.config.oneAppClientId);
    authorizationUrl.searchParams.set('redirect_uri', this.config.oneAppRedirectUri);
    authorizationUrl.searchParams.set('lang', this.language);
    authorizationUrl.searchParams.set('state', 'ccsp');
    authorizationUrl.searchParams.set('country', CCI_AUTHORIZATION_COUNTRY);

    let currentUrl = authorizationUrl.toString();
    for (let hop = 0; hop < MAX_AUTHORIZATION_REDIRECTS; hop += 1) {
      const parsedUrl = new nodeUrl.URL(currentUrl);

      if (parsedUrl.pathname.startsWith('/web/') && parsedUrl.searchParams.has('next_uri')) {
        const nextUri = decodeRedirectValue(parsedUrl.searchParams.get('next_uri') ?? '');
        const nextUrl = new nodeUrl.URL(nextUri, parsedUrl.origin);
        const country = parsedUrl.searchParams.get('country');
        if (country && !nextUrl.searchParams.has('country')) {
          nextUrl.searchParams.set('country', country);
        }
        currentUrl = nextUrl.toString();
        continue;
      }

      const response = await this.request(
        transport,
        'OneApp authorization',
        currentUrl,
        'GET',
        this.createIdpHeaders()
      );
      const location = getHeader(response, 'location');

      if (/abusing request/i.test(response.body) || /\/error\?status=400/i.test(location)) {
        throw new CciAuthenticationError(
          'OneApp authorization',
          'the request was classified as abusive by the IDPConnect WAF',
          response.statusCode
        );
      }

      if ([301, 302, 303, 307, 308].includes(response.statusCode)) {
        if (!location) {
          throw new CciAuthenticationError(
            'OneApp authorization',
            'the IDP returned a redirect without a Location header',
            response.statusCode
          );
        }
        currentUrl = new nodeUrl.URL(location, currentUrl).toString();
        continue;
      }

      if (response.statusCode >= 400) {
        throw new CciAuthenticationError(
          'OneApp authorization',
          getResponseErrorDetail(response.body),
          response.statusCode
        );
      }

      return;
    }

    throw new CciAuthenticationError(
      'OneApp authorization',
      `more than ${MAX_AUTHORIZATION_REDIRECTS} redirects were required`
    );
  }

  /**
   * Retrieves and validates the JWK used to encrypt the account password.
   */
  private async getAuthenticationCertificate(
    transport: cciTypes.CciHttpTransport
  ): Promise<CciJsonWebKey> {
    const response = await this.request(
      transport,
      'certificate retrieval',
      `${this.config.idpBaseUrl}/auth/api/v1/accounts/certs`,
      'GET',
      this.createIdpHeaders()
    );

    if (response.statusCode !== 200) {
      throw new CciAuthenticationError(
        'certificate retrieval',
        getResponseErrorDetail(response.body),
        response.statusCode
      );
    }

    const payload = getJsonRecord(
      this.parseJson(response, 'certificate retrieval'),
      'certificate response'
    );
    const certificate = getJsonRecord(payload.retValue, 'certificate retValue');
    if (
      typeof certificate.kid !== 'string' ||
      typeof certificate.n !== 'string' ||
      typeof certificate.e !== 'string'
    ) {
      throw new CciAuthenticationError(
        'certificate retrieval',
        'the response did not contain a complete RSA JWK'
      );
    }

    return {
      kty: 'RSA',
      kid: certificate.kid,
      n: certificate.n,
      e: certificate.e,
    };
  }

  /**
   * Encrypts the password with RSA PKCS#1 v1.5 and exchanges it for an authorization code.
   */
  private async signIn(
    transport: cciTypes.CciHttpTransport,
    input: cciTypes.CciLoginInput,
    certificate: CciJsonWebKey
  ): Promise<string> {
    let encryptedPassword: string;
    try {
      const publicKey = nodeCrypto.createPublicKey({ key: certificate, format: 'jwk' });
      encryptedPassword = nodeCrypto
        .publicEncrypt(
          {
            key: publicKey,
            padding: nodeCrypto.constants.RSA_PKCS1_PADDING,
          },
          Buffer.from(input.password, 'utf8')
        )
        .toString('hex');
    } catch (error) {
      const detail = error instanceof Error ? error.message : 'RSA encryption failed';
      throw new CciAuthenticationError('certificate retrieval', detail);
    }

    const form = new nodeUrl.URLSearchParams({
      client_id: this.config.oneAppClientId,
      encryptedPassword: 'true',
      password: encryptedPassword,
      redirect_uri: this.config.oneAppRedirectUri,
      scope: '',
      nonce: '',
      state: 'ccsp',
      username: input.username,
      connector_session_key: '',
      kid: certificate.kid ?? '',
      _csrf: '',
    });
    const response = await this.request(
      transport,
      'CCI sign-in',
      `${this.config.idpBaseUrl}/auth/account/signin`,
      'POST',
      this.createIdpHeaders({
        'Content-Type': 'application/x-www-form-urlencoded',
        Origin: this.config.idpBaseUrl,
        Referer: `${this.config.idpBaseUrl}/auth/ui/login`,
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-User': '?1',
        'Upgrade-Insecure-Requests': '1',
      }),
      form.toString()
    );

    if (response.statusCode !== 302) {
      throw new CciAuthenticationError(
        'CCI sign-in',
        getResponseErrorDetail(response.body),
        response.statusCode
      );
    }

    const location = getHeader(response, 'location');
    if (!location) {
      throw new CciAuthenticationError('CCI sign-in', 'the response had no redirect location');
    }

    const redirectUrl = new nodeUrl.URL(location, this.config.idpBaseUrl);
    const code = redirectUrl.searchParams.get('code');
    if (code) {
      return code;
    }

    const errorDescription =
      redirectUrl.searchParams.get('error_description') ?? redirectUrl.searchParams.get('error');
    if (errorDescription) {
      throw new CciAuthenticationError('CCI sign-in', errorDescription);
    }
    if (redirectUrl.pathname.includes('/web/v1/user/authorization')) {
      throw new CciAuthenticationError(
        'CCI sign-in',
        'account consent is required; sign in with the official app once and accept the terms'
      );
    }

    throw new CciAuthenticationError(
      'CCI sign-in',
      `the IDP returned an unexpected redirect to ${redirectUrl.origin}${redirectUrl.pathname}`
    );
  }

  /**
   * Exchanges the authorization code for every token required by CCI refresh.
   */
  private async createTokenSet(
    transport: cciTypes.CciHttpTransport,
    authorizationCode: string,
    deviceId: string
  ): Promise<cciTypes.CciTokenSet> {
    const url = new nodeUrl.URL('/domain/api/v1/auth/token', this.config.cciBaseUrl);
    url.searchParams.set('code', authorizationCode);
    const response = await this.request(
      transport,
      'CCI token processing',
      url.toString(),
      'POST',
      this.createCciHeaders(deviceId)
    );

    if (response.statusCode !== 200) {
      throw new CciAuthenticationError(
        'CCI token processing',
        getResponseErrorDetail(response.body),
        response.statusCode
      );
    }

    try {
      return parseCciTokenSet(this.parseJson(response, 'CCI token processing'), deviceId);
    } catch (error) {
      if (error instanceof CciAuthenticationError) {
        throw error;
      }
      const detail = error instanceof Error ? error.message : 'invalid CCI token response';
      throw new CciAuthenticationError('CCI token processing', detail);
    }
  }

  /**
   * Exchanges an exchangeable CCI token for the CCS token used by vehicle APIs.
   */
  private async exchangeCcsToken(
    transport: cciTypes.CciHttpTransport,
    tokenSet: cciTypes.CciTokenSet
  ): Promise<CcsTokenExchangeResult> {
    const url = new nodeUrl.URL('/domain/api/v1/auth/token-exchange', this.config.cciBaseUrl);
    url.searchParams.set('serviceType', 'CCS');
    const response = await this.request(
      transport,
      'CCS token exchange',
      url.toString(),
      'POST',
      this.createCciHeaders(tokenSet.deviceId, tokenSet)
    );

    if (response.statusCode !== 200) {
      throw new CciAuthenticationError(
        'CCS token exchange',
        getResponseErrorDetail(response.body),
        response.statusCode
      );
    }

    const payload = getJsonRecord(
      this.parseJson(response, 'CCS token exchange'),
      'CCS token response'
    );
    const accessToken =
      (typeof payload.accessToken === 'string' && payload.accessToken) ||
      (typeof payload.ccsAccessToken === 'string' && payload.ccsAccessToken) ||
      '';
    if (!accessToken) {
      throw new CciAuthenticationError(
        'CCS token exchange',
        'the response did not contain accessToken or ccsAccessToken'
      );
    }

    return {
      accessToken,
      expiresAt: calculateTokenExpiresAt(payload.expiresTime, this.now()),
    };
  }

  /**
   * Merges a rotating refresh response with fields that CCI may omit when unchanged.
   */
  private mergeRefreshedTokenSet(
    payload: unknown,
    current: cciTypes.CciTokenSet
  ): cciTypes.CciTokenSet {
    const record = getJsonRecord(payload, 'CCI refresh response');

    return {
      accessToken: getOptionalString(record, 'accessToken') || current.accessToken,
      refreshToken: getOptionalString(record, 'refreshToken') || current.refreshToken,
      exchangeableAccessToken:
        getOptionalString(record, 'exchangeableAccessToken') || current.exchangeableAccessToken,
      exchangeableRefreshToken:
        getOptionalString(record, 'exchangeableRefreshToken') || current.exchangeableRefreshToken,
      nonCcsToken: getOptionalString(record, 'nonCcsToken') || current.nonCcsToken,
      nonCcsRefreshToken:
        getOptionalString(record, 'nonCcsRefreshToken') || current.nonCcsRefreshToken,
      idToken: getOptionalString(record, 'idToken') || current.idToken,
      expiresIn: getPositiveInteger(record.expiresIn, current.expiresIn),
      deviceId: current.deviceId,
    };
  }

  /**
   * Builds the sparse IDP header set while Impit supplies matching browser fingerprint headers.
   */
  private createIdpHeaders(extraHeaders: Record<string, string> = {}): Record<string, string> {
    return {
      'User-Agent': IDP_USER_AGENT,
      ...extraHeaders,
    };
  }

  /**
   * Builds the exact CCI mobile headers for token creation, refresh, and exchange.
   */
  private createCciHeaders(
    deviceId: string,
    tokens?: CciHeaderTokens,
    jsonBody = false
  ): Record<string, string> {
    const headers: Record<string, string> = {
      'client-id': this.config.packageId,
      'client-name': this.config.clientName,
      'client-version': CCI_CLIENT_VERSION,
      'client-os-code': CCI_CLIENT_OS_CODE,
      'client-os-version': this.config.clientOsVersion,
      'client-device-id': deviceId,
      'client-device-model': CCI_CLIENT_DEVICE_MODEL,
      'client-notification-provider-type': this.config.notificationProvider,
      locale: this.language.toUpperCase(),
      timezone: getTimezoneOffset(new Date(this.now())),
      Accept: 'application/json',
      'Accept-Language': this.language,
      'User-Agent': IDP_USER_AGENT,
    };

    if (jsonBody) {
      headers['Content-Type'] = 'application/json';
    }
    if (tokens) {
      headers.Authentication = tokens.nonCcsToken;
      headers.authorization = `Bearer ${tokens.accessToken.replace(/^Bearer\s+/i, '')}`;
      headers['exchangeable-token'] = tokens.exchangeableAccessToken;
      headers['non-ccs-token'] = tokens.nonCcsToken;
    }

    return headers;
  }

  /**
   * Executes a transport request and converts network errors into the active protocol stage.
   */
  private async request(
    transport: cciTypes.CciHttpTransport,
    stage: CciAuthenticationStage,
    url: string,
    method: 'GET' | 'POST',
    headers: Record<string, string>,
    body?: string
  ): Promise<cciTypes.CciHttpResponse> {
    try {
      return await transport.request({ url, method, headers, body });
    } catch (error) {
      if (error instanceof CciAuthenticationError) {
        throw error;
      }
      const detail = error instanceof Error ? error.message : 'network request failed';
      throw new CciAuthenticationError(stage, detail);
    }
  }

  /**
   * Parses JSON while preserving the protocol stage and withholding the raw payload on failure.
   */
  private parseJson(response: cciTypes.CciHttpResponse, stage: CciAuthenticationStage): unknown {
    try {
      return JSON.parse(response.body);
    } catch {
      throw new CciAuthenticationError(stage, 'the remote service returned invalid JSON');
    }
  }
}
