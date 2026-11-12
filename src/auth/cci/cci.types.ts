/**
 * EU brands whose current account login is backed by the OneApp CCI service.
 */
export type CciBrand = 'hyundai' | 'kia';

/**
 * Brand-specific Android identity and key suffix used only by CCI request signing.
 */
export interface CciSigningConfig {
  /** Android OneApp name validated together with the package identifier. */
  readonly clientName: string;
  /** Display-case brand label required by the X-Brand header. */
  readonly brandLabel: string;
  /** App-embedded HMAC key suffix; never include it in diagnostics. */
  readonly keySuffix: string;
}

/**
 * Brand-specific constants required by the current OneApp and CCI wire protocols.
 */
export interface CciBrandConfig {
  /** Brand represented by this immutable configuration entry. */
  brand: CciBrand;
  /** IDPConnect origin used for authorization, certificate retrieval, and sign-in. */
  idpBaseUrl: string;
  /** OAuth client identifier embedded in the current EU OneApp. */
  oneAppClientId: string;
  /** Redirect URI registered for the OneApp OAuth client. */
  oneAppRedirectUri: string;
  /** CCI API origin used for token creation, refresh, and service exchange. */
  cciBaseUrl: string;
  /** Mobile package identifier sent as the CCI client-id header. */
  packageId: string;
  /** Brand identifier sent as the CCI client-name header. */
  clientName: string;
  /** Mobile operating-system version expected by the brand-specific CCI profile. */
  clientOsVersion: string;
  /** Push-provider identifier expected by the brand-specific CCI profile. */
  notificationProvider: string;
  /** Verified Android signing identity, separate from the legacy iOS fallback profile. */
  signing: Readonly<CciSigningConfig>;
}

/**
 * Complete CCI token state required to refresh a session without another password sign-in.
 */
export interface CciTokenSet {
  /** CCI access token used in the authorization header, distinct from the CCS token. */
  accessToken: string;
  /** CCI refresh token submitted to the v2 token-refresh endpoint. */
  refreshToken: string;
  /** Access token that can be exchanged for a service-specific CCS token. */
  exchangeableAccessToken: string;
  /** Refresh companion for the exchangeable access token. */
  exchangeableRefreshToken: string;
  /** Token representing services outside CCS and used by CCI authentication headers. */
  nonCcsToken: string;
  /** Refresh companion for the non-CCS token. */
  nonCcsRefreshToken: string;
  /** OpenID identity token retained because the CCI refresh body requires it. */
  idToken: string;
  /** Lifetime in seconds reported for the CCI access token. */
  expiresIn: number;
  /** Stable registered device identifier to which this token set is bound. */
  deviceId: string;
}

/**
 * Result consumed by the European controller after login or refresh.
 */
export interface CciAuthenticationResult {
  /** Raw CCS token accepted by the existing EU ccapi vehicle endpoints. */
  ccsAccessToken: string;
  /** Absolute Unix timestamp in seconds at which the CCS token expires. */
  ccsTokenExpiresAt: number;
  /** Full token set that must be retained for the next CCI refresh. */
  tokenSet: CciTokenSet;
}

/**
 * Credentials and registered device identity supplied to a CCI password login.
 */
export interface CciLoginInput {
  /** Full account email address expected by IDPConnect. */
  username: string;
  /** Plaintext account password encrypted immediately before sign-in. */
  password: string;
  /** Device identifier returned by the EU notification registration endpoint. */
  deviceId: string;
}

/**
 * Minimal request contract used to keep the protocol client independent of its TLS transport.
 */
export interface CciHttpRequest {
  /** Absolute request URL, including protocol query parameters. */
  url: string;
  /** HTTP verb used by the current CCI flow. */
  method: 'GET' | 'POST';
  /** String-valued headers passed to the fingerprinted HTTP client. */
  headers: Record<string, string>;
  /** Optional serialized form or JSON request body. */
  body?: string;
}

/**
 * Transport-neutral response consumed by the CCI protocol client and test doubles.
 */
export interface CciHttpResponse {
  /** Numeric HTTP response status. */
  statusCode: number;
  /** Lowercase response headers, preserving repeated Set-Cookie values when available. */
  headers: Record<string, string | string[] | undefined>;
  /** Response payload decoded as UTF-8 text. */
  body: string;
  /** Final request URL reported by the transport. */
  url: string;
}

/**
 * HTTP boundary implemented by the production Impit transport and deterministic test fakes.
 */
export interface CciHttpTransport {
  /** Executes one CCI/IDP request without automatically following redirects. */
  request(request: CciHttpRequest): Promise<CciHttpResponse>;
}

/**
 * Factory that gives each login or refresh operation an isolated transport session.
 */
export type CciHttpTransportFactory = () => CciHttpTransport;
