/* eslint-disable @typescript-eslint/no-explicit-any */

import * as nodeCrypto from 'crypto';
import * as nodeUrl from 'url';

import got from 'got';

import * as cciClient from '../src/auth/cci/cci.client';
import * as cciConfig from '../src/auth/cci/cci.config';
import type * as cciTypes from '../src/auth/cci/cci.types';
import * as stampConstants from '../src/constants/stamps';
import * as americanController from '../src/controllers/american.controller';
import * as europeanCciAuthStrategy from '../src/controllers/authStrategies/european.cciAuth.strategy';
import * as europeanController from '../src/controllers/european.controller';
import BlueLinky from '../src/index';

jest.mock('got');

const NOW_MILLISECONDS = 1_700_000_000_000;

/**
 * Deterministic transport that records requests and returns a predefined response sequence.
 */
class QueueTransport implements cciTypes.CciHttpTransport {
  /** Requests emitted by the client in wire order. */
  public readonly requests: cciTypes.CciHttpRequest[] = [];

  /** Remaining responses or network errors consumed by request calls. */
  private readonly queue: Array<cciTypes.CciHttpResponse | Error>;

  /**
   * Creates a transport with one queue entry per expected network request.
   */
  public constructor(queue: Array<cciTypes.CciHttpResponse | Error>) {
    this.queue = [...queue];
  }

  /**
   * Records one request and resolves or rejects with the next queue entry.
   */
  public async request(request: cciTypes.CciHttpRequest): Promise<cciTypes.CciHttpResponse> {
    this.requests.push(request);
    const next = this.queue.shift();
    if (!next) {
      throw new Error(`Unexpected request: ${request.method} ${request.url}`);
    }
    if (next instanceof Error) {
      throw next;
    }

    return {
      ...next,
      url: next.url || request.url,
    };
  }
}

/**
 * Creates a transport response while serializing JSON fixtures exactly as the API would.
 */
function response(
  statusCode: number,
  body: unknown,
  headers: Record<string, string | string[]> = {}
): cciTypes.CciHttpResponse {
  return {
    statusCode,
    headers,
    body: typeof body === 'string' ? body : JSON.stringify(body),
    url: 'https://fixture.invalid/',
  };
}

/**
 * Generates a valid RSA public JWK for the password-encryption stage.
 */
function createCertificateResponse(): cciTypes.CciHttpResponse {
  const keyPair = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
  const publicJwk = keyPair.publicKey.export({ format: 'jwk' });
  return response(200, {
    retValue: {
      kid: 'fixture-key',
      n: publicJwk.n,
      e: publicJwk.e,
    },
  });
}

/**
 * Returns a complete initial CCI token payload reused by login and controller tests.
 */
function createTokenSet(overrides: Partial<cciTypes.CciTokenSet> = {}): cciTypes.CciTokenSet {
  return {
    accessToken: 'cci-access-1',
    refreshToken: 'cci-refresh-1',
    exchangeableAccessToken: 'exchangeable-access-1',
    exchangeableRefreshToken: 'exchangeable-refresh-1',
    nonCcsToken: 'non-ccs-1',
    nonCcsRefreshToken: 'non-ccs-refresh-1',
    idToken: 'id-token-1',
    expiresIn: 3599,
    deviceId: 'registered-device',
    ...overrides,
  };
}

/**
 * Builds the five-response sequence for a complete CCI password login.
 */
function createLoginResponses(ccsPayload: unknown): cciTypes.CciHttpResponse[] {
  return [
    response(200, '<html>login</html>'),
    createCertificateResponse(),
    response(302, '', {
      location: 'https://oneapp.hyundai.com/redirect?code=authorization-code&state=ccsp',
    }),
    response(200, {
      accessToken: 'cci-access-1',
      refreshToken: 'cci-refresh-1',
      exchangeableAccessToken: 'exchangeable-access-1',
      exchangeableRefreshToken: 'exchangeable-refresh-1',
      nonCcsToken: 'non-ccs-1',
      nonCcsRefreshToken: 'non-ccs-refresh-1',
      idToken: 'id-token-1',
      expiresIn: '3599',
    }),
    response(200, ccsPayload),
  ];
}

describe('EU CCI configuration and strategy selection', () => {
  it('selects verified brand-specific constants', () => {
    const hyundai = cciConfig.getCciBrandConfig('hyundai');
    const kia = cciConfig.getCciBrandConfig('kia');

    expect(hyundai.oneAppClientId).toBe('4f4953b5-02e1-4dbc-8599-87e983ee1be5');
    expect(hyundai.packageId).toBe('com.hyundai.oneapp.eu');
    expect(hyundai.notificationProvider).toBe('APNS');
    expect(kia.oneAppClientId).toBe('01b36c86-79e8-486c-8009-15f2ad88d670');
    expect(kia.packageId).toBe('com.kia.oneapp.eu');
    expect(kia.notificationProvider).toBe('IOS_APPSTORE');
  });

  it('selects CCI authentication for a normal EU controller', () => {
    const strategy = europeanCciAuthStrategy.createEuropeanAuthenticationStrategy('hyundai', 'cs');

    expect(strategy).toBeInstanceOf(europeanCciAuthStrategy.EuropeanCciAuthStrategy);
    expect(strategy.name).toBe('EuropeanCciAuthStrategy');
  });

  it('does not change non-EU controller selection', () => {
    const client = new BlueLinky({
      username: 'fixture@example.com',
      password: 'not-a-real-password',
      pin: '1234',
      brand: 'hyundai',
      region: 'US',
      autoLogin: false,
    });
    const controller = (client as unknown as { controller: unknown }).controller;

    expect(controller).toBeInstanceOf(americanController.AmericanController);
  });
});

describe('CciClient login', () => {
  it('parses the complete token set and exchanges it for a CCS token', async () => {
    const transport = new QueueTransport(
      createLoginResponses({ accessToken: 'ccs-access-1', expiresTime: '86400' })
    );
    const client = new cciClient.CciClient(
      'hyundai',
      'cs',
      () => transport,
      () => NOW_MILLISECONDS
    );

    const result = await client.login({
      username: 'fixture@example.com',
      password: 'PlaintextPassword1!',
      deviceId: 'registered-device',
    });

    expect(result.ccsAccessToken).toBe('ccs-access-1');
    expect(result.ccsTokenExpiresAt).toBe(Math.floor(NOW_MILLISECONDS / 1000) + 86400);
    expect(result.tokenSet).toEqual(createTokenSet());
    expect(transport.requests).toHaveLength(5);

    const signInForm = new nodeUrl.URLSearchParams(transport.requests[2].body);
    expect(signInForm.get('encryptedPassword')).toBe('true');
    expect(signInForm.get('password')).toMatch(/^[0-9a-f]+$/);
    expect(signInForm.get('password')).not.toContain('PlaintextPassword1!');
    expect(transport.requests[3].headers['client-id']).toBe('com.hyundai.oneapp.eu');
    expect(transport.requests[3].headers.locale).toBe('CS');
    expect(transport.requests[4].headers.authorization).toBe('Bearer cci-access-1');
    expect(transport.requests[4].headers['exchangeable-token']).toBe('exchangeable-access-1');
  });

  it('rejects a successful CCS response that contains no usable access token', async () => {
    const transport = new QueueTransport(createLoginResponses({ expiresTime: 86400 }));
    const client = new cciClient.CciClient(
      'hyundai',
      'en',
      () => transport,
      () => NOW_MILLISECONDS
    );

    await expect(
      client.login({
        username: 'fixture@example.com',
        password: 'PlaintextPassword1!',
        deviceId: 'registered-device',
      })
    ).rejects.toMatchObject({
      name: 'CciAuthenticationError',
      stage: 'CCS token exchange',
    });
  });

  it('propagates the failing authentication stage and redacts request secrets', async () => {
    const transport = new QueueTransport([
      new Error(
        'request failed at https://idp.invalid/path?code=secret-code ' +
          'Bearer complete-token Authentication: raw-non-ccs-token'
      ),
    ]);
    const client = new cciClient.CciClient('hyundai', 'en', () => transport);

    await expect(
      client.login({
        username: 'fixture@example.com',
        password: 'PlaintextPassword1!',
        deviceId: 'registered-device',
      })
    ).rejects.toThrow(
      'EU CCI OneApp authorization failed: request failed at ' +
        'https://idp.invalid/path?code=[redacted] Bearer [redacted] Authentication: [redacted]'
    );
  });

  it('calculates expiration from relative seconds and uses a safe fallback', () => {
    expect(cciClient.calculateTokenExpiresAt('120', NOW_MILLISECONDS)).toBe(
      Math.floor(NOW_MILLISECONDS / 1000) + 120
    );
    expect(cciClient.calculateTokenExpiresAt('invalid', NOW_MILLISECONDS)).toBe(
      Math.floor(NOW_MILLISECONDS / 1000) + 3600
    );
  });
});

describe('CciClient refresh', () => {
  it('rotates all returned fields, honors the t cookie, and exchanges a fresh CCS token', async () => {
    const transport = new QueueTransport([
      response(
        200,
        {
          accessToken: 'cci-access-2',
          refreshToken: 'cci-refresh-2',
          exchangeableRefreshToken: 'exchangeable-refresh-2',
          nonCcsToken: 'non-ccs-2',
          nonCcsRefreshToken: 'non-ccs-refresh-2',
          idToken: 'id-token-2',
          expiresIn: 7200,
        },
        { 'set-cookie': ['session=fixture; Path=/', 't=cookie-exchangeable-2; Path=/'] }
      ),
      response(200, { ccsAccessToken: 'ccs-access-2', expiresTime: 120 }),
    ]);
    const client = new cciClient.CciClient(
      'hyundai',
      'en',
      () => transport,
      () => NOW_MILLISECONDS
    );

    const result = await client.refresh(createTokenSet());

    expect(JSON.parse(transport.requests[0].body ?? '{}')).toEqual({
      accessToken: 'cci-access-1',
      refreshToken: 'cci-refresh-1',
      exchangeableAccessToken: 'exchangeable-access-1',
      exchangeableRefreshToken: 'exchangeable-refresh-1',
      nonCcsToken: 'non-ccs-1',
      nonCcsRefreshToken: 'non-ccs-refresh-1',
      idToken: 'id-token-1',
    });
    expect(result.tokenSet).toEqual(
      createTokenSet({
        accessToken: 'cci-access-2',
        refreshToken: 'cci-refresh-2',
        exchangeableAccessToken: 'cookie-exchangeable-2',
        exchangeableRefreshToken: 'exchangeable-refresh-2',
        nonCcsToken: 'non-ccs-2',
        nonCcsRefreshToken: 'non-ccs-refresh-2',
        idToken: 'id-token-2',
        expiresIn: 7200,
      })
    );
    expect(transport.requests[1].headers['exchangeable-token']).toBe('cookie-exchangeable-2');
    expect(result.ccsAccessToken).toBe('ccs-access-2');
    expect(result.ccsTokenExpiresAt).toBe(Math.floor(NOW_MILLISECONDS / 1000) + 120);
  });
});

describe('EuropeanController CCI session integration', () => {
  const config = {
    username: 'fixture@example.com',
    password: 'not-a-real-password',
    pin: '1234',
    brand: 'hyundai' as const,
    region: 'EU' as const,
    language: 'cs' as const,
    stampMode: stampConstants.StampMode.LOCAL,
  };

  beforeEach(() => {
    (got as unknown as jest.Mock).mockReset();
  });

  it('stores the CCS token and grouped CCI state during normal login', async () => {
    const loginResult: cciTypes.CciAuthenticationResult = {
      ccsAccessToken: 'ccs-access-1',
      ccsTokenExpiresAt: Math.floor(NOW_MILLISECONDS / 1000) + 86400,
      tokenSet: createTokenSet(),
    };
    const authenticationStrategy: europeanCciAuthStrategy.EuropeanAuthenticationStrategy = {
      name: 'FixtureCciAuthStrategy',
      login: jest.fn().mockResolvedValue(loginResult),
      refresh: jest.fn(),
    };
    (got as unknown as jest.Mock).mockResolvedValueOnce({
      statusCode: 200,
      body: { resMsg: { deviceId: 'registered-device' } },
    });
    const controller = new europeanController.EuropeanController(config, {
      authenticationStrategy,
    });

    await expect(controller.login()).resolves.toBe('Login success');

    expect(authenticationStrategy.login).toHaveBeenCalledWith({
      username: config.username,
      password: config.password,
      deviceId: 'registered-device',
    });
    expect(controller.session.accessToken).toBe('Bearer ccs-access-1');
    expect(controller.session.refreshToken).toBe('cci-refresh-1');
    expect(controller.session.tokenExpiresAt).toBe(loginResult.ccsTokenExpiresAt);
    expect(controller.session.cci).toEqual(createTokenSet());

    const registrationOptions = (got as unknown as jest.Mock).mock.calls[0][1];
    expect(registrationOptions.body.pushType).toBe('GCM');
    expect(registrationOptions.headers['ccsp-application-id']).toBe(
      '014d2225-8495-4735-812d-2616334fd15d'
    );
  });

  it('updates every session token field after CCI refresh', async () => {
    const refreshedResult: cciTypes.CciAuthenticationResult = {
      ccsAccessToken: 'ccs-access-2',
      ccsTokenExpiresAt: Math.floor(NOW_MILLISECONDS / 1000) + 120,
      tokenSet: createTokenSet({
        accessToken: 'cci-access-2',
        refreshToken: 'cci-refresh-2',
      }),
    };
    const authenticationStrategy: europeanCciAuthStrategy.EuropeanAuthenticationStrategy = {
      name: 'FixtureCciAuthStrategy',
      login: jest.fn(),
      refresh: jest.fn().mockResolvedValue(refreshedResult),
    };
    const controller = new europeanController.EuropeanController(config, {
      authenticationStrategy,
    });
    controller.session.cci = createTokenSet();
    controller.session.refreshToken = 'cci-refresh-1';
    controller.session.accessToken = 'Bearer old-ccs-access';
    controller.session.tokenExpiresAt = 0;

    await expect(controller.refreshAccessToken()).resolves.toBe('Token refreshed');

    expect(authenticationStrategy.refresh).toHaveBeenCalledWith(createTokenSet());
    expect(controller.session.accessToken).toBe('Bearer ccs-access-2');
    expect(controller.session.refreshToken).toBe('cci-refresh-2');
    expect(controller.session.cci).toEqual(refreshedResult.tokenSet);
    expect(controller.session.tokenExpiresAt).toBe(refreshedResult.ccsTokenExpiresAt);
  });
});
