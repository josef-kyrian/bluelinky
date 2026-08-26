import * as nodeCrypto from 'crypto';
import * as nodeUrl from 'url';

import got from 'got';
import type * as gotTypes from 'got';

import type * as cciTypes from '../auth/cci/cci.types';
import * as europeConstants from '../constants/europe';
import * as stampConstants from '../constants/stamps';
import type * as commonInterfaces from '../interfaces/common.interfaces';
import logger from '../logger';
import * as commonTools from '../tools/common.tools';
import EuropeanVehicle from '../vehicles/european.vehicle';
import type * as vehicleTypes from '../vehicles/vehicle';
import * as europeanCciAuthStrategy from './authStrategies/european.cciAuth.strategy';
import * as controllerTypes from './controller';

/**
 * Public EU configuration retained by the normal BlueLinky constructor API.
 */
export interface EuropeBlueLinkyConfig extends commonInterfaces.BlueLinkyConfig {
  /** Language sent to IDPConnect and the CCI mobile API. */
  language?: europeConstants.EULanguages;
  /** Region discriminator selecting this controller. */
  region: 'EU';
  /** Stamp source used by the existing ccapi vehicle endpoints. */
  stampMode?: stampConstants.StampMode;
  /** Optional local or remote stamp collection override. */
  stampsFile?: string;
}

/**
 * Vehicle-list entry returned by the EU ccapi endpoint before profile enrichment.
 */
interface EuropeanVehicleDescription {
  /** User-selected display name. */
  nickname: string;
  /** Brand-provided model name. */
  vehicleName: string;
  /** Vehicle registration date in the ccapi wire format. */
  regDate: string;
  /** Stable ccapi vehicle identifier. */
  vehicleId: string;
  /** Non-zero when the vehicle uses CCS2 status and control endpoints. */
  ccuCCS2ProtocolSupport: number;
}

/**
 * Device registration payload returned by the legacy ccapi bootstrap endpoint.
 */
interface DeviceRegistrationResponse {
  /** Standard ccapi result envelope. */
  resMsg?: {
    /** Server-issued identifier required on all later vehicle requests. */
    deviceId?: string;
  };
}

/**
 * Internal seams that make authentication and session behavior deterministic in tests.
 */
export interface EuropeanControllerDependencies {
  /** Optional replacement for the production CCI authentication strategy. */
  authenticationStrategy?: europeanCciAuthStrategy.EuropeanAuthenticationStrategy;
}

/**
 * Coordinates EU session state while delegating OneApp and CCI wire details to its strategy.
 */
export class EuropeanController extends controllerTypes.SessionController<EuropeBlueLinkyConfig> {
  /** Brand-specific constants for the existing ccapi vehicle service. */
  private readonly _environment: europeConstants.EuropeanBrandEnvironment;

  /** Current EU authentication implementation selected during construction. */
  private readonly authenticationStrategy: europeanCciAuthStrategy.EuropeanAuthenticationStrategy;

  /** Shared promise preventing concurrent callers from rotating one CCI token set twice. */
  private refreshInFlight?: Promise<string>;

  /** Vehicle objects cached after the latest account listing. */
  private vehicles: EuropeanVehicle[] = [];

  /** Session exposed by BlueLinky#getSession and consumed by existing vehicle classes. */
  public session: commonInterfaces.Session = {
    accessToken: undefined,
    refreshToken: undefined,
    controlToken: undefined,
    deviceId: nodeCrypto.randomUUID(),
    tokenExpiresAt: 0,
    controlTokenExpiresAt: 0,
    cci: undefined,
  };

  /**
   * Validates EU configuration and selects the current CCI authentication strategy.
   */
  public constructor(
    userConfig: EuropeBlueLinkyConfig,
    dependencies: EuropeanControllerDependencies = {}
  ) {
    super(userConfig);
    this.userConfig.language = userConfig.language ?? europeConstants.DEFAULT_LANGUAGE;
    if (!europeConstants.EU_LANGUAGES.includes(this.userConfig.language)) {
      throw new Error(
        `The language code ${
          this.userConfig.language
        } is not managed. Only ${europeConstants.EU_LANGUAGES.join(', ')} are.`
      );
    }

    this._environment = europeConstants.getBrandEnvironment(userConfig);
    this.authenticationStrategy =
      dependencies.authenticationStrategy ??
      europeanCciAuthStrategy.createEuropeanAuthenticationStrategy(
        userConfig.brand,
        this.userConfig.language
      );
    logger.debug('EU Controller created');
  }

  /**
   * Exposes brand-specific vehicle API constants to existing vehicle implementations.
   */
  public get environment(): europeConstants.EuropeanBrandEnvironment {
    return this._environment;
  }

  /**
   * Refreshes an expiring EU token through CCI, retaining legacy refresh for injected old sessions.
   */
  public async refreshAccessToken(): Promise<string> {
    const shouldRefreshToken = Math.floor(Date.now() / 1000) >= this.session.tokenExpiresAt - 10;

    if (!shouldRefreshToken) {
      return 'Token not expired, no need to refresh';
    }

    if (this.session.cci) {
      return this.refreshCciAccessToken();
    }

    return this.refreshLegacyAccessToken();
  }

  /**
   * Serializes CCI rotation so parallel API calls cannot invalidate each other's refresh state.
   */
  private async refreshCciAccessToken(): Promise<string> {
    if (!this.refreshInFlight) {
      this.refreshInFlight = this.performCciRefresh();
    }

    const pendingRefresh = this.refreshInFlight;
    try {
      return await pendingRefresh;
    } finally {
      if (this.refreshInFlight === pendingRefresh) {
        this.refreshInFlight = undefined;
      }
    }
  }

  /**
   * Applies one complete CCI refresh and updates both compatibility and grouped session fields.
   */
  private async performCciRefresh(): Promise<string> {
    const tokenSet = this.session.cci;
    if (!tokenSet) {
      throw new Error('EU CCI token refresh failed: no CCI token state is available');
    }

    try {
      const result = await this.authenticationStrategy.refresh(tokenSet);
      this.applyAuthenticationResult(result);
      return 'Token refreshed';
    } catch (error) {
      throw commonTools.manageBluelinkyError(error, 'EuropeController.refreshAccessToken');
    }
  }

  /**
   * Preserves the old OAuth refresh behavior for callers that manually inject a legacy EU session.
   */
  private async refreshLegacyAccessToken(): Promise<string> {
    if (!this.session.refreshToken) {
      return 'Need refresh token to refresh access token. Use login()';
    }

    const formData = new nodeUrl.URLSearchParams();
    formData.append('grant_type', 'refresh_token');
    formData.append('redirect_uri', 'https://www.getpostman.com/oauth2/callback');
    formData.append('refresh_token', this.session.refreshToken);

    try {
      const response = await got(this.environment.endpoints.token, {
        method: 'POST',
        headers: {
          Authorization: this.environment.basicToken,
          'Content-Type': 'application/x-www-form-urlencoded',
          Host: this.environment.host,
          Connection: 'Keep-Alive',
          'Accept-Encoding': 'gzip',
          'User-Agent': 'okhttp/3.10.0',
        },
        body: formData.toString(),
        throwHttpErrors: false,
      });

      if (response.statusCode !== 200) {
        return `Refresh token failed: HTTP ${response.statusCode}`;
      }

      const responseBody = JSON.parse(response.body);
      this.session.accessToken = `Bearer ${responseBody.access_token}`;
      this.session.tokenExpiresAt = Math.floor(Date.now() / 1000 + responseBody.expires_in);
      return 'Token refreshed';
    } catch (error) {
      throw commonTools.manageBluelinkyError(error, 'EuropeController.refreshAccessToken');
    }
  }

  /**
   * Obtains a short-lived control token after validating the user's vehicle PIN.
   */
  public async enterPin(): Promise<string> {
    if (!this.session.accessToken) {
      throw new Error('Token not set');
    }

    try {
      const response = await got(`${this.environment.baseUrl}/api/v1/user/pin`, {
        method: 'PUT',
        headers: {
          Authorization: this.session.accessToken,
          'Content-Type': 'application/json',
        },
        body: {
          deviceId: this.session.deviceId,
          pin: this.userConfig.pin,
        },
        json: true,
      });

      this.session.controlToken = `Bearer ${response.body.controlToken}`;
      this.session.controlTokenExpiresAt = Math.floor(
        Date.now() / 1000 + response.body.expiresTime
      );
      return 'PIN entered OK, The pin is valid for 10 minutes';
    } catch (error) {
      throw commonTools.manageBluelinkyError(error, 'EuropeController.pin');
    }
  }

  /**
   * Registers a ccapi device, performs CCI login, and populates the normal Bluelinky session.
   */
  public async login(): Promise<string> {
    try {
      if (!this.userConfig.password || !this.userConfig.username) {
        throw new Error('@EuropeController.login: username and password must be defined.');
      }

      const deviceId = await this.registerDevice();
      const result = await this.authenticationStrategy.login({
        password: this.userConfig.password,
        username: this.userConfig.username,
        deviceId,
      });

      this.session.deviceId = deviceId;
      this.applyAuthenticationResult(result);
      return 'Login success';
    } catch (error) {
      throw commonTools.manageBluelinkyError(error, 'EuropeController.login');
    }
  }

  /**
   * Registers the device identifier required by all existing EU vehicle API requests.
   */
  private async registerDevice(): Promise<string> {
    try {
      const response = await got(`${this.environment.baseUrl}/api/v1/spa/notifications/register`, {
        method: 'POST',
        headers: {
          'ccsp-service-id': this.environment.clientId,
          'Content-Type': 'application/json;charset=UTF-8',
          Host: this.environment.host,
          Connection: 'Keep-Alive',
          'Accept-Encoding': 'gzip',
          'User-Agent': 'okhttp/3.10.0',
          'ccsp-application-id': this.environment.appId,
          Stamp: await this.environment.stamp(),
        },
        body: {
          pushRegId: nodeCrypto.randomBytes(32).toString('hex'),
          pushType: this.environment.pushType,
          uuid: nodeCrypto.randomUUID(),
        },
        json: true,
      });
      const body = response.body as DeviceRegistrationResponse;
      const deviceId = body.resMsg?.deviceId;
      if (!deviceId) {
        throw new Error('EU device registration returned no deviceId');
      }

      return deviceId;
    } catch (error) {
      throw commonTools.manageBluelinkyError(error, 'EuropeController.deviceRegistration');
    }
  }

  /**
   * Keeps root session fields compatible while retaining the grouped CCI refresh state.
   */
  private applyAuthenticationResult(result: cciTypes.CciAuthenticationResult): void {
    this.session.accessToken = `Bearer ${result.ccsAccessToken.replace(/^Bearer\s+/i, '')}`;
    this.session.refreshToken = result.tokenSet.refreshToken;
    this.session.tokenExpiresAt = result.ccsTokenExpiresAt;
    this.session.cci = result.tokenSet;
  }

  /**
   * Keeps the existing no-op logout contract because the ccapi exposes no session revocation here.
   */
  public async logout(): Promise<string> {
    return 'OK';
  }

  /**
   * Loads account vehicles and enriches each list entry with profile details.
   */
  public async getVehicles(): Promise<vehicleTypes.Vehicle[]> {
    if (!this.session.accessToken) {
      throw new Error('Token not set');
    }

    try {
      const response = await got(`${this.environment.baseUrl}/api/v1/spa/vehicles`, {
        method: 'GET',
        headers: {
          ...this.defaultHeaders,
          Stamp: await this.environment.stamp(),
        },
        json: true,
      });

      this.vehicles = await commonTools.asyncMap<EuropeanVehicleDescription, EuropeanVehicle>(
        response.body.resMsg.vehicles,
        async vehicleDescription => {
          const vehicleProfileResponse = await got(
            `${this.environment.baseUrl}/api/v1/spa/vehicles/${vehicleDescription.vehicleId}/profile`,
            {
              method: 'GET',
              headers: {
                ...this.defaultHeaders,
                Stamp: await this.environment.stamp(),
              },
              json: true,
            }
          );

          const vehicleProfile = vehicleProfileResponse.body.resMsg;
          const vehicleConfig = {
            nickname: vehicleDescription.nickname,
            name: vehicleDescription.vehicleName,
            regDate: vehicleDescription.regDate,
            brandIndicator: 'H',
            id: vehicleDescription.vehicleId,
            vin: vehicleProfile.vinInfo[0].basic.vin,
            generation: vehicleProfile.vinInfo[0].basic.modelYear,
            ccuCCS2ProtocolSupport: !!vehicleDescription.ccuCCS2ProtocolSupport,
          } as commonInterfaces.VehicleRegisterOptions;

          return new EuropeanVehicle(vehicleConfig, this);
        }
      );
    } catch (error) {
      throw commonTools.manageBluelinkyError(error, 'EuropeController.getVehicles');
    }

    return this.vehicles;
  }

  /**
   * Ensures both the CCS access token and PIN-derived control token are usable.
   */
  private async checkControlToken(): Promise<void> {
    await this.refreshAccessToken();
    if (
      this.session.controlTokenExpiresAt !== undefined &&
      (!this.session.controlToken || Date.now() / 1000 > this.session.controlTokenExpiresAt)
    ) {
      await this.enterPin();
    }
  }

  /**
   * Returns the authenticated HTTP client used by vehicle control methods.
   */
  public async getVehicleHttpService(): Promise<gotTypes.GotInstance<gotTypes.GotJSONFn>> {
    await this.checkControlToken();
    return got.extend({
      baseUrl: this.environment.baseUrl,
      headers: {
        ...this.defaultHeaders,
        Authorization: this.session.controlToken,
        Stamp: await this.environment.stamp(),
      },
      json: true,
    });
  }

  /**
   * Returns the authenticated HTTP client used by normal vehicle data methods.
   */
  public async getApiHttpService(): Promise<gotTypes.GotInstance<gotTypes.GotJSONFn>> {
    await this.refreshAccessToken();
    return got.extend({
      baseUrl: this.environment.baseUrl,
      headers: {
        ...this.defaultHeaders,
        Stamp: await this.environment.stamp(),
      },
      json: true,
    });
  }

  /**
   * Builds common ccapi headers from the active CCS session without exposing CCI internals.
   */
  private get defaultHeaders(): Record<string, string | undefined> {
    return {
      Authorization: this.session.accessToken,
      offset: (new Date().getTimezoneOffset() / 60).toFixed(2),
      'ccsp-service-id': this.environment.clientId,
      'ccsp-device-id': this.session.deviceId,
      'ccsp-application-id': this.environment.appId,
      'Content-Type': 'application/json',
    };
  }
}
