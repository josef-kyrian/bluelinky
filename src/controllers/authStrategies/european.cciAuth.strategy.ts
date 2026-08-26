import * as cciClient from '../../auth/cci/cci.client';
import type * as cciTypes from '../../auth/cci/cci.types';
import type * as commonInterfaces from '../../interfaces/common.interfaces';

/**
 * Controller-facing contract for the current EU authentication implementation.
 */
export interface EuropeanAuthenticationStrategy {
  /** Stable strategy name used for diagnostics and selection tests. */
  readonly name: string;

  /** Performs a full password login after the vehicle API has registered a device. */
  login(input: cciTypes.CciLoginInput): Promise<cciTypes.CciAuthenticationResult>;

  /** Rotates the stored CCI state and exchanges it for a new CCS access token. */
  refresh(tokenSet: cciTypes.CciTokenSet): Promise<cciTypes.CciAuthenticationResult>;
}

/**
 * Thin authentication strategy that keeps CCI protocol details outside the European controller.
 */
export class EuropeanCciAuthStrategy implements EuropeanAuthenticationStrategy {
  /** Protocol client responsible for OneApp, CCI, and CCS wire operations. */
  private readonly client: cciClient.CciClient;

  /**
   * Creates a strategy for one EU brand and language.
   */
  public constructor(
    brand: commonInterfaces.Brand,
    language: string,
    client?: cciClient.CciClient
  ) {
    this.client = client ?? new cciClient.CciClient(brand, language);
  }

  /**
   * Identifies the strategy selected for normal EU username/password authentication.
   */
  public get name(): string {
    return 'EuropeanCciAuthStrategy';
  }

  /**
   * Delegates a complete password login to the isolated CCI protocol client.
   */
  public login(input: cciTypes.CciLoginInput): Promise<cciTypes.CciAuthenticationResult> {
    return this.client.login(input);
  }

  /**
   * Delegates token rotation and CCS exchange to the isolated CCI protocol client.
   */
  public refresh(tokenSet: cciTypes.CciTokenSet): Promise<cciTypes.CciAuthenticationResult> {
    return this.client.refresh(tokenSet);
  }
}

/**
 * Selects CCI authentication for every currently supported EU brand.
 */
export function createEuropeanAuthenticationStrategy(
  brand: commonInterfaces.Brand,
  language: string
): EuropeanAuthenticationStrategy {
  return new EuropeanCciAuthStrategy(brand, language);
}
