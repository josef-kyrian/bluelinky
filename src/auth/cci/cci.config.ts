import type * as cciTypes from './cci.types';

/**
 * Creates one immutable brand configuration while keeping shared OneApp metadata centralized.
 */
function createBrandConfig(config: cciTypes.CciBrandConfig): Readonly<cciTypes.CciBrandConfig> {
  Object.freeze(config.signing);
  return Object.freeze(config);
}

/**
 * Current OneApp/CCI constants extracted from the production Hyundai and Kia EU applications.
 */
const CCI_BRAND_CONFIGS: Readonly<Record<cciTypes.CciBrand, Readonly<cciTypes.CciBrandConfig>>> =
  Object.freeze({
    hyundai: createBrandConfig({
      brand: 'hyundai',
      idpBaseUrl: 'https://idpconnect-eu.hyundai.com',
      oneAppClientId: '4f4953b5-02e1-4dbc-8599-87e983ee1be5',
      oneAppRedirectUri: 'https://oneapp.hyundai.com/redirect',
      cciBaseUrl: 'https://cci-api-eu.hyundai.com',
      packageId: 'com.hyundai.oneapp.eu',
      clientName: 'hyundai',
      clientOsVersion: '18.7',
      notificationProvider: 'APNS',
      signing: {
        clientName: 'HyundaiEU',
        brandLabel: 'Hyundai',
        // Android OneApp 1.4.0 constants verified against the MIT references in THIRD_PARTY_NOTICES.
        keySuffix: 'OsZDfDuCyVX' + 'yfqjCoA2JbX' + '2MrLpGwNBC',
      },
    }),
    kia: createBrandConfig({
      brand: 'kia',
      idpBaseUrl: 'https://idpconnect-eu.kia.com',
      oneAppClientId: '01b36c86-79e8-486c-8009-15f2ad88d670',
      oneAppRedirectUri: 'https://oneapp.kia.com/redirect',
      cciBaseUrl: 'https://cci-api-eu.kia.com',
      packageId: 'com.kia.oneapp.eu',
      clientName: 'kia',
      clientOsVersion: '27',
      notificationProvider: 'IOS_APPSTORE',
      signing: {
        clientName: 'KiaEU',
        brandLabel: 'Kia',
        // Android OneApp 1.4.0 constants verified against the MIT references in THIRD_PARTY_NOTICES.
        keySuffix: 'yb4Z1n2nlKe' + 'ukNilE7QEdb' + 'KB34nStPVa',
      },
    }),
  });

/**
 * Selects the verified OneApp/CCI constants for an EU brand.
 */
export function getCciBrandConfig(brand: cciTypes.CciBrand): Readonly<cciTypes.CciBrandConfig> {
  const config = CCI_BRAND_CONFIGS[brand];

  if (!config) {
    throw new Error(`EU CCI authentication does not support brand: ${String(brand)}`);
  }

  return config;
}
