import * as nodeCrypto from 'crypto';

import type * as cciTypes from './cci.types';

/** Android OneApp build whose identity is bound to the configured signing constants. */
const SIGNED_CLIENT_VERSION = '1.4.0';
/** Platform identifier included in both the HMAC key and message. */
const SIGNED_OS_CODE = 'android';
/** Operating-system version included in the signed message. */
const SIGNED_OS_VERSION = '14';
/** Twelve random bytes form the 24-character hexadecimal prefix of App-Request-Id. */
const REQUEST_ID_RANDOM_BYTES = 12;

/**
 * Creates the Android profile and fingerprint without owning HTTP, tokens, or session state.
 * The caller must send the same body string; only ASCII whitespace is removed for the HMAC.
 * Protocol and signing-constant provenance is documented in THIRD_PARTY_NOTICES.
 */
export function createSignedHeaders(
	packageId: string,
	config: Readonly<cciTypes.CciSigningConfig>,
	deviceId: string,
	nowMilliseconds: number,
	body: string
): Record<string, string> {
	const timestamp = String(nowMilliseconds);
	const identity = packageId + config.clientName + SIGNED_CLIENT_VERSION + SIGNED_OS_CODE;
	const message = identity + SIGNED_OS_VERSION + timestamp + body.replace(/[ \t\n\v\f\r]/g, '');
	const fingerprint = nodeCrypto
		.createHmac('sha256', Buffer.from(identity + config.keySuffix, 'utf8'))
		.update(message, 'utf8')
		.digest('hex');
	const requestId = nodeCrypto.randomBytes(REQUEST_ID_RANDOM_BYTES).toString('hex').toUpperCase();

	return {
		'client-id': packageId,
		'client-name': config.clientName,
		'client-version': SIGNED_CLIENT_VERSION,
		'client-os-code': SIGNED_OS_CODE,
		'client-os-version': SIGNED_OS_VERSION,
		'client-device-model': 'SM-S918B',
		'client-notification-provider-type': 'FCM',
		'App-Request-Id': `${requestId}_${deviceId.replace(/-/g, '')}_AOS`,
		'X-Brand': config.brandLabel,
		'X-Region': 'eu',
		'X-Timestamp': timestamp,
		'X-Fingerprint': fingerprint,
		Accept: '*/*',
		'User-Agent': 'okhttp/4.12.0',
	};
}
