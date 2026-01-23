/**
 * RA-TLS Crypto Client
 * 
 * Provides ECDH + AES-GCM encrypted communication with Nova TEE enclave.
 * Supports both P-384 (Odyn standard) and secp256k1 curves.
 */

import * as secp256k1 from '@noble/secp256k1';

import { fetchAttestation, hexToBytes, type DecodedAttestation } from './attestation';

export interface EncryptedPayload {
    nonce: string;      // hex-encoded 32 bytes
    public_key: string; // hex-encoded DER public key
    data: string;       // hex-encoded encrypted data
}

export interface EncryptedCallTrace {
    endpoint: string;
    url: string;
    curve: 'P-384' | 'secp256k1';
    server_encryption_public_key: string; // hex DER (no 0x)
    request: {
        plaintext: string;
        encrypted_payload: EncryptedPayload;
    };
    response: {
        ok: boolean;
        status: number;
        statusText: string;
        body_text?: string;
        json?: any;
        decrypted_plaintext?: string;
        decrypted_json?: any;
    };
    error?: string;
}

export type EncryptedCallResult<T = any> = {
    data?: T;
    trace: EncryptedCallTrace;
};

export interface RATLSConnectTrace {
    baseUrl: string;
    steps: Array<{
        name: string;
        ok: boolean;
        startedAt: number;
        endedAt: number;
        detail?: any;
        error?: string;
    }>;
    attestation?: {
        url: string;
        http?: { ok: boolean; status: number; statusText: string; contentType?: string };
        decoded?: {
            module_id?: string;
            timestamp?: number;
            pcr_count?: number;
            public_key?: string;
        };
    };
    encryptionPublicKey?: {
        url: string;
        public_key_der?: string;
        curve?: 'P-384' | 'secp256k1';
    };
    client?: {
        curve?: 'P-384' | 'secp256k1';
        client_public_key_der_len?: number;
    };
}

export interface AttestationDoc {
    attestation_doc: string;  // Base64-encoded CBOR attestation
    public_key: string;       // hex-encoded DER public key
}

export type FetchedAttestation = DecodedAttestation & {
    raw_doc: string; // Base64-encoded CBOR attestation
    attestation_doc: string; // Same as raw_doc (kept for backwards compatibility)
    public_key: string; // hex-encoded DER public key
};

// Convert ArrayBuffer to hex string
function bufferToHex(buffer: ArrayBuffer | Uint8Array): string {
    const arr = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    return Array.from(arr)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

// Curve types
type CurveType = 'P-384' | 'secp256k1';

// DER SPKI OIDs
const OID_SEC_P384 = '2b81040022';
const OID_SECP256K1 = '2b8104000a';

function detectCurve(keyHex: string): CurveType {
    if (keyHex.includes(OID_SEC_P384)) return 'P-384';
    if (keyHex.includes(OID_SECP256K1)) return 'secp256k1';

    const len = keyHex.length;
    if (len === 240 || len === 194) return 'P-384';
    if (len === 176 || len === 130) return 'secp256k1';
    if (len > 160) return 'P-384';
    return 'secp256k1';
}

/**
 * Convert DER to raw point format.
 */
function derToRaw(derKey: Uint8Array, curve: CurveType): Uint8Array {
    if (curve === 'P-384') {
        if (derKey.length === 120) return derKey.slice(23);
        if (derKey.length === 97) return derKey;
    }
    if (curve === 'secp256k1') {
        if (derKey.length === 88) return derKey.slice(23);
        if (derKey.length === 65) return derKey;
    }
    console.warn(`[derToRaw] Unexpected key length ${derKey.length} for curve ${curve}`);
    return derKey;
}

/**
 * Convert raw point to DER SPKI format.
 */
function rawToDer(rawKey: Uint8Array, curve: CurveType): Uint8Array {
    if (curve === 'P-384') {
        const header = hexToBytes('3076301006072a8648ce3d020106082b81040022036200');
        const der = new Uint8Array(header.length + rawKey.length);
        der.set(header, 0);
        der.set(rawKey, header.length);
        return der;
    } else {
        const header = hexToBytes('3056301006072a8648ce3d020106052b8104000a034200');
        const der = new Uint8Array(header.length + rawKey.length);
        der.set(header, 0);
        der.set(rawKey, header.length);
        return der;
    }
}

/**
 * EnclaveClient - RA-TLS client for secure communication with Nova TEE
 * 
 * Usage:
 *   const client = new EnclaveClient();
 *   await client.connect('https://your-app.app.sparsity.cloud');
 *   const response = await client.callEncrypted('/api/echo', { message: 'Hello' });
 */
export class EnclaveClient {
    private enclaveBaseUrl: string = '';
    private isConnected: boolean = false;
    private curve: CurveType = 'P-384';

    // Hex-encoded DER public key returned by /api/encryption/public_key (no 0x prefix)
    private serverEncryptionPublicKeyDerHex: string = '';

    get serverEncryptionPublicKey() {
        return this.serverEncryptionPublicKeyDerHex;
    }

    // P-384 keys (WebCrypto)
    private p384KeyPair: CryptoKeyPair | null = null;
    private serverP384Key: CryptoKey | null = null;

    // secp256k1 keys
    private secpPrivKey: Uint8Array | null = null;
    private secpPubKey: Uint8Array | null = null;
    private serverSecpPubKeyRaw: Uint8Array | null = null;

    get baseUrl() {
        return this.enclaveBaseUrl;
    }

    get connected() {
        return this.isConnected;
    }

    constructor() {
        // Bind methods so they remain safe if passed around as callbacks.
        // This prevents runtime errors like: "Cannot read properties of undefined (reading 'call')".
        this.call = this.call.bind(this);
        this.callEncrypted = this.callEncrypted.bind(this);
        this.callEncryptedTrace = this.callEncryptedTrace.bind(this);
        this.connect = this.connect.bind(this);
        this.connectWithTrace = this.connectWithTrace.bind(this);
        this.fetchAttestation = this.fetchAttestation.bind(this);
        this.checkHealth = this.checkHealth.bind(this);
    }

    /**
     * Connect to enclave and establish ECDH key exchange.
     * Fetches attestation and generates ephemeral key pair.
     */
    async connect(baseUrl: string): Promise<AttestationDoc> {
        this.enclaveBaseUrl = baseUrl.replace(/\/$/, '');

        const attestation = await this.fetchAttestation();

        // RA-TLS: the enclave encryption public key is embedded in the attestation document.
        // Use it directly to avoid an extra network call.
        const encryptionPublicKey = ((attestation as any).public_key || '').replace(/^0x/, '');
        if (!encryptionPublicKey) {
            // Fallback for older/non-standard attestation responses.
            const encKey = await this.call<{ public_key_der?: string; public_key_pem?: string }>(
                '/api/encryption/public_key',
                'GET'
            );
            const fallback = (encKey.public_key_der || '').replace(/^0x/, '');
            if (!fallback) throw new Error('Failed to retrieve enclave encryption public key');
            this.serverEncryptionPublicKeyDerHex = fallback;
            (attestation as any).public_key = fallback;
            this.curve = detectCurve(fallback);
        } else {
            this.serverEncryptionPublicKeyDerHex = encryptionPublicKey;
            this.curve = detectCurve(encryptionPublicKey);
        }

        console.log(`[EnclaveClient] Detected curve: ${this.curve}`);

        if (this.curve === 'P-384') {
            this.p384KeyPair = await crypto.subtle.generateKey(
                { name: 'ECDH', namedCurve: 'P-384' },
                true,
                ['deriveBits']
            );

            const serverPubKeyDer = hexToBytes(this.serverEncryptionPublicKeyDerHex);
            const serverPubKeyRaw = derToRaw(serverPubKeyDer, 'P-384');

            this.serverP384Key = await crypto.subtle.importKey(
                'raw',
                serverPubKeyRaw as any,
                { name: 'ECDH', namedCurve: 'P-384' },
                true,
                []
            );
        } else {
            this.secpPrivKey = secp256k1.utils.randomSecretKey();
            this.secpPubKey = secp256k1.getPublicKey(this.secpPrivKey, false);

            const serverPubKeyDer = hexToBytes(this.serverEncryptionPublicKeyDerHex);
            this.serverSecpPubKeyRaw = derToRaw(serverPubKeyDer, 'secp256k1');

            try {
                const rawHex = Array.from(this.serverSecpPubKeyRaw).map(b => b.toString(16).padStart(2, '0')).join('');
                secp256k1.Point.fromHex(rawHex);
            } catch (e) {
                throw new Error(`Invalid server public key: ${e instanceof Error ? e.message : String(e)}`);
            }
        }

        this.isConnected = true;
        return attestation;
    }

    /**
     * Connect to enclave and return a detailed trace of the RA-TLS establishment process.
     * This is intended for UI/debugging.
     */
    async connectWithTrace(baseUrl: string): Promise<{ attestation: AttestationDoc; trace: RATLSConnectTrace }> {
        const trace: RATLSConnectTrace = { baseUrl, steps: [] };

        const step = async <T>(name: string, fn: () => Promise<T>, detail?: any): Promise<T> => {
            const startedAt = Date.now();
            try {
                const result = await fn();
                trace.steps.push({ name, ok: true, startedAt, endedAt: Date.now(), detail });
                return result;
            } catch (e) {
                trace.steps.push({
                    name,
                    ok: false,
                    startedAt,
                    endedAt: Date.now(),
                    detail,
                    error: e instanceof Error ? e.message : String(e),
                });
                throw e;
            }
        };

        this.enclaveBaseUrl = baseUrl.replace(/\/$/, '');

        const attestation = await step('Fetch attestation (/.well-known/attestation)', async () => {
            return await this.fetchAttestation();
        });

        trace.attestation = {
            url: `${this.enclaveBaseUrl}/.well-known/attestation`,
            decoded: {
                module_id: (attestation as any).attestation_document?.module_id,
                timestamp: (attestation as any).attestation_document?.timestamp,
                pcr_count: (attestation as any).attestation_document?.pcrs ? Object.keys((attestation as any).attestation_document.pcrs).length : undefined,
                public_key: (attestation as any).public_key,
            },
        };

        // Prefer encryption public key embedded in the attestation document.
        const embeddedEncKey = ((attestation as any).public_key || '').replace(/^0x/, '');
        if (embeddedEncKey) {
            await step('Use encryption public key from attestation', async () => undefined, {
                source: 'attestation',
            });
            this.serverEncryptionPublicKeyDerHex = embeddedEncKey;
            this.curve = detectCurve(embeddedEncKey);
            trace.encryptionPublicKey = {
                url: `${this.enclaveBaseUrl}/.well-known/attestation`,
                public_key_der: embeddedEncKey,
                curve: this.curve,
            };
        } else {
            // Fallback only if the attestation response doesn't include a key.
            const encKey = await step('Fetch encryption public key (/api/encryption/public_key)', async () => {
                return await this.call<{ public_key_der?: string; public_key_pem?: string }>('/api/encryption/public_key', 'GET');
            });

            const encryptionPublicKey = (encKey.public_key_der || '').replace(/^0x/, '');
            if (!encryptionPublicKey) throw new Error('Failed to retrieve enclave encryption public key');

            this.serverEncryptionPublicKeyDerHex = encryptionPublicKey;
            (attestation as any).public_key = encryptionPublicKey;
            this.curve = detectCurve(encryptionPublicKey);
            trace.encryptionPublicKey = {
                url: `${this.enclaveBaseUrl}/api/encryption/public_key`,
                public_key_der: encryptionPublicKey,
                curve: this.curve,
            };
        }

        await step('Generate client ephemeral keypair', async () => {
            if (this.curve === 'P-384') {
                this.p384KeyPair = await crypto.subtle.generateKey(
                    { name: 'ECDH', namedCurve: 'P-384' },
                    true,
                    ['deriveBits']
                );
            } else {
                this.secpPrivKey = secp256k1.utils.randomSecretKey();
                this.secpPubKey = secp256k1.getPublicKey(this.secpPrivKey, false);
            }
        }, { curve: this.curve });

        await step('Import server public key', async () => {
            const serverPubKeyDer = hexToBytes(this.serverEncryptionPublicKeyDerHex);
            if (this.curve === 'P-384') {
                const serverPubKeyRaw = derToRaw(serverPubKeyDer, 'P-384');
                this.serverP384Key = await crypto.subtle.importKey(
                    'raw',
                    serverPubKeyRaw as any,
                    { name: 'ECDH', namedCurve: 'P-384' },
                    true,
                    []
                );
            } else {
                this.serverSecpPubKeyRaw = derToRaw(serverPubKeyDer, 'secp256k1');
                const rawHex = Array.from(this.serverSecpPubKeyRaw).map(b => b.toString(16).padStart(2, '0')).join('');
                secp256k1.Point.fromHex(rawHex);
            }
        }, { curve: this.curve });

        // Record client pubkey length for reference (DER/SPKI)
        let clientPubDerLen: number | undefined;
        try {
            if (this.curve === 'P-384' && this.p384KeyPair) {
                const raw = await crypto.subtle.exportKey('raw', this.p384KeyPair.publicKey);
                clientPubDerLen = rawToDer(new Uint8Array(raw), 'P-384').length;
            } else if (this.curve === 'secp256k1' && this.secpPubKey) {
                clientPubDerLen = rawToDer(this.secpPubKey, 'secp256k1').length;
            }
        } catch {
            // ignore
        }
        trace.client = { curve: this.curve, client_public_key_der_len: clientPubDerLen };

        this.isConnected = true;
        return { attestation, trace };
    }

    /**
     * Fetch attestation document from enclave.
     */
    async fetchAttestation(): Promise<FetchedAttestation> {
        const result = await fetchAttestation(this.enclaveBaseUrl);
        const publicKey = result.public_key || result.attestation_document?.public_key || '';

        return {
            ...result,
            raw_doc: result.raw_doc,
            attestation_doc: result.raw_doc,
            public_key: publicKey,
        };
    }

    /**
     * Derive shared AES-256 key from ECDH.
     */
    private async deriveSharedKey(peerPublicKeyDer: string): Promise<CryptoKey> {
        const peerKeyBytes = hexToBytes(peerPublicKeyDer);
        const peerRaw = derToRaw(peerKeyBytes, this.curve);

        let sharedSecret: ArrayBuffer;

        if (this.curve === 'P-384') {
            if (!this.p384KeyPair) throw new Error('P-384 keys not initialized');
            const peerKey = await crypto.subtle.importKey(
                'raw', peerRaw as any, { name: 'ECDH', namedCurve: 'P-384' }, true, []
            );
            sharedSecret = await crypto.subtle.deriveBits(
                { name: 'ECDH', public: peerKey }, (this.p384KeyPair as any).privateKey, 384
            );
        } else {
            if (!this.secpPrivKey) throw new Error('secp256k1 keys not initialized');
            const fullSecret = secp256k1.getSharedSecret(this.secpPrivKey, peerRaw);
            sharedSecret = fullSecret.slice(1, 33).buffer;
        }

        const hkdfKey = await crypto.subtle.importKey(
            'raw', sharedSecret as any, { name: 'HKDF' }, false, ['deriveKey']
        );

        return crypto.subtle.deriveKey(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                // Odyn uses HKDF(salt=None, info="encryption data").
                // Using an empty salt here is required for interoperability.
                salt: new Uint8Array(0),
                info: new TextEncoder().encode('encryption data')
            },
            hkdfKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Encrypt plaintext using ECDH-derived AES-GCM key.
     */
    async encrypt(plaintext: string): Promise<EncryptedPayload> {
        if (!this.isConnected) throw new Error('Not connected');

        if (!this.serverEncryptionPublicKeyDerHex) {
            throw new Error('Missing enclave encryption public key; call connect() first');
        }
        const aesKey = await this.deriveSharedKey(this.serverEncryptionPublicKeyDerHex);

        const nonce = crypto.getRandomValues(new Uint8Array(32));
        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: nonce.slice(0, 12) as any },
            aesKey,
            new TextEncoder().encode(plaintext)
        );

        let myPubKeyDer: Uint8Array;
        if (this.curve === 'P-384') {
            const raw = await crypto.subtle.exportKey('raw', this.p384KeyPair!.publicKey);
            myPubKeyDer = rawToDer(new Uint8Array(raw), 'P-384');
        } else {
            myPubKeyDer = rawToDer(this.secpPubKey!, 'secp256k1');
        }

        return {
            nonce: bufferToHex(nonce),
            public_key: bufferToHex(myPubKeyDer),
            data: bufferToHex(ciphertext)
        };
    }

    /**
     * Decrypt payload from enclave.
     */
    async decrypt(payload: { nonce: string; public_key: string; encrypted_data: string }): Promise<string> {
        if (!this.isConnected) throw new Error('Not connected');

        const aesKey = await this.deriveSharedKey(payload.public_key);
        const nonceBytes = hexToBytes(payload.nonce).slice(0, 12);

        const plaintext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: nonceBytes as any },
            aesKey,
            hexToBytes(payload.encrypted_data) as any
        );

        return new TextDecoder().decode(plaintext);
    }

    /**
     * Call enclave API endpoint with encrypted payload.
     * 
     * @param endpoint - API endpoint path (e.g., '/api/echo')
     * @param data - Request data object
     * @returns Decrypted response data
     */
    async callEncrypted<T = any>(endpoint: string, data: any): Promise<T> {
        const payload = JSON.stringify(data);
        const encrypted = await this.encrypt(payload);

        const response = await fetch(`${this.enclaveBaseUrl}${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(encrypted)
        });

        if (!response.ok) {
            let bodyText: string | undefined;
            try {
                bodyText = await response.text();
            } catch {
                bodyText = undefined;
            }

            // Try to extract FastAPI-style { detail: ... }
            let detail: string | undefined;
            if (bodyText) {
                try {
                    const asJson = JSON.parse(bodyText);
                    if (typeof asJson?.detail === 'string') {
                        detail = asJson.detail;
                    } else if (asJson?.detail != null) {
                        detail = JSON.stringify(asJson.detail);
                    }
                } catch {
                    // not JSON
                }
            }

            const suffix = detail ? `: ${detail}` : (bodyText ? `: ${bodyText}` : '');
            throw new Error(`Request failed: ${response.status} ${response.statusText}${suffix}`);
        }

        const result = await response.json();

        // If response contains encrypted data, decrypt it
        if (result.data && result.data.encrypted_data) {
            const decrypted = await this.decrypt(result.data);
            return JSON.parse(decrypted);
        }

        return result;
    }

    /**
     * Call enclave API endpoint with encrypted payload and return a full trace of the interaction.
     * This is meant for UI/debugging and attempts to capture request/response even on failures.
     */
    async callEncryptedTrace<T = any>(endpoint: string, data: any): Promise<EncryptedCallResult<T>> {
        const plaintext = JSON.stringify(data);
        const encrypted = await this.encrypt(plaintext);

        const url = `${this.enclaveBaseUrl}${endpoint}`;
        const trace: EncryptedCallTrace = {
            endpoint,
            url,
            curve: this.curve,
            server_encryption_public_key: this.serverEncryptionPublicKeyDerHex,
            request: {
                plaintext,
                encrypted_payload: encrypted,
            },
            response: {
                ok: false,
                status: 0,
                statusText: '',
            },
        };

        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(encrypted),
            });

            trace.response.ok = response.ok;
            trace.response.status = response.status;
            trace.response.statusText = response.statusText;

            let bodyText: string | undefined;
            try {
                bodyText = await response.text();
            } catch {
                bodyText = undefined;
            }
            trace.response.body_text = bodyText;

            if (bodyText) {
                try {
                    trace.response.json = JSON.parse(bodyText);
                } catch {
                    // non-JSON
                }
            }

            if (!response.ok) {
                const detail = (trace.response.json && (trace.response.json as any).detail)
                    ? (typeof (trace.response.json as any).detail === 'string'
                        ? (trace.response.json as any).detail
                        : JSON.stringify((trace.response.json as any).detail))
                    : undefined;
                trace.error = `Request failed: ${response.status} ${response.statusText}${detail ? `: ${detail}` : ''}`;
                return { trace };
            }

            // If response contains encrypted data, decrypt it
            const json = trace.response.json;
            if (json && json.data && json.data.encrypted_data) {
                try {
                    const decrypted = await this.decrypt(json.data);
                    trace.response.decrypted_plaintext = decrypted;
                    try {
                        trace.response.decrypted_json = JSON.parse(decrypted);
                    } catch {
                        // not JSON
                    }
                    if (trace.response.decrypted_json != null) {
                        return { data: trace.response.decrypted_json as T, trace };
                    }
                } catch (e) {
                    trace.error = `Failed to decrypt response: ${e instanceof Error ? e.message : String(e)}`;
                    return { trace };
                }
            }

            // Plain JSON response
            return { data: (json as T), trace };
        } catch (e) {
            trace.error = e instanceof Error ? e.message : String(e);
            return { trace };
        }
    }

    /**
     * Call enclave API endpoint without encryption (for public endpoints).
     */
    async call<T = any>(endpoint: string, method: 'GET' | 'POST' = 'GET', data?: any): Promise<T> {
        const options: RequestInit = {
            method,
            headers: { 'Content-Type': 'application/json' },
        };

        if (data && method === 'POST') {
            options.body = JSON.stringify(data);
        }

        const response = await fetch(`${this.enclaveBaseUrl}${endpoint}`, options);

        if (!response.ok) {
            // Try to parse detailed error from response body
            let detail: any;
            try {
                const body = await response.json();
                detail = body.detail ?? body;
            } catch {
                detail = null;
            }
            if (detail && typeof detail === 'object' && detail.message) {
                const err = new Error(detail.message) as any;
                err.detail = detail;
                err.status = response.status;
                throw err;
            }
            throw new Error(`Request failed: ${response.status} ${response.statusText}`);
        }

        return response.json();
    }

    /**
     * Check enclave health status.
     */
    async checkHealth(): Promise<any> {
        return this.call('/health');
    }
}

// Singleton instance for convenience
export const enclaveClient = new EnclaveClient();
