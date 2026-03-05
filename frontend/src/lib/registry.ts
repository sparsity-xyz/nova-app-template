/**
 * Nova App Registry Client
 *
 * Registry-mode connection flow:
 * 1) Query getActiveInstances(appId) to list active instance wallets.
 * 2) Randomly pick one wallet from the active set.
 * 3) Query getInstanceByWallet(wallet) for URL + teePubkey.
 * 4) Query getVersion(appId, versionId) for codeMeasurement.
 */

// Default registry contract address on Base Sepolia.
export const DEFAULT_REGISTRY_ADDRESS = '0x0f68E6e699f2E972998a1EcC000c7ce103E64cc8';

// Default RPC URL for Base Sepolia
export const DEFAULT_RPC_URL = 'https://sepolia.base.org';

const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';
const WORD_BYTES = 32;

// Function selectors
const SELECTOR_GET_ACTIVE_INSTANCES = '0x8c228cbf'; // getActiveInstances(uint256)
const SELECTOR_GET_INSTANCE_BY_WALLET = '0x9863f8a2'; // getInstanceByWallet(address)
const SELECTOR_GET_VERSION = '0x6987b075'; // getVersion(uint256,uint256)

// App-registry ABI subset used by frontend.
const REGISTRY_ABI = [
    {
        inputs: [{ name: 'appId', type: 'uint256' }],
        name: 'getActiveInstances',
        outputs: [{ name: '', type: 'address[]' }],
        stateMutability: 'view',
        type: 'function',
    },
    {
        inputs: [{ name: 'teeWalletAddress', type: 'address' }],
        name: 'getInstanceByWallet',
        outputs: [
            {
                components: [
                    { name: 'instanceId', type: 'uint256' },
                    { name: 'appId', type: 'uint256' },
                    { name: 'versionId', type: 'uint256' },
                    { name: 'operator', type: 'address' },
                    { name: 'instanceUrl', type: 'string' },
                    { name: 'teePubkey', type: 'bytes' },
                    { name: 'teeWalletAddress', type: 'address' },
                    { name: 'zkVerified', type: 'bool' },
                    { name: 'status', type: 'uint8' },
                    { name: 'registeredAt', type: 'uint256' },
                ],
                name: '',
                type: 'tuple',
            },
        ],
        stateMutability: 'view',
        type: 'function',
    },
    {
        inputs: [
            { name: 'appId', type: 'uint256' },
            { name: 'versionId', type: 'uint256' },
        ],
        name: 'getVersion',
        outputs: [
            {
                components: [
                    { name: 'versionId', type: 'uint256' },
                    { name: 'versionName', type: 'string' },
                    { name: 'codeMeasurement', type: 'bytes32' },
                    { name: 'imageUri', type: 'string' },
                    { name: 'auditUrl', type: 'string' },
                    { name: 'auditHash', type: 'string' },
                    { name: 'githubRunId', type: 'string' },
                    { name: 'status', type: 'uint8' },
                    { name: 'enrolledAt', type: 'uint256' },
                    { name: 'enrolledBy', type: 'address' },
                ],
                name: '',
                type: 'tuple',
            },
        ],
        stateMutability: 'view',
        type: 'function',
    },
] as const;

// Keep exported so callers can inspect the exact ABI used for frontend reads.
export { REGISTRY_ABI };

export interface SparsityApp {
    owner: string; // selected instance operator
    appId: bigint;
    teeArch: string;
    codeMeasurement: string;
    teePubkey: string;
    teeWalletAddress: string;
    appUrl: string;
    contractAddr: string;
    metadataUri: string;
    zkVerified: boolean;
    buildAttestation: {
        url: string;
        sha256: string;
        githubRunId: string;
    };
    instanceId?: bigint;
    versionId?: bigint;
    activeInstanceCount?: number;
    selectedInstanceWallet?: string;
}

interface RuntimeInstance {
    instanceId: bigint;
    appId: bigint;
    versionId: bigint;
    operator: string;
    instanceUrl: string;
    teePubkey: string;
    teeWalletAddress: string;
    zkVerified: boolean;
    status: number;
    registeredAt: bigint;
}

interface VersionInfo {
    versionId: bigint;
    codeMeasurement: string;
    status: number;
}

function strip0x(hex: string): string {
    return hex.startsWith('0x') ? hex.slice(2) : hex;
}

function toSafeNumber(value: bigint, field: string): number {
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error(`Value too large for number in ${field}: ${value.toString()}`);
    }
    return Number(value);
}

function readWord(data: string, byteOffset: number): string {
    const start = byteOffset * 2;
    const end = start + 64;
    if (end > data.length) {
        throw new Error(`Out-of-bounds ABI read at byte offset ${byteOffset}`);
    }
    return data.slice(start, end);
}

function readUint(data: string, byteOffset: number): bigint {
    return BigInt('0x' + readWord(data, byteOffset));
}

function readAddress(data: string, byteOffset: number): string {
    return ('0x' + readWord(data, byteOffset).slice(24)).toLowerCase();
}

function readBool(data: string, byteOffset: number): boolean {
    return readUint(data, byteOffset) !== BigInt(0);
}

function readHexBytes(data: string, byteOffset: number, byteLength: number): string {
    const start = byteOffset * 2;
    const end = start + byteLength * 2;
    if (end > data.length) {
        throw new Error(`Out-of-bounds ABI slice at byte offset ${byteOffset}`);
    }
    return data.slice(start, end);
}

function hexToUtf8(hex: string): string {
    if (!hex) return '';
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
    }
    return new TextDecoder().decode(bytes);
}

function readDynamicString(data: string, base: number, pointerSlotOffset: number): string {
    const rel = toSafeNumber(readUint(data, pointerSlotOffset), 'string pointer');
    const ptr = base + rel;
    const len = toSafeNumber(readUint(data, ptr), 'string length');
    return hexToUtf8(readHexBytes(data, ptr + WORD_BYTES, len));
}

function readDynamicBytes(data: string, base: number, pointerSlotOffset: number): string {
    const rel = toSafeNumber(readUint(data, pointerSlotOffset), 'bytes pointer');
    const ptr = base + rel;
    const len = toSafeNumber(readUint(data, ptr), 'bytes length');
    return '0x' + readHexBytes(data, ptr + WORD_BYTES, len).toLowerCase();
}

function encodeUint256(value: number | bigint): string {
    const n = BigInt(value);
    if (n < BigInt(0)) throw new Error('uint256 must be non-negative');
    return n.toString(16).padStart(64, '0');
}

function encodeAddress(address: string): string {
    const hex = strip0x(address).toLowerCase();
    if (!/^[0-9a-f]{40}$/.test(hex)) {
        throw new Error(`Invalid address: ${address}`);
    }
    return hex.padStart(64, '0');
}

async function ethCall(to: string, data: string, rpcUrl: string): Promise<string> {
    const response = await fetch(rpcUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            jsonrpc: '2.0',
            method: 'eth_call',
            params: [{ to, data }, 'latest'],
            id: 1,
        }),
    });

    if (!response.ok) {
        throw new Error(`RPC HTTP error: ${response.status} ${response.statusText}`);
    }

    const json = await response.json();
    if (json.error) {
        throw new Error(`RPC error: ${json.error.message || JSON.stringify(json.error)}`);
    }
    return typeof json.result === 'string' ? json.result : '0x';
}

function decodeAddressArrayResult(raw: string): string[] {
    const data = strip0x(raw);
    if (!data || data.length < 64) return [];

    const arrayOffset = toSafeNumber(readUint(data, 0), 'array offset');
    const arrayLen = toSafeNumber(readUint(data, arrayOffset), 'array length');
    const addresses: string[] = [];
    for (let i = 0; i < arrayLen; i += 1) {
        const offset = arrayOffset + WORD_BYTES * (i + 1);
        addresses.push(readAddress(data, offset));
    }
    return addresses;
}

function decodeRuntimeInstanceResult(raw: string): RuntimeInstance {
    const data = strip0x(raw);
    if (!data || data.length < 64) {
        throw new Error('Empty getInstanceByWallet response');
    }

    const base = toSafeNumber(readUint(data, 0), 'instance tuple offset');
    return {
        instanceId: readUint(data, base + 0),
        appId: readUint(data, base + 32),
        versionId: readUint(data, base + 64),
        operator: readAddress(data, base + 96),
        instanceUrl: readDynamicString(data, base, base + 128),
        teePubkey: readDynamicBytes(data, base, base + 160),
        teeWalletAddress: readAddress(data, base + 192),
        zkVerified: readBool(data, base + 224),
        status: toSafeNumber(readUint(data, base + 256), 'instance status'),
        registeredAt: readUint(data, base + 288),
    };
}

function decodeVersionResult(raw: string): VersionInfo {
    const data = strip0x(raw);
    if (!data || data.length < 64) {
        throw new Error('Empty getVersion response');
    }

    const base = toSafeNumber(readUint(data, 0), 'version tuple offset');
    return {
        versionId: readUint(data, base + 0),
        codeMeasurement: ('0x' + readWord(data, base + 64)).toLowerCase(),
        status: toSafeNumber(readUint(data, base + 224), 'version status'),
    };
}

export async function fetchAppFromRegistry(
    appId: number | string,
    registryAddress: string = DEFAULT_REGISTRY_ADDRESS,
    rpcUrl: string = DEFAULT_RPC_URL
): Promise<SparsityApp | null> {
    const appIdNum = typeof appId === 'string' ? parseInt(appId, 10) : appId;
    if (Number.isNaN(appIdNum) || appIdNum <= 0) {
        throw new Error('Invalid App ID: must be a positive number');
    }

    const normalizedRegistry = registryAddress.toLowerCase();
    const appIdHex = encodeUint256(appIdNum);

    const activeRaw = await ethCall(
        normalizedRegistry,
        `${SELECTOR_GET_ACTIVE_INSTANCES}${appIdHex}`,
        rpcUrl
    );
    const activeWallets = decodeAddressArrayResult(activeRaw);
    if (activeWallets.length === 0) {
        throw new Error(`No active instances found for app ${appIdNum}`);
    }

    const selectedWallet =
        activeWallets[Math.floor(Math.random() * activeWallets.length)];

    const instanceRaw = await ethCall(
        normalizedRegistry,
        `${SELECTOR_GET_INSTANCE_BY_WALLET}${encodeAddress(selectedWallet)}`,
        rpcUrl
    );
    const instance = decodeRuntimeInstanceResult(instanceRaw);

    if (instance.instanceId === BigInt(0) || instance.appId !== BigInt(appIdNum)) {
        throw new Error(`Selected wallet is not a valid active instance for app ${appIdNum}`);
    }

    const versionRaw = await ethCall(
        normalizedRegistry,
        `${SELECTOR_GET_VERSION}${encodeUint256(instance.appId)}${encodeUint256(instance.versionId)}`,
        rpcUrl
    );
    const version = decodeVersionResult(versionRaw);

    return {
        owner: instance.operator,
        appId: instance.appId,
        teeArch: 'nitro',
        codeMeasurement: version.codeMeasurement,
        teePubkey: instance.teePubkey,
        teeWalletAddress: instance.teeWalletAddress,
        appUrl: instance.instanceUrl,
        contractAddr: ZERO_ADDRESS,
        metadataUri: '',
        zkVerified: instance.zkVerified,
        buildAttestation: {
            url: '',
            sha256: '',
            githubRunId: '',
        },
        instanceId: instance.instanceId,
        versionId: instance.versionId,
        activeInstanceCount: activeWallets.length,
        selectedInstanceWallet: selectedWallet,
    };
}

/**
 * Format public key for display (truncated)
 */
export function formatPubkeyPreview(pubkey: string): string {
    if (!pubkey || pubkey === '0x') return 'N/A';
    if (pubkey.length <= 20) return pubkey;
    return pubkey.slice(0, 10) + '...' + pubkey.slice(-8);
}

/**
 * Format code measurement for display
 */
export function formatCodeMeasurement(measurement: string): string {
    if (!measurement || measurement === '0x' || measurement === '0x0000000000000000000000000000000000000000000000000000000000000000') {
        return 'N/A';
    }
    return measurement.slice(0, 10) + '...' + measurement.slice(-8);
}
