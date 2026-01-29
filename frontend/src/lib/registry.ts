/**
 * Nova App Registry Client
 * 
 * Queries the SparsityAppRegistry contract to fetch registered app information
 * including appUrl, teePubkey, and codeMeasurement for verified TLS connections.
 */

// Default registry contract address on Base Sepolia
export const DEFAULT_REGISTRY_ADDRESS = '0x58e41D71606410E43BDA23C348B68F5A93245461';

// Default RPC URL for Base Sepolia
export const DEFAULT_RPC_URL = 'https://sepolia.base.org';

/**
 * SparsityApp struct from the registry contract
 */
export interface SparsityApp {
    owner: string;
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
}

// Minimal ABI for getApp function
const REGISTRY_ABI = [
    {
        "inputs": [{ "name": "appId", "type": "uint256" }],
        "name": "getApp",
        "outputs": [
            {
                "components": [
                    { "name": "owner", "type": "address" },
                    { "name": "appId", "type": "uint256" },
                    { "name": "teeArch", "type": "bytes32" },
                    { "name": "codeMeasurement", "type": "bytes32" },
                    { "name": "teePubkey", "type": "bytes" },
                    { "name": "teeWalletAddress", "type": "address" },
                    { "name": "appUrl", "type": "string" },
                    { "name": "contractAddr", "type": "address" },
                    { "name": "metadataUri", "type": "string" },
                    { "name": "zkVerified", "type": "bool" },
                    {
                        "name": "buildAttestation",
                        "type": "tuple",
                        "components": [
                            { "name": "url", "type": "string" },
                            { "name": "sha256", "type": "string" },
                            { "name": "githubRunId", "type": "string" }
                        ]
                    }
                ],
                "name": "",
                "type": "tuple"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [{ "name": "appId", "type": "uint256" }],
        "name": "appExists",
        "outputs": [{ "name": "", "type": "bool" }],
        "stateMutability": "view",
        "type": "function"
    }
] as const;

/**
 * Convert bytes32 to hex string
 */
function bytes32ToHex(bytes32: string): string {
    // If already prefixed with 0x, return as-is
    if (bytes32.startsWith('0x')) {
        return bytes32.toLowerCase();
    }
    return '0x' + bytes32.toLowerCase();
}

/**
 * Convert bytes to hex string
 */
function bytesToHex(bytes: string | Uint8Array): string {
    if (typeof bytes === 'string') {
        if (bytes.startsWith('0x')) {
            return bytes.toLowerCase();
        }
        return '0x' + bytes.toLowerCase();
    }
    return '0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Fetch app information from the Nova App Registry
 * 
 * @param appId - The numeric App ID to query
 * @param registryAddress - The registry contract address (defaults to Base Sepolia registry)
 * @param rpcUrl - The RPC URL to use for the query (defaults to Base Sepolia)
 * @returns SparsityApp information or null if not found
 */
export async function fetchAppFromRegistry(
    appId: number | string,
    registryAddress: string = DEFAULT_REGISTRY_ADDRESS,
    rpcUrl: string = DEFAULT_RPC_URL
): Promise<SparsityApp | null> {
    const appIdNum = typeof appId === 'string' ? parseInt(appId, 10) : appId;

    if (isNaN(appIdNum) || appIdNum <= 0) {
        throw new Error('Invalid App ID: must be a positive number');
    }

    // Encode the getApp function call
    // Function selector: keccak256("getApp(uint256)")[0:4]
    const functionSelector = '0x24f3a51b'; // getApp(uint256)
    const encodedAppId = appIdNum.toString(16).padStart(64, '0');
    const callData = functionSelector + encodedAppId;

    // Make the eth_call
    const response = await fetch(rpcUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            jsonrpc: '2.0',
            method: 'eth_call',
            params: [
                {
                    to: registryAddress,
                    data: callData
                },
                'latest'
            ],
            id: 1
        })
    });

    const result = await response.json();

    if (result.error) {
        throw new Error(`RPC error: ${result.error.message || JSON.stringify(result.error)}`);
    }

    const data = result.result;

    // Check if result is empty (all zeros indicates app not found)
    if (!data || data === '0x' || data.length < 66) {
        return null;
    }

    // Decode the response manually
    // The response is ABI-encoded tuple data
    try {
        const decoded = decodeGetAppResponse(data);

        // Check if owner is zero address (app doesn't exist)
        if (decoded.owner === '0x0000000000000000000000000000000000000000') {
            return null;
        }

        return decoded;
    } catch (error) {
        console.error('Failed to decode registry response:', error);
        throw new Error('Failed to decode app data from registry');
    }
}

/**
 * Decode the getApp response from raw hex data
 */
function decodeGetAppResponse(hexData: string): SparsityApp {
    // Remove 0x prefix
    const data = hexData.startsWith('0x') ? hexData.slice(2) : hexData;

    // Helper to read 32 bytes (64 hex chars) at a given offset
    const readBytes32 = (offset: number): string => {
        return '0x' + data.slice(offset * 2, offset * 2 + 64);
    };

    // Helper to read address (20 bytes, right-aligned in 32 bytes)
    const readAddress = (offset: number): string => {
        return '0x' + data.slice(offset * 2 + 24, offset * 2 + 64);
    };

    // Helper to read uint256
    const readUint256 = (offset: number): bigint => {
        return BigInt(readBytes32(offset));
    };

    // Helper to read bool
    const readBool = (offset: number): boolean => {
        return readUint256(offset) !== BigInt(0);
    };

    // Helper to read dynamic bytes at offset
    const readDynamicBytes = (dataOffset: number): string => {
        const pointerOffset = Number(readUint256(dataOffset));
        const length = Number(readUint256(pointerOffset));
        if (length === 0) return '0x';
        const bytesData = data.slice((pointerOffset + 32) * 2, (pointerOffset + 32 + length) * 2);
        return '0x' + bytesData;
    };

    // Helper to read dynamic string at offset
    const readDynamicString = (dataOffset: number): string => {
        const pointerOffset = Number(readUint256(dataOffset));
        const length = Number(readUint256(pointerOffset));
        if (length === 0) return '';
        const stringHex = data.slice((pointerOffset + 32) * 2, (pointerOffset + 32 + length) * 2);
        // Convert hex to string
        let result = '';
        for (let i = 0; i < stringHex.length; i += 2) {
            result += String.fromCharCode(parseInt(stringHex.slice(i, i + 2), 16));
        }
        return result;
    };

    // The struct layout with tuple offset at position 0
    // First, we need to handle the outer tuple offset
    const tupleOffset = Number(readUint256(0));

    // Now read from the tuple start
    const base = tupleOffset;

    // Fixed fields (each 32 bytes)
    const owner = readAddress(base);                      // offset 0
    const appId = readUint256(base + 32);                 // offset 32
    const teeArch = readBytes32(base + 64);               // offset 64
    const codeMeasurement = readBytes32(base + 96);       // offset 96
    // teePubkey is dynamic - offset 128 contains pointer
    const teePubkeyPointer = base + Number(readUint256(base + 128));
    const teeWalletAddress = readAddress(base + 160);     // offset 160
    // appUrl is dynamic - offset 192 contains pointer
    const appUrlPointer = base + Number(readUint256(base + 192));
    const contractAddr = readAddress(base + 224);         // offset 224
    // metadataUri is dynamic - offset 256 contains pointer
    const metadataUriPointer = base + Number(readUint256(base + 256));
    const zkVerified = readBool(base + 288);              // offset 288
    // buildAttestation tuple - offset 320 contains pointer
    const buildAttestationPointer = base + Number(readUint256(base + 320));

    // Read dynamic fields
    const teePubkeyLength = Number(readUint256(teePubkeyPointer));
    const teePubkey = teePubkeyLength > 0
        ? '0x' + data.slice((teePubkeyPointer + 32) * 2, (teePubkeyPointer + 32 + teePubkeyLength) * 2)
        : '0x';

    const appUrlLength = Number(readUint256(appUrlPointer));
    let appUrl = '';
    if (appUrlLength > 0) {
        const appUrlHex = data.slice((appUrlPointer + 32) * 2, (appUrlPointer + 32 + appUrlLength) * 2);
        for (let i = 0; i < appUrlHex.length; i += 2) {
            appUrl += String.fromCharCode(parseInt(appUrlHex.slice(i, i + 2), 16));
        }
    }

    const metadataUriLength = Number(readUint256(metadataUriPointer));
    let metadataUri = '';
    if (metadataUriLength > 0) {
        const metadataUriHex = data.slice((metadataUriPointer + 32) * 2, (metadataUriPointer + 32 + metadataUriLength) * 2);
        for (let i = 0; i < metadataUriHex.length; i += 2) {
            metadataUri += String.fromCharCode(parseInt(metadataUriHex.slice(i, i + 2), 16));
        }
    }

    // Read buildAttestation tuple
    // BuildAttestation has 3 string fields with relative pointers
    const buildUrlPointer = buildAttestationPointer + Number(readUint256(buildAttestationPointer));
    const buildSha256Pointer = buildAttestationPointer + Number(readUint256(buildAttestationPointer + 32));
    const buildGithubRunIdPointer = buildAttestationPointer + Number(readUint256(buildAttestationPointer + 64));

    const readStringAt = (pointer: number): string => {
        const len = Number(readUint256(pointer));
        if (len === 0) return '';
        const hex = data.slice((pointer + 32) * 2, (pointer + 32 + len) * 2);
        let result = '';
        for (let i = 0; i < hex.length; i += 2) {
            result += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
        }
        return result;
    };

    return {
        owner,
        appId,
        teeArch: bytes32ToString(teeArch),
        codeMeasurement,
        teePubkey,
        teeWalletAddress,
        appUrl,
        contractAddr,
        metadataUri,
        zkVerified,
        buildAttestation: {
            url: readStringAt(buildUrlPointer),
            sha256: readStringAt(buildSha256Pointer),
            githubRunId: readStringAt(buildGithubRunIdPointer)
        }
    };
}

/**
 * Convert bytes32 to readable string (for teeArch like "nitro")
 */
function bytes32ToString(bytes32: string): string {
    const hex = bytes32.startsWith('0x') ? bytes32.slice(2) : bytes32;
    let result = '';
    for (let i = 0; i < hex.length; i += 2) {
        const charCode = parseInt(hex.slice(i, i + 2), 16);
        if (charCode === 0) break;
        result += String.fromCharCode(charCode);
    }
    return result;
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
