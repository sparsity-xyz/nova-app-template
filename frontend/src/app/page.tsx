'use client';

import { useEffect, useState } from 'react';
import { createPortal } from 'react-dom';

import { EnclaveClient, type EncryptedCallTrace, type FetchedAttestation } from '@/lib/crypto';
import { fetchAppFromRegistry, DEFAULT_REGISTRY_ADDRESS, DEFAULT_RPC_URL, type SparsityApp, formatPubkeyPreview } from '@/lib/registry';

interface ConnectionStatus {
    connected: boolean;
    enclaveUrl: string;
    teeAddress?: string;
    error?: string;
}

interface ApiResponse {
    success: boolean;
    data?: any;
    error?: string;
    type?: string;
}

/** Reusable info box showing which Enclaver sidecar APIs a feature demonstrates. */
function ApiInfoBox({ title, apis, description, docLink }: {
    title: string;
    apis: string[];
    description: string;
    docLink?: { url: string; label: string };
}) {
    return (
        <div className="bg-sky-50 border border-sky-100 rounded-xl p-4 mb-6">
            <div className="flex items-start gap-3">
                <span className="text-sky-600 text-lg">ℹ️</span>
                <div className="flex-1 min-w-0">
                    <h3 className="text-xs font-bold text-sky-800 uppercase tracking-widest mb-1">{title}</h3>
                    <p className="text-xs text-slate-600 leading-relaxed mb-2">{description}</p>
                    <div className="flex flex-wrap gap-2">
                        {apis.map(api => (
                            <code key={api} className="text-[11px] bg-white text-sky-700 px-2 py-0.5 rounded border border-sky-200 font-mono">
                                {api}
                            </code>
                        ))}
                    </div>
                    {docLink && (
                        <a href={docLink.url} target="_blank" rel="noopener noreferrer"
                            className="inline-block mt-2 text-xs text-blue-600 hover:text-blue-800 hover:underline">
                            📖 {docLink.label} →
                        </a>
                    )}
                </div>
            </div>
        </div>
    );
}

export default function Home() {
    const [client] = useState(() => new EnclaveClient());
    const [status, setStatus] = useState<ConnectionStatus>({
        connected: false,
        enclaveUrl: 'http://127.0.0.1:8000',
    });
    const [loading, setLoading] = useState(false);
    const [activeTab, setActiveTab] = useState('identity');
    const [responsesByTab, setResponsesByTab] = useState<Record<string, ApiResponse | null>>({});
    const [lastResponseKey, setLastResponseKey] = useState<string | null>(null);
    const activeResponse = lastResponseKey
        ? (responsesByTab[lastResponseKey] || null)
        : (responsesByTab[activeTab] || null);

    const [showAttestation, setShowAttestation] = useState(false);
    const [attestationLoading, setAttestationLoading] = useState(false);
    const [attestationError, setAttestationError] = useState<string | null>(null);
    const [attestationData, setAttestationData] = useState<FetchedAttestation | null>(null);
    const [attestationView, setAttestationView] = useState<'decoded' | 'raw'>('decoded');
    const [isClient, setIsClient] = useState(false);

    // Form inputs
    const [echoMsg, setEchoMsg] = useState('Hello from Nova!');
    const [storageKey, setStorageKey] = useState('user_settings');
    const [storageVal, setStorageVal] = useState('{"theme": "dark"}');
    const [storageConfig, setStorageConfig] = useState<{ s3_encryption_mode: string; kms_required: boolean } | null>(null);
    const [storageConfigLoading, setStorageConfigLoading] = useState(false);
    const [storageConfigError, setStorageConfigError] = useState<string | null>(null);
    const [kmsDerivePath, setKmsDerivePath] = useState('app/session/demo');
    const [kmsDeriveContext, setKmsDeriveContext] = useState('demo');
    const [kmsDeriveLength, setKmsDeriveLength] = useState(32);
    const [kmsKvKey, setKmsKvKey] = useState('config/demo');
    const [kmsKvValue, setKmsKvValue] = useState('hello-from-kms');
    const [kmsKvTtl, setKmsKvTtl] = useState('0');
    const [appWalletMessage, setAppWalletMessage] = useState('Nova app wallet signature demo');

    const [echoTrace, setEchoTrace] = useState<EncryptedCallTrace | null>(null);

    // Connection mode state
    const [connectionMode, setConnectionMode] = useState<'registry' | 'direct'>('registry');
    const [lastConnectedMode, setLastConnectedMode] = useState<'registry' | 'direct' | null>(null);
    const [appId, setAppId] = useState('');
    const [registryAddress, setRegistryAddress] = useState(DEFAULT_REGISTRY_ADDRESS);
    const [registryRpcUrl, setRegistryRpcUrl] = useState(DEFAULT_RPC_URL);
    const [showAdvancedSettings, setShowAdvancedSettings] = useState(false);
    const [registryAppInfo, setRegistryAppInfo] = useState<SparsityApp | null>(null);
    const [registryLoading, setRegistryLoading] = useState(false);
    const [registryError, setRegistryError] = useState<string | null>(null);

    // Auto-detect enclave URL from current location
    useEffect(() => {
        if (typeof window !== 'undefined') {
            const currentHost = window.location.origin;
            if (currentHost.includes('sparsity.cloud') || currentHost.includes('localhost:8000')) {
                setStatus(prev => ({ ...prev, enclaveUrl: currentHost }));
            }
        }
    }, []);

    useEffect(() => {
        setIsClient(true);
    }, []);

    useEffect(() => {
        if (!showAttestation) return;

        const previousOverflow = document.body.style.overflow;
        const handleKeyDown = (event: KeyboardEvent) => {
            if (event.key === 'Escape') {
                setShowAttestation(false);
            }
        };

        document.body.style.overflow = 'hidden';
        window.addEventListener('keydown', handleKeyDown);

        return () => {
            window.removeEventListener('keydown', handleKeyDown);
            document.body.style.overflow = previousOverflow;
        };
    }, [showAttestation]);

    useEffect(() => {
        if (!status.connected || activeTab !== 'storage') return;

        let cancelled = false;
        const fetchStorageConfig = async () => {
            setStorageConfigLoading(true);
            setStorageConfigError(null);
            try {
                const res = await client.call('/api/storage/config', 'GET');
                if (!cancelled) {
                    setStorageConfig({
                        s3_encryption_mode: String(res?.s3_encryption_mode ?? 'unknown'),
                        kms_required: Boolean(res?.kms_required),
                    });
                }
            } catch (error) {
                if (!cancelled) {
                    setStorageConfigError(error instanceof Error ? error.message : 'Failed to fetch storage config');
                }
            } finally {
                if (!cancelled) {
                    setStorageConfigLoading(false);
                }
            }
        };

        fetchStorageConfig();
        return () => {
            cancelled = true;
        };
    }, [activeTab, client, status.connected]);

    const handleConnect = async () => {
        let targetUrl = status.enclaveUrl;
        let trustedPubkey: string | undefined;
        let trustedCodeMeasurement: string | undefined;
        let appInfo = registryAppInfo;

        if (connectionMode === 'registry') {
            if (!appId) {
                setRegistryError('App ID is required in registry mode');
                return;
            }
            setRegistryLoading(true);
            setRegistryError(null);
            try {
                const app = await fetchAppFromRegistry(appId, registryAddress, registryRpcUrl);
                if (!app) {
                    setRegistryError(`App ID ${appId} not found in registry`);
                    setRegistryLoading(false);
                    return;
                }
                setRegistryAppInfo(app);
                appInfo = app;
            } catch (error) {
                setRegistryError(error instanceof Error ? error.message : 'Failed to fetch from registry');
                setRegistryLoading(false);
                return;
            }
            setRegistryLoading(false);
            if (appInfo) {
                targetUrl = appInfo.appUrl;
                trustedPubkey = appInfo.teePubkey;
                trustedCodeMeasurement = appInfo.codeMeasurement;
            }
        }

        if (!targetUrl) return;
        setLoading(true);
        try {
            const { attestation } = await client.connectWithTrace(
                targetUrl,
                trustedPubkey,
                trustedCodeMeasurement
            );
            const statusInfo = await client.call('/status');
            setStatus({
                ...status,
                enclaveUrl: targetUrl,
                connected: true,
                teeAddress: statusInfo.ETH_address,
                error: undefined,
            });
            setLastConnectedMode(connectionMode);
            setResponsesByTab(prev => ({
                ...prev,
                identity: {
                    success: true,
                    data: {
                        attestation,
                        statusInfo,
                        registryVerified: connectionMode === 'registry' && !!appInfo
                    },
                    type: 'Connection'
                },
            }));
        } catch (error) {
            setStatus({
                ...status,
                connected: false,
                error: error instanceof Error ? error.message : 'Connection failed',
            });
            setLastConnectedMode(null);
        } finally {
            setLoading(false);
        }
    };

    const handleTabChange = (tabId: string) => {
        setActiveTab(tabId);
        setLastResponseKey(null);
    };

    const callApi = async (path: string, method: 'GET' | 'POST' = 'GET', body?: any, encrypted = false, tabOverride?: string) => {
        const tabAtCall = tabOverride || activeTab;
        setLoading(true);
        setLastResponseKey(tabAtCall);
        setResponsesByTab(prev => ({ ...prev, [tabAtCall]: null }));
        try {
            let res;
            if (encrypted) {
                res = await client.callEncrypted(path, body);
            } else {
                res = await client.call(path, method, body);
            }
            setResponsesByTab(prev => ({
                ...prev,
                [tabAtCall]: { success: true, data: res, type: path },
            }));
        } catch (error: any) {
            const errorDetail = error?.detail ?? null;
            const errorMessage = error instanceof Error ? error.message : 'Request failed';
            setResponsesByTab(prev => ({
                ...prev,
                [tabAtCall]: {
                    success: false,
                    error: errorMessage,
                    data: errorDetail,
                    type: path,
                },
            }));
        } finally {
            setLoading(false);
        }
    };

    const callEchoEncrypted = async () => {
        setLoading(true);
        setResponsesByTab(prev => ({ ...prev, 'secure-echo': null }));
        setEchoTrace(null);
        try {
            const { data, trace } = await client.callEncryptedTrace('/api/echo', { message: echoMsg });
            setEchoTrace(trace);
            if (data !== undefined) {
                setResponsesByTab(prev => ({
                    ...prev,
                    'secure-echo': { success: true, data, type: '/api/echo (encrypted)' },
                }));
            } else {
                setResponsesByTab(prev => ({
                    ...prev,
                    'secure-echo': { success: false, error: trace.error || 'Request failed', type: '/api/echo (encrypted)' },
                }));
            }
        } catch (error) {
            setResponsesByTab(prev => ({
                ...prev,
                'secure-echo': { success: false, error: error instanceof Error ? error.message : 'Request failed', type: '/api/echo (encrypted)' },
            }));
        } finally {
            setLoading(false);
        }
    };

    const refreshStorageConfig = async () => {
        if (!status.connected) return;
        setStorageConfigLoading(true);
        setStorageConfigError(null);
        try {
            const res = await client.call('/api/storage/config', 'GET');
            setStorageConfig({
                s3_encryption_mode: String(res?.s3_encryption_mode ?? 'unknown'),
                kms_required: Boolean(res?.kms_required),
            });
        } catch (error) {
            setStorageConfigError(error instanceof Error ? error.message : 'Failed to fetch storage config');
        } finally {
            setStorageConfigLoading(false);
        }
    };

    const handleViewAttestation = async () => {
        if (!status.connected) return;
        setAttestationLoading(true);
        setAttestationError(null);
        setAttestationData(null);
        setAttestationView('decoded');
        try {
            const attestation = await client.fetchAttestation();
            setAttestationData(attestation);
        } catch (error) {
            setAttestationError(error instanceof Error ? error.message : 'Failed to fetch attestation');
        } finally {
            setAttestationLoading(false);
        }
    };

    const copyToClipboard = async (text: string) => {
        try {
            await navigator.clipboard.writeText(text);
        } catch {
            const textarea = document.createElement('textarea');
            textarea.value = text;
            textarea.style.position = 'fixed';
            textarea.style.left = '-9999px';
            document.body.appendChild(textarea);
            textarea.focus();
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);
        }
    };

    const TABS = [
        { id: 'identity', label: 'Identify & Attestation', icon: '🔑' },
        { id: 'hardware-entropy', label: 'Hardware Entropy', icon: '🎲' },
        { id: 'secure-echo', label: 'Secure Echo', icon: '🔒' },
        { id: 'storage', label: 'S3 Storage', icon: '📦' },
        { id: 'kms-demo', label: 'KMS Demo', icon: '🗄️' },
        { id: 'app-wallet', label: 'App Wallet Sign', icon: '🗝️' },
        { id: 'oracle', label: 'Oracle Demo', icon: '🌐' },
    ];

    const attestationUrl = `${(status.enclaveUrl || '').replace(/\/$/, '')}/.well-known/attestation`;
    const attestationDoc = attestationData?.attestation_document;
    const attestationPcrEntries = attestationDoc?.pcrs ? Object.entries(attestationDoc.pcrs) : [];
    const directModePubkey =
        client.serverEncryptionPublicKey
            ? `${client.serverEncryptionPublicKey.slice(0, 18)}...${client.serverEncryptionPublicKey.slice(-18)}`
            : 'Not available (connect first)';
    const effectiveConnectionMode = status.connected && lastConnectedMode ? lastConnectedMode : connectionMode;
    const registryInstanceId = registryAppInfo?.instanceId ? registryAppInfo.instanceId.toString() : 'N/A';
    const registryToastPubkey = registryAppInfo ? formatPubkeyPreview(registryAppInfo.teePubkey) : 'N/A';
return (
    <div className="min-h-screen bg-gradient-to-br from-white via-slate-50 to-sky-50 text-slate-900 p-8 font-sans">
        <header className="max-w-7xl mx-auto mb-12">
            <div className="rounded-3xl border border-slate-200 bg-white/95 backdrop-blur px-8 py-6 shadow-xl shadow-slate-200/50">
                <div className="app-template-header-grid">
                    <div>
                        <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Nova Platform</p>
                        <h1 className="text-3xl font-semibold text-slate-900 mt-2">
                            🛡️ Nova App Template
                        </h1>
                        <p className="text-slate-500 mt-2">
                            Best-practice demos for Nova App development and Enclaver sidecar APIs.
                        </p>
                        <div className="flex flex-wrap gap-2 mt-4 text-xs text-slate-500">
                            <span className="px-3 py-1 rounded-full bg-sky-50 border border-sky-100 text-sky-700">TLS</span>
                            <span className="px-3 py-1 rounded-full bg-sky-50 border border-sky-100 text-sky-700">S3 Storage</span>
                            <span className="px-3 py-1 rounded-full bg-sky-50 border border-sky-100 text-sky-700">KMS</span>
                            <span className="px-3 py-1 rounded-full bg-sky-50 border border-sky-100 text-sky-700">App Wallet</span>
                            <span className="px-3 py-1 rounded-full bg-sky-50 border border-sky-100 text-sky-700">Hardware Entropy</span>
                            <span className="px-3 py-1 rounded-full bg-sky-50 border border-sky-100 text-sky-700">Oracle / Base Sepolia</span>
                        </div>
                    </div>

                    <div className="space-y-3 app-template-connection-panel">
                        <div className="flex gap-1 p-1 bg-slate-100 rounded-xl mb-3">
                            <button
                                onClick={() => setConnectionMode('registry')}
                                className={`flex-1 px-3 py-1.5 rounded-lg text-xs font-semibold transition ${connectionMode === 'registry'
                                    ? 'bg-white text-slate-900 shadow-sm'
                                    : 'text-slate-600 hover:text-slate-900'
                                    }`}
                            >
                                Via Registry
                            </button>
                            <button
                                onClick={() => setConnectionMode('direct')}
                                className={`flex-1 px-3 py-1.5 rounded-lg text-xs font-semibold transition ${connectionMode === 'direct'
                                    ? 'bg-white text-slate-900 shadow-sm'
                                    : 'text-slate-600 hover:text-slate-900'
                                    }`}
                            >
                                Direct URL
                            </button>
                        </div>

                        {connectionMode === 'registry' ? (
                            <div className="space-y-3">
                                <div className="flex items-center gap-3 rounded-2xl border border-slate-200 bg-white px-4 py-3 shadow-sm">
                                    <span className="text-[10px] uppercase tracking-widest text-slate-400">App ID</span>
                                    <input
                                        className="flex-1 bg-transparent text-sm text-slate-700 outline-none placeholder:text-slate-400"
                                        value={appId}
                                        onChange={(e) => {
                                            const val = e.target.value.replace(/[^0-9]/g, '');
                                            setAppId(val);
                                            setRegistryAppInfo(null);
                                            setRegistryError(null);
                                        }}
                                        placeholder="Enter App ID (e.g., 1)"
                                    />
                                    <button
                                        onClick={handleConnect}
                                        disabled={loading || registryLoading || status.connected || !appId}
                                        className={`px-6 py-2.5 rounded-xl text-sm font-semibold transition-all whitespace-nowrap ${status.connected
                                            ? 'bg-emerald-100 text-emerald-700 border border-emerald-300 shadow-sm'
                                            : 'bg-gradient-to-r from-blue-600 to-blue-500 hover:from-blue-500 hover:to-blue-400 text-white shadow-sm disabled:opacity-50'
                                            }`}
                                    >
                                        {registryLoading ? 'Fetching...' : loading ? 'Connecting...' : status.connected ? 'Connected' : 'Connect'}
                                    </button>
                                </div>

                                <button
                                    onClick={() => setShowAdvancedSettings(!showAdvancedSettings)}
                                    className="text-xs text-slate-500 hover:text-slate-700 flex items-center gap-1"
                                >
                                    <span>{showAdvancedSettings ? '▼' : '▶'}</span>
                                    Advanced Settings
                                </button>

                                {showAdvancedSettings && (
                                    <div className="grid grid-cols-2 gap-3 p-3 bg-slate-50 rounded-xl border border-slate-200">
                                        <div>
                                            <label className="text-[10px] uppercase tracking-widest text-slate-400">Registry Address</label>
                                            <input
                                                className="mt-1 w-full bg-white text-xs text-slate-700 outline-none px-2 py-1.5 rounded border border-slate-200"
                                                value={registryAddress}
                                                onChange={(e) => setRegistryAddress(e.target.value)}
                                                placeholder={DEFAULT_REGISTRY_ADDRESS}
                                            />
                                        </div>
                                        <div>
                                            <label className="text-[10px] uppercase tracking-widest text-slate-400">RPC URL</label>
                                            <input
                                                className="mt-1 w-full bg-white text-xs text-slate-700 outline-none px-2 py-1.5 rounded border border-slate-200"
                                                value={registryRpcUrl}
                                                onChange={(e) => setRegistryRpcUrl(e.target.value)}
                                                placeholder={DEFAULT_RPC_URL}
                                            />
                                        </div>
                                    </div>
                                )}
                            </div>
                        ) : (
                            <div className="space-y-3">
                                <div className="flex items-center gap-3 rounded-2xl border border-slate-200 bg-white px-4 py-3 shadow-sm">
                                    <span className="text-[10px] uppercase tracking-widest text-slate-400">Enclave URL</span>
                                    <input
                                        className="flex-1 bg-transparent text-sm text-slate-700 outline-none placeholder:text-slate-400"
                                        value={status.enclaveUrl}
                                        onChange={(e) => setStatus({ ...status, enclaveUrl: e.target.value })}
                                        placeholder="https://your-app.sparsity.cloud"
                                    />
                                    <button
                                        onClick={handleConnect}
                                        disabled={loading || status.connected || !status.enclaveUrl}
                                        className={`px-6 py-2.5 rounded-xl text-sm font-semibold transition-all whitespace-nowrap ${status.connected
                                            ? 'bg-emerald-100 text-emerald-700 border border-emerald-300 shadow-sm'
                                            : 'bg-gradient-to-r from-blue-600 to-blue-500 hover:from-blue-500 hover:to-blue-400 text-white shadow-sm disabled:opacity-50'
                                            }`}
                                    >
                                        {loading ? 'Connecting...' : status.connected ? 'Connected' : 'Connect'}
                                    </button>
                                </div>
                            </div>
                        )}

                        {registryError && (
                            <div className="text-xs text-red-600 bg-red-50 px-3 py-2 rounded-lg border border-red-200">
                                {registryError}
                            </div>
                        )}
                        {status.error && (
                            <div className="text-xs text-red-600 bg-red-50 px-3 py-2 rounded-lg border border-red-200">
                                {status.error}
                            </div>
                        )}
                    </div>
                </div>

                {status.connected && (
                    <div className="mt-4 connection-popup-panel">
                        <div className="connection-popup-row text-xs">
                            {effectiveConnectionMode === 'registry' && registryAppInfo ? (
                                <>
                                    <span className="connection-popup-success">✓ Connection Success</span>
                                    <span className="connection-popup-item"><span className="text-slate-500">Instance ID:</span> {registryInstanceId}</span>
                                    <span className="connection-popup-item"><span className="text-slate-500">Instance URL:</span> {registryAppInfo.appUrl}</span>
                                    <span className="connection-popup-item"><span className="text-slate-500">Wallet Address:</span> {registryAppInfo.teeWalletAddress}</span>
                                    <span className="connection-popup-item"><span className="text-slate-500">TEE Pubkey:</span> {registryToastPubkey}</span>
                                </>
                            ) : (
                                <>
                                    <span className="connection-popup-success">✓ Connection Success</span>
                                    <span className="connection-popup-item"><span className="text-slate-500">Wallet Address:</span> {status.teeAddress || 'N/A'}</span>
                                    <span className="connection-popup-item"><span className="text-slate-500">TEE Pubkey:</span> {directModePubkey}</span>
                                </>
                            )}
                        </div>
                    </div>
                )}
            </div>
        </header>
<main className="max-w-7xl mx-auto grid grid-cols-1 lg:grid-cols-3 gap-8">
    {/* Left: Navigation */}
    <div className="lg:col-span-1 space-y-6">
        <section className="bg-white rounded-2xl border border-slate-200 p-6 shadow-lg shadow-slate-200/60">
            <h2 className="text-xs font-semibold text-slate-500 uppercase tracking-[0.2em] mb-4">Capabilities</h2>
            <nav className="flex flex-col gap-2">
                {TABS.map(tab => (
                    <button
                        key={tab.id}
                        onClick={() => handleTabChange(tab.id)}
                        className={`group flex items-center gap-3 px-4 py-3 rounded-xl transition text-left border ${activeTab === tab.id
                            ? 'bg-blue-50 text-slate-900 border-blue-200 shadow-sm shadow-blue-100/60'
                            : 'text-slate-600 border-transparent hover:border-slate-200 hover:bg-slate-50'
                            }`}
                    >
                        <span className={`text-base ${activeTab === tab.id ? 'text-blue-600' : 'text-slate-400 group-hover:text-slate-600'}`}>{tab.icon}</span>
                        <span className={`text-sm font-medium ${activeTab === tab.id ? 'text-slate-900' : 'text-slate-600 group-hover:text-slate-900'}`}>{tab.label}</span>
                    </button>
                ))}
            </nav>
        </section>

    </div>

    {/* Right: Content Area */}
    <div className="lg:col-span-2 space-y-6">
        <div className="bg-white rounded-2xl border border-slate-200 p-8 min-h-[400px] shadow-lg shadow-slate-200/60">

            {/* ============ TAB 1: Identity & Attestation ============ */}
            {activeTab === 'identity' && (
                <div className="space-y-6">
                    <h2 className="text-xl font-semibold mb-4">Identify & Attestation</h2>
                    <ApiInfoBox
                        title="Best Practice: Identity & Attestation"
                        apis={['GET /v1/eth/address', 'POST /v1/attestation', 'GET /v1/encryption/public_key']}
                        description="Use app-registry metadata and Nitro attestation together: first identify which enclave you connect to, then validate parsed attestation content as the trust anchor."
                    />

                    <div className="rounded-2xl border border-slate-200 bg-slate-50 p-5">
                        <div className="flex items-center justify-between mb-3">
                            <h3 className="text-sm font-semibold text-slate-800">Parsed Attestation (AWS Nitro)</h3>
                            <div className="flex items-center gap-3">
                                {attestationData && (
                                    <button
                                        onClick={() => setShowAttestation(true)}
                                        className="text-sm text-slate-500 hover:text-slate-700 font-medium"
                                    >
                                        Open Decoded/Raw View
                                    </button>
                                )}
                                <button
                                    onClick={handleViewAttestation}
                                    disabled={loading || !status.connected}
                                    className="text-sm text-blue-600 hover:text-blue-700 font-medium disabled:opacity-50"
                                >
                                    Fetch & Parse Attestation →
                                </button>
                            </div>
                        </div>
                        {status.connected && (
                            <div className="bg-white border border-slate-200 rounded-xl p-3 mb-3">
                                <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">Attestation URL (POST only)</p>
                                <code className="text-xs text-slate-700 break-all">{attestationUrl}</code>
                            </div>
                        )}
                        {!status.connected && (
                            <p className="text-sm text-slate-500 italic">Connect to an enclave to fetch attestation.</p>
                        )}

                        {attestationLoading && (
                            <div className="text-xs text-slate-500">Loading attestation...</div>
                        )}

                        {attestationError && (
                            <div className="bg-red-50 border border-red-200 rounded-xl p-3 text-xs text-red-700">
                                {attestationError}
                            </div>
                        )}

                        {attestationDoc && !attestationLoading && (
                            <div className="space-y-3">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                                    <div className="bg-white border border-slate-200 rounded-xl p-3">
                                        <p className="text-slate-500 mb-1">Module ID</p>
                                        <code className="text-slate-800 break-all">{attestationDoc.module_id || 'N/A'}</code>
                                    </div>
                                    <div className="bg-white border border-slate-200 rounded-xl p-3">
                                        <p className="text-slate-500 mb-1">Timestamp</p>
                                        <code className="text-slate-800 break-all">
                                            {attestationDoc.timestamp ? new Date(attestationDoc.timestamp).toISOString() : 'N/A'}
                                        </code>
                                    </div>
                                    <div className="bg-white border border-slate-200 rounded-xl p-3">
                                        <p className="text-slate-500 mb-1">Digest</p>
                                        <code className="text-slate-800 break-all">{attestationDoc.digest || 'N/A'}</code>
                                    </div>
                                    <div className="bg-white border border-slate-200 rounded-xl p-3">
                                        <p className="text-slate-500 mb-1">Public Key</p>
                                        <code className="text-slate-800 break-all">{attestationDoc.public_key || 'N/A'}</code>
                                    </div>
                                </div>

                                <div className="bg-white border border-slate-200 rounded-xl p-3">
                                    <p className="text-slate-500 mb-2 text-xs">PCR Values</p>
                                    {attestationPcrEntries.length > 0 ? (
                                        <div className="space-y-1 max-h-56 overflow-auto">
                                            {attestationPcrEntries.map(([idx, val]) => (
                                                <div key={idx} className="flex gap-2 text-xs">
                                                    <span className="text-slate-500 font-mono w-12">PCR{idx}</span>
                                                    <span className="text-slate-700 font-mono break-all">{String(val)}</span>
                                                </div>
                                            ))}
                                        </div>
                                    ) : (
                                        <p className="text-xs text-slate-500">No PCR data.</p>
                                    )}
                                </div>
                            </div>
                        )}
                    </div>

                </div>
            )}

            {/* ============ TAB 2: Secure Echo ============ */}
            {activeTab === 'secure-echo' && (
                <div className="space-y-6">
                    <h2 className="text-xl font-semibold mb-4">Secure Echo</h2>
                    <ApiInfoBox
                        title="Enclaver Sidecar APIs"
                        apis={['POST /v1/encryption/encrypt', 'POST /v1/encryption/decrypt', 'GET /v1/encryption/public_key']}
                        description="Demonstrates end-to-end encrypted communication with the enclave using ECDH key exchange (P-384 / secp256k1) and AES-256-GCM encryption. Even if the TLS tunnel is compromised, data remains private."
                        docLink={{
                            url: 'https://github.com/sparsity-xyz/enclaver/blob/sparsity/docs/encryption.md',
                            label: 'E2E Encryption Documentation'
                        }}
                    />

                    <div className="space-y-4">
                        <div className="flex flex-col gap-2">
                            <label className="text-sm text-slate-600">Message to Echo</label>
                            <div className="flex gap-2">
                                <input
                                    className="bg-white border border-slate-300 rounded-lg px-4 py-2 flex-1 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-100 transition"
                                    value={echoMsg}
                                    onChange={(e) => setEchoMsg(e.target.value)}
                                />
                                <button
                                    onClick={callEchoEncrypted}
                                    disabled={loading || !status.connected}
                                    className="bg-blue-600 hover:bg-blue-500 text-white px-6 py-2 rounded-lg font-semibold shadow-sm disabled:opacity-50"
                                >
                                    Encrypted Send
                                </button>
                            </div>
                        </div>

                        {echoTrace && (
                            <div className="mt-2 rounded-2xl border border-slate-200 bg-slate-50 p-5">
                                <div className="flex items-center justify-between gap-4">
                                    <div>
                                        <p className="text-xs uppercase tracking-widest text-slate-500">Encrypted Echo Trace</p>
                                        <p className="text-sm text-slate-700 break-all mt-1">{echoTrace.url}</p>
                                    </div>
                                    <button
                                        onClick={() => copyToClipboard(JSON.stringify(echoTrace, null, 2))}
                                        className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-white hover:bg-slate-100 text-slate-700 border border-slate-200"
                                    >
                                        Copy Trace JSON
                                    </button>
                                </div>

                                {echoTrace.error && (
                                    <div className="mt-4 bg-red-50 border border-red-200 rounded-xl p-3">
                                        <p className="text-xs font-semibold text-red-700">Error</p>
                                        <p className="text-xs text-red-700 break-words mt-1">{echoTrace.error}</p>
                                    </div>
                                )}

                                <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
                                    <div className="bg-white border border-slate-200 rounded-xl p-4">
                                        <p className="text-xs uppercase tracking-widest text-slate-500 mb-2">Request (plaintext)</p>
                                        <pre className="text-xs font-mono whitespace-pre-wrap break-words text-slate-700 max-h-56 overflow-auto">
                                            {echoTrace.request.plaintext}
                                        </pre>
                                    </div>
                                    <div className="bg-white border border-slate-200 rounded-xl p-4">
                                        <p className="text-xs uppercase tracking-widest text-slate-500 mb-2">Request (encrypted envelope)</p>
                                        <pre className="text-xs font-mono whitespace-pre-wrap break-words text-slate-700 max-h-56 overflow-auto">
                                            {JSON.stringify(echoTrace.request.encrypted_payload, null, 2)}
                                        </pre>
                                    </div>
                                    <div className="bg-white border border-slate-200 rounded-xl p-4">
                                        <p className="text-xs uppercase tracking-widest text-slate-500 mb-2">Response (raw)</p>
                                        <div className="text-[11px] text-slate-600 mb-2">
                                            HTTP {echoTrace.response.status} {echoTrace.response.statusText}
                                        </div>
                                        <pre className="text-xs font-mono whitespace-pre-wrap break-words text-slate-700 max-h-56 overflow-auto">
                                            {echoTrace.response.body_text || ''}
                                        </pre>
                                    </div>
                                    <div className="bg-white border border-slate-200 rounded-xl p-4">
                                        <p className="text-xs uppercase tracking-widest text-slate-500 mb-2">Response (decrypted plaintext)</p>
                                        <pre className="text-xs font-mono whitespace-pre-wrap break-words text-slate-700 max-h-56 overflow-auto">
                                            {echoTrace.response.decrypted_plaintext || ''}
                                        </pre>
                                    </div>
                                </div>

                                <div className="mt-4 bg-white border border-slate-200 rounded-xl p-4">
                                    <p className="text-xs uppercase tracking-widest text-slate-500 mb-2">Metadata</p>
                                    <div className="text-xs text-slate-700 space-y-1">
                                        <div><span className="text-slate-500">Curve:</span> {echoTrace.curve}</div>
                                        <div className="break-all"><span className="text-slate-500">Server encryption public key:</span> {echoTrace.server_encryption_public_key || '—'}</div>
                                    </div>
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            )}

            {/* ============ TAB 3: Hardware Entropy ============ */}
            {activeTab === 'hardware-entropy' && (
                <div className="space-y-6">
                    <h2 className="text-xl font-semibold mb-4">Hardware Entropy</h2>
                    <ApiInfoBox
                        title="Enclaver Sidecar API"
                        apis={['GET /v1/random']}
                        description="Generates cryptographically secure random bytes using the AWS Nitro Secure Module (NSM) hardware random number generator. Unlike software-based PRNGs, NSM provides true hardware entropy sourced from the Nitro Hypervisor, making it suitable for key generation, nonces, and other security-critical operations."
                    />

                    <div className="bg-gradient-to-br from-slate-50 to-white border border-slate-200 rounded-2xl p-8 flex flex-col items-center justify-center gap-6 shadow-sm">
                        <div className="text-center">
                            <div className="text-4xl mb-2">🎲</div>
                            <div className="text-lg font-semibold text-slate-900">Nitro Secure Module RNG</div>
                            <p className="text-xs text-slate-500 mt-1 max-w-md">
                                AWS Nitro Enclaves provide hardware-backed random number generation through the Nitro Secure Module (NSM).
                                This produces true random entropy, not software-based pseudo-random numbers.
                            </p>
                        </div>
                        <button
                            onClick={() => callApi('/api/random', 'GET', undefined, false, 'hardware-entropy')}
                            disabled={loading || !status.connected}
                            className="bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white px-8 py-3 rounded-xl font-semibold shadow-lg shadow-blue-200/60 disabled:opacity-50"
                        >
                            Generate Random Bytes
                        </button>
                    </div>

                    {responsesByTab['hardware-entropy'] && responsesByTab['hardware-entropy'].success && (
                        <div className="bg-gradient-to-br from-emerald-50 to-white border border-emerald-200 rounded-xl p-4">
                            <p className="text-xs font-semibold text-emerald-700 uppercase tracking-widest mb-2">Hardware Entropy Result</p>
                            <div className="space-y-2">
                                <div>
                                    <span className="text-xs text-slate-500">Random Hex:</span>
                                    <code className="block text-xs font-mono bg-white px-2 py-1 rounded mt-1 break-all border border-emerald-100">
                                        {responsesByTab['hardware-entropy'].data?.random_hex}
                                    </code>
                                </div>
                                <div>
                                    <span className="text-xs text-slate-500">Random Int:</span>
                                    <code className="block text-xs font-mono bg-white px-2 py-1 rounded mt-1 break-all border border-emerald-100">
                                        {responsesByTab['hardware-entropy'].data?.random_int}
                                    </code>
                                </div>
                            </div>
                        </div>
                    )}
                </div>
            )}

            {/* ============ TAB 4: S3 Storage ============ */}
            {activeTab === 'storage' && (
                <div className="space-y-6">
                    <h2 className="text-xl font-semibold mb-4">S3 Persistent Storage</h2>
                    <ApiInfoBox
                        title="Enclaver Sidecar APIs"
                        apis={['POST /v1/s3/put', 'POST /v1/s3/get', 'POST /v1/s3/list', 'POST /v1/s3/delete', 'GET /api/storage/config']}
                        description="Store and retrieve application data in S3 via the Enclaver sidecar. Encryption is transparent and uses the same /v1/s3/* endpoints; actual mode is controlled by Enclaver config."
                    />

                    <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                        <div className="flex flex-wrap items-center justify-between gap-3">
                            <div>
                                <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">Storage Encryption Status</p>
                                {storageConfigLoading ? (
                                    <p className="text-xs text-slate-500">Checking encryption mode...</p>
                                ) : storageConfig ? (
                                    <div className="flex items-center gap-2">
                                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${storageConfig.kms_required ? 'bg-emerald-100 text-emerald-700' : 'bg-amber-100 text-amber-700'}`}>
                                            {storageConfig.kms_required ? 'KMS ENABLED' : 'KMS DISABLED'}
                                        </span>
                                        <span className="text-xs text-slate-600">mode: {storageConfig.s3_encryption_mode}</span>
                                    </div>
                                ) : (
                                    <p className="text-xs text-slate-500">Unknown</p>
                                )}
                                {storageConfigError && (
                                    <p className="text-xs text-red-600 mt-1">{storageConfigError}</p>
                                )}
                            </div>
                            <button
                                onClick={refreshStorageConfig}
                                disabled={storageConfigLoading || !status.connected}
                                className="text-xs text-blue-600 hover:text-blue-700 font-medium disabled:opacity-50"
                            >
                                Refresh status
                            </button>
                        </div>
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                        <div className="flex flex-col gap-2 col-span-1">
                            <label className="text-sm text-slate-600">Key</label>
                            <input
                                className="bg-white border border-slate-300 rounded-lg px-4 py-2 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-100"
                                value={storageKey}
                                onChange={(e) => setStorageKey(e.target.value)}
                            />
                        </div>
                        <div className="flex flex-col gap-2 col-span-1">
                            <label className="text-sm text-slate-600">Value (JSON/Text)</label>
                            <input
                                className="bg-white border border-slate-300 rounded-lg px-4 py-2 outline-none focus:border-emerald-500 focus:ring-2 focus:ring-emerald-100"
                                value={storageVal}
                                onChange={(e) => setStorageVal(e.target.value)}
                            />
                        </div>
                    </div>
                    <div className="flex gap-3">
                        <button
                            onClick={() => callApi('/api/storage', 'POST', { key: storageKey, value: storageVal })}
                            disabled={loading || !status.connected}
                            className="bg-emerald-600 hover:bg-emerald-500 text-white px-6 py-2 rounded-lg font-semibold shadow-sm flex-1"
                        >
                            Store Value
                        </button>
                        <button
                            onClick={() => callApi(`/api/storage/${storageKey}`, 'GET')}
                            disabled={loading || !status.connected}
                            className="bg-blue-600 hover:bg-blue-500 text-white px-6 py-2 rounded-lg font-semibold shadow-sm disabled:opacity-50 flex-1"
                        >
                            Retrieve Key
                        </button>
                    </div>
                    <button
                        onClick={() => callApi('/api/storage', 'GET')}
                        className="text-sm text-slate-500 hover:text-slate-700"
                    >
                        List all stored keys...
                    </button>
                </div>
            )}
{/* ============ TAB 6: KMS Demo ============ */ }
{
    activeTab === 'kms-demo' && (
        <div className="space-y-6">
            <h2 className="text-xl font-semibold mb-4">KMS Demo</h2>
            <ApiInfoBox
                title="Enclaver Sidecar APIs"
                apis={['POST /v1/kms/derive', 'POST /v1/kms/kv/put', 'POST /v1/kms/kv/get', 'POST /v1/kms/kv/delete']}
                description="Demonstrates the Nova KMS (Key Management Service) integrated as an Enclaver sidecar. Provides deterministic key derivation for application secrets and a Key-Value store for persistent, app-scoped secret management with optional TTL expiration."
            />

            {/* Derive Key Section */}
            <div className="rounded-2xl border border-slate-200 bg-slate-50 p-5 space-y-4">
                <h3 className="text-sm font-semibold text-slate-800">Derive Key</h3>
                <p className="text-xs text-slate-600">Derive a deterministic cryptographic key from a hierarchical path. Same path + context always yields the same key.</p>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                    <div>
                        <label className="text-[10px] uppercase tracking-widest text-slate-500 mb-1 block">Path</label>
                        <input
                            className="w-full bg-white border border-slate-300 rounded-lg px-3 py-2 text-sm outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-100"
                            value={kmsDerivePath}
                            onChange={(e) => setKmsDerivePath(e.target.value)}
                            placeholder="app/session/demo"
                        />
                    </div>
                    <div>
                        <label className="text-[10px] uppercase tracking-widest text-slate-500 mb-1 block">Context</label>
                        <input
                            className="w-full bg-white border border-slate-300 rounded-lg px-3 py-2 text-sm outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-100"
                            value={kmsDeriveContext}
                            onChange={(e) => setKmsDeriveContext(e.target.value)}
                            placeholder="demo"
                        />
                    </div>
                    <div>
                        <label className="text-[10px] uppercase tracking-widest text-slate-500 mb-1 block">Length (bytes)</label>
                        <input
                            type="number"
                            className="w-full bg-white border border-slate-300 rounded-lg px-3 py-2 text-sm outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-100"
                            value={kmsDeriveLength}
                            min={1}
                            max={4096}
                            onChange={(e) => setKmsDeriveLength(Math.max(1, Number(e.target.value || 32)))}
                        />
                    </div>
                </div>
                <button
                    onClick={() => callApi('/api/kms/derive', 'POST', {
                        path: kmsDerivePath,
                        context: kmsDeriveContext,
                        length: kmsDeriveLength,
                    }, false, 'kms-demo')}
                    disabled={loading || !status.connected}
                    className="bg-blue-600 hover:bg-blue-500 text-white px-6 py-2 rounded-lg font-semibold text-sm disabled:opacity-50"
                >
                    Derive Key
                </button>
            </div>

            {/* KV Store Section */}
            <div className="rounded-2xl border border-slate-200 bg-slate-50 p-5 space-y-4">
                <h3 className="text-sm font-semibold text-slate-800">Key-Value Store</h3>
                <p className="text-xs text-slate-600">Securely store and retrieve application data. Data is isolated per-application and supports optional TTL expiration.</p>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                    <div>
                        <label className="text-[10px] uppercase tracking-widest text-slate-500 mb-1 block">Key</label>
                        <input
                            className="w-full bg-white border border-slate-300 rounded-lg px-3 py-2 text-sm outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-100"
                            value={kmsKvKey}
                            onChange={(e) => setKmsKvKey(e.target.value)}
                            placeholder="config/demo"
                        />
                    </div>
                    <div>
                        <label className="text-[10px] uppercase tracking-widest text-slate-500 mb-1 block">Value</label>
                        <input
                            className="w-full bg-white border border-slate-300 rounded-lg px-3 py-2 text-sm outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-100"
                            value={kmsKvValue}
                            onChange={(e) => setKmsKvValue(e.target.value)}
                            placeholder="hello-from-kms"
                        />
                    </div>
                    <div>
                        <label className="text-[10px] uppercase tracking-widest text-slate-500 mb-1 block">TTL (ms, 0=∞)</label>
                        <input
                            type="number"
                            className="w-full bg-white border border-slate-300 rounded-lg px-3 py-2 text-sm outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-100"
                            value={kmsKvTtl}
                            onChange={(e) => setKmsKvTtl(e.target.value)}
                            placeholder="0"
                        />
                    </div>
                </div>
                <div className="flex flex-wrap gap-3">
                    <button
                        onClick={() => callApi('/api/kms/kv/put', 'POST', { key: kmsKvKey, value: kmsKvValue, ttl_ms: parseInt(kmsKvTtl, 10) || 0 }, false, 'kms-demo')}
                        disabled={loading || !status.connected}
                        className="bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2 rounded-lg font-semibold text-sm shadow-sm disabled:opacity-50"
                    >
                        Put
                    </button>
                    <button
                        onClick={() => callApi('/api/kms/kv/get', 'POST', { key: kmsKvKey }, false, 'kms-demo')}
                        disabled={loading || !status.connected}
                        className="bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg font-semibold text-sm shadow-sm disabled:opacity-50"
                    >
                        Get
                    </button>
                    <button
                        onClick={() => callApi('/api/kms/kv/delete', 'POST', { key: kmsKvKey }, false, 'kms-demo')}
                        disabled={loading || !status.connected}
                        className="bg-red-600 hover:bg-red-500 text-white px-4 py-2 rounded-lg font-semibold text-sm shadow-sm disabled:opacity-50"
                    >
                        Delete
                    </button>
                </div>
            </div>
        </div>
    )
}

{/* ============ TAB 7: App Wallet Sign ============ */ }
{
    activeTab === 'app-wallet' && (
        <div className="space-y-6">
            <h2 className="text-xl font-semibold mb-4">App Wallet Sign</h2>
            <ApiInfoBox
                title="Enclaver Sidecar APIs"
                apis={['GET /v1/app-wallet/address', 'POST /v1/app-wallet/sign']}
                description="The App Wallet is a separate Ethereum wallet provisioned per-application by the Nova KMS. It can sign messages (EIP-191) and transactions independently of the TEE wallet, enabling flexible authorization patterns."
            />

            <div className="rounded-2xl border border-slate-200 bg-white p-5 space-y-4">
                <button
                    onClick={() => callApi('/api/app-wallet/address', 'GET', undefined, false, 'app-wallet')}
                    disabled={loading || !status.connected}
                    className="bg-slate-100 hover:bg-slate-200 text-slate-700 px-6 py-2.5 rounded-lg font-semibold text-sm disabled:opacity-50"
                >
                    Get Address
                </button>

                <div className="flex flex-col gap-2 border-t border-slate-200 pt-4">
                    <label className="text-xs text-slate-500">EIP-191 Message to Sign</label>
                    <div className="flex gap-3">
                        <input
                            className="bg-white border border-slate-300 rounded-lg px-3 py-2 text-sm outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-100 flex-1"
                            value={appWalletMessage}
                            onChange={(e) => setAppWalletMessage(e.target.value)}
                            placeholder="Message to sign"
                        />
                        <button
                            onClick={() => callApi('/api/app-wallet/sign', 'POST', { message: appWalletMessage }, false, 'app-wallet')}
                            disabled={loading || !status.connected}
                            className="bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white px-6 py-2 rounded-lg font-semibold text-sm whitespace-nowrap shadow-sm disabled:opacity-50"
                        >
                            Sign Message
                        </button>
                    </div>
                </div>
            </div>
        </div>
    )
}

{/* ============ TAB 8: Oracle Demo ============ */ }
{
    activeTab === 'oracle' && (
        <div className="space-y-6">
            <h2 className="text-xl font-semibold mb-4">Oracle: Internet → Chain</h2>
            <ApiInfoBox
                title="Best Practice: Oracle Update on Base Sepolia"
                apis={['POST /v1/eth/sign-tx', 'GET /v1/eth/address']}
                description="Demonstrates a TEE-based oracle pattern: fetch BTC price from internet data sources, then sign and submit the update transaction on Base Sepolia."
            />

            <div className="bg-gradient-to-br from-slate-50 to-white border border-slate-200 rounded-2xl p-8 flex flex-col items-center justify-center gap-6 shadow-sm">
                <div className="text-center">
                    <div className="text-4xl mb-2">💎</div>
                    <div className="text-2xl font-mono text-slate-900 tracking-tight">BTC / USD</div>
                </div>
                <button
                    onClick={() => callApi('/api/oracle/update-now', 'POST')}
                    disabled={loading || !status.connected}
                    className="bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white px-8 py-3 rounded-xl font-semibold shadow-lg shadow-blue-200/60 disabled:opacity-50"
                >
                    Update On-Chain Now
                </button>
            </div>

            {/* Background Runner Status */}
            <div className="grid grid-cols-2 gap-4">
                <div className="bg-slate-50 p-4 rounded-xl border border-slate-200">
                    <label className="text-xs text-slate-500 block mb-1">Last Cron Run</label>
                    <span className="text-sm font-mono text-emerald-600 italic">
                        {status.connected && responsesByTab.identity?.data?.statusInfo?.cron_info?.last_run
                            ? new Date(responsesByTab.identity.data.statusInfo.cron_info.last_run).toLocaleTimeString()
                            : 'Awaiting sync...'}
                    </span>
                </div>
                <div className="bg-slate-50 p-4 rounded-xl border border-slate-200">
                    <label className="text-xs text-slate-500 block mb-1">Background Runner Status</label>
                    <div className="flex items-center gap-2">
                        <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></div>
                        <span className="text-xs text-slate-600">
                            Worker active • {responsesByTab.identity?.data?.statusInfo?.cron_info?.counter || 0} tasks completed
                        </span>
                    </div>
                </div>
            </div>
            <button
                onClick={() => callApi('/status', 'GET')}
                disabled={loading || !status.connected}
                className="w-full py-3 border border-slate-200 rounded-xl text-sm font-medium hover:bg-slate-50 transition disabled:opacity-50"
            >
                Refresh Background Job Stats
            </button>
        </div>
    )
}

{/* ============ Universal Response Viewer ============ */ }
{
    activeResponse && activeResponse.type !== 'Connection' && (
        <div className="mt-8 border-t border-slate-200 pt-8 animate-in fade-in slide-in-from-top-4 duration-300">
            <div className="flex justify-between items-center mb-3">
                <h3 className="text-xs font-bold text-slate-500 uppercase tracking-widest">
                    Latest Response: {activeResponse.type}
                </h3>
                <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${activeResponse.success ? 'bg-emerald-100 text-emerald-700' : 'bg-red-100 text-red-700'}`}>
                    {activeResponse.success ? 'SUCCESS' : 'FAILED'}
                </span>
            </div>
            {!activeResponse.success && activeResponse.error && (
                <div className="bg-red-50 border border-red-200 rounded-xl p-4 mb-4">
                    <p className="text-sm font-semibold text-red-700">{activeResponse.error}</p>
                    {activeResponse.data && typeof activeResponse.data === 'object' && (
                        <div className="mt-3 text-xs text-red-600 space-y-1">
                            {activeResponse.data.error && (
                                <p><span className="font-semibold">Error Code:</span> {activeResponse.data.error}</p>
                            )}
                            {activeResponse.data.hint && (
                                <p><span className="font-semibold">Hint:</span> {activeResponse.data.hint}</p>
                            )}
                        </div>
                    )}
                </div>
            )}
            <pre className="bg-slate-50 rounded-xl p-5 text-xs font-mono text-slate-700 overflow-auto max-h-[300px] border border-slate-200 whitespace-pre-wrap">
                {JSON.stringify(activeResponse.data || activeResponse.error, null, 2)}
            </pre>
        </div>
    )
}
                    </div >
                </div >
            </main >

    <footer className="max-w-6xl mx-auto mt-12 text-center text-slate-500 text-sm">
        Built with <span className="text-blue-600 font-semibold">Nova Platform</span> • Powered by AWS Nitro Enclaves
    </footer>

{/* ============ Attestation Modal ============ */ }
{
    showAttestation && isClient && createPortal(
        <div
            className="fixed inset-0 z-[100] bg-black/45 backdrop-blur-sm p-4 sm:p-6"
            onClick={() => setShowAttestation(false)}
        >
            <div
                role="dialog"
                aria-modal="true"
                aria-label="Attestation document details"
                className="mx-auto flex h-full max-h-[90vh] w-full max-w-4xl flex-col overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-2xl"
                onClick={(e) => e.stopPropagation()}
            >
                <div className="sticky top-0 z-10 border-b border-slate-200 bg-white px-4 py-3 sm:px-6">
                    <div className="flex items-center justify-between gap-3" style={{ flexWrap: 'wrap' }}>
                        <h2 className="text-lg sm:text-xl font-semibold text-slate-900">Attestation Document</h2>
                        <button
                            onClick={() => setShowAttestation(false)}
                            className="px-3 py-1.5 rounded-lg text-xs font-semibold border border-slate-300 text-slate-700 hover:bg-slate-100"
                        >
                            Close
                        </button>
                    </div>
                    <div className="mt-2">
                        <div className="flex gap-1 p-1 bg-slate-100 rounded-lg" style={{ width: 'fit-content' }}>
                            {(['decoded', 'raw'] as const).map((v) => (
                                <button
                                    key={v}
                                    onClick={() => setAttestationView(v)}
                                    className={`px-3 py-1 rounded text-xs font-semibold transition ${attestationView === v ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-600 hover:text-slate-900'}`}
                                >
                                    {v.charAt(0).toUpperCase() + v.slice(1)}
                                </button>
                            ))}
                        </div>
                    </div>
                </div>
                <div className="flex-1 overflow-auto p-4 sm:p-6" style={{ overflowY: 'auto' }}>
                    {attestationLoading && (
                        <div className="flex items-center justify-center py-12">
                            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
                        </div>
                    )}
                    {attestationError && (
                        <div className="bg-red-50 border border-red-200 rounded-xl p-4 text-sm text-red-700">{attestationError}</div>
                    )}
                    {attestationData && !attestationLoading && (
                        <div className="space-y-4">
                            <div className="bg-slate-50 border border-slate-200 rounded-xl p-3">
                                <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">Attestation URL (POST only)</p>
                                <code className="text-xs text-slate-700 break-all">
                                    {(status.enclaveUrl || '').replace(/\/$/, '')}/.well-known/attestation
                                </code>
                            </div>

                            {attestationView === 'decoded' && (
                                <div className="space-y-3">
                                    <pre className="bg-slate-50 rounded-xl p-4 text-xs font-mono text-slate-700 overflow-auto max-h-[400px] border border-slate-200 whitespace-pre-wrap">
                                        {JSON.stringify(attestationData.attestation_document || {}, null, 2)}
                                    </pre>
                                </div>
                            )}

                            {attestationView === 'raw' && (
                                <div className="relative">
                                    <button
                                        onClick={() => copyToClipboard(attestationData.raw_doc || '')}
                                        className="absolute top-3 right-3 px-3 py-1.5 rounded text-xs bg-white hover:bg-slate-100 text-slate-700 border border-slate-200"
                                    >
                                        Copy
                                    </button>
                                    <pre className="bg-slate-50 rounded-xl p-4 text-xs font-mono text-slate-700 overflow-auto max-h-[400px] border border-slate-200 whitespace-pre-wrap break-all">
                                        {attestationData.raw_doc || 'No raw document available'}
                                    </pre>
                                </div>
                            )}

                        </div>
                    )}
                </div>
            </div>
        </div>,
        document.body
    )
}
        </div >
    );
}
