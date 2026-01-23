'use client';

import { useEffect, useState } from 'react';

import { EnclaveClient, type EncryptedCallTrace, type FetchedAttestation, type RATLSConnectTrace } from '@/lib/crypto';

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

export default function Home() {
    const [client] = useState(() => new EnclaveClient());
    const [status, setStatus] = useState<ConnectionStatus>({
        connected: false,
        enclaveUrl: 'http://127.0.0.1:8000',
    });
    const [loading, setLoading] = useState(false);
    const [activeTab, setActiveTab] = useState('identity');
    const [responsesByTab, setResponsesByTab] = useState<Record<string, ApiResponse | null>>({});
    const activeResponse = responsesByTab[activeTab] || null;

    const [ratlsTrace, setRATlsTrace] = useState<RATLSConnectTrace | null>(null);
    const [showRATlsTrace, setShowRATlsTrace] = useState(false);

    const [showAttestation, setShowAttestation] = useState(false);
    const [attestationLoading, setAttestationLoading] = useState(false);
    const [attestationError, setAttestationError] = useState<string | null>(null);
    const [attestationData, setAttestationData] = useState<FetchedAttestation | null>(null);
    const [attestationView, setAttestationView] = useState<'decoded' | 'raw' | 'full'>('decoded');

    // Form inputs
    const [echoMsg, setEchoMsg] = useState('Hello from Nova!');
    const [storageKey, setStorageKey] = useState('user_settings');
    const [storageVal, setStorageVal] = useState('{"theme": "dark"}');

    const [echoTrace, setEchoTrace] = useState<EncryptedCallTrace | null>(null);

    // Event monitor state
    const [eventMonitorData, setEventMonitorData] = useState<any>(null);
    const [eventMonitorLoading, setEventMonitorLoading] = useState(false);
    const [eventMonitorError, setEventMonitorError] = useState<string | null>(null);

    // Auto-detect enclave URL from current location
    useEffect(() => {
        if (typeof window !== 'undefined') {
            const currentHost = window.location.origin;
            if (currentHost.includes('sparsity.cloud') || currentHost.includes('localhost:8000')) {
                setStatus(prev => ({ ...prev, enclaveUrl: currentHost }));
            }
        }
    }, []);

    const handleConnect = async () => {
        if (!status.enclaveUrl) return;
        setLoading(true);
        try {
            setRATlsTrace(null);
            setShowRATlsTrace(false);
            const { attestation, trace } = await client.connectWithTrace(status.enclaveUrl);
            setRATlsTrace(trace);
            const statusInfo = await client.call('/status');
            setStatus({
                ...status,
                connected: true,
                teeAddress: statusInfo.eth_address,
                error: undefined,
            });
            setResponsesByTab(prev => ({
                ...prev,
                identity: { success: true, data: { attestation, statusInfo }, type: 'Connection' },
            }));
        } catch (error) {
            setStatus({
                ...status,
                connected: false,
                error: error instanceof Error ? error.message : 'Connection failed',
            });
        } finally {
            setLoading(false);
        }
    };

    const handleTabChange = (tabId: string) => {
        setActiveTab(tabId);
    };

    // Auto-load event monitor status when switching to events tab (poll every 5s)
    useEffect(() => {
        if (activeTab !== 'events' || !status.connected) return;

        const fetchMonitorStatus = async () => {
            setEventMonitorLoading(true);
            setEventMonitorError(null);

            try {
                const res = await client.call('/api/events/monitor', 'GET');
                setEventMonitorData(res);
            } catch (err: any) {
                const errDetail = err?.detail;
                const errMsg = errDetail?.message || errDetail?.error || err?.message || 'Unknown error';
                setEventMonitorError(errMsg);
            } finally {
                setEventMonitorLoading(false);
            }
        };

        // Initial fetch
        fetchMonitorStatus();

        // Poll every 5 seconds
        const interval = setInterval(fetchMonitorStatus, 5000);

        return () => clearInterval(interval);
    }, [activeTab, status.connected, client]);

    const callApi = async (path: string, method: 'GET' | 'POST' = 'GET', body?: any, encrypted = false) => {
        const tabAtCall = activeTab;
        setLoading(true);
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

    const syntaxHighlight = (jsonString: string) => {
        if (!jsonString) return '';
        const escaped = jsonString.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        return escaped.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g, match => {
            if (/^".*"\s*:?$/.test(match)) {
                if (/":$/.test(match)) {
                    return `<span class="text-sky-700 font-semibold">${match}</span>`;
                }
                return `<span class="text-emerald-700">${match}</span>`;
            }
            if (/true|false/.test(match)) return `<span class="text-violet-700">${match}</span>`;
            if (/null/.test(match)) return `<span class="text-slate-500">${match}</span>`;
            return `<span class="text-amber-700">${match}</span>`;
        });
    };

    const handleViewAttestation = async () => {
        if (!status.connected) return;
        setShowAttestation(true);
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
            // Fallback for older browsers
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

    return (
        <div className="min-h-screen bg-gradient-to-br from-white via-slate-50 to-sky-50 text-slate-900 p-8 font-sans">
            <header className="max-w-7xl mx-auto mb-12">
                <div className="flex flex-col gap-6 rounded-3xl border border-slate-200 bg-white/95 backdrop-blur px-8 py-6 shadow-xl shadow-slate-200/50">
                    <div className="flex items-start justify-between gap-6 flex-wrap">
                        <div>
                            <p className="text-xs uppercase tracking-[0.3em] text-slate-400">Nova Platform</p>
                            <h1 className="text-3xl font-semibold text-slate-900 mt-2">
                                🛡️ Nova App Template
                            </h1>
                            <p className="text-slate-500 mt-2">Secure, verifiable TEE apps with RA‑TLS, S3, and on‑chain trust.</p>
                        </div>

                        <div className="min-w-[320px] flex-1 max-w-md">
                            <div className="flex items-center gap-3 rounded-2xl border border-slate-200 bg-white px-4 py-3 shadow-sm">
                                <div className="flex-1">
                                    <label className="text-[10px] uppercase tracking-widest text-slate-400">Enclave URL</label>
                                    <input
                                        className="mt-1 w-full bg-transparent text-sm text-slate-700 outline-none placeholder:text-slate-400"
                                        value={status.enclaveUrl}
                                        onChange={(e) => setStatus({ ...status, enclaveUrl: e.target.value })}
                                        placeholder="https://your-app.sparsity.cloud"
                                    />
                                </div>
                                <button
                                    onClick={handleConnect}
                                    disabled={loading || status.connected}
                                    className={`px-4 py-2 rounded-xl text-sm font-semibold transition ${status.connected
                                        ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                                        : 'bg-blue-600 hover:bg-blue-500 text-white shadow-sm'
                                        }`}
                                >
                                    {loading ? 'Connecting...' : status.connected ? 'Connected' : 'Connect'}
                                </button>
                            </div>
                        </div>
                    </div>

                    <div className="flex flex-wrap gap-3 text-xs text-slate-500">
                        <span className="px-3 py-1 rounded-full bg-sky-50 border border-sky-100 text-sky-700">RA‑TLS</span>
                        <span className="px-3 py-1 rounded-full bg-sky-50 border border-sky-100 text-sky-700">S3 Storage</span>
                        <span className="px-3 py-1 rounded-full bg-sky-50 border border-sky-100 text-sky-700">Oracles</span>
                        <span className="px-3 py-1 rounded-full bg-sky-50 border border-sky-100 text-sky-700">Event Listener</span>
                    </div>
                </div>
            </header>

            <main className="max-w-7xl mx-auto grid grid-cols-1 lg:grid-cols-3 gap-8">
                {/* Left: Navigation & Info */}
                <div className="lg:col-span-1 space-y-6">
                    <section className="bg-white rounded-2xl border border-slate-200 p-6 shadow-lg shadow-slate-200/60">
                        <h2 className="text-xs font-semibold text-slate-500 uppercase tracking-[0.2em] mb-4">Capabilities</h2>
                        <nav className="flex flex-col gap-2">
                            {[
                                { id: 'identity', label: 'Identity & RA-TLS', icon: '🔑' },
                                { id: 'secure-echo', label: 'Secure Echo', icon: '🔒' },
                                { id: 'storage', label: 'S3 Storage', icon: '📦' },
                                { id: 'oracle', label: 'Oracle Demo', icon: '🌐' },
                                { id: 'events', label: 'Event Monitor', icon: '📊' },
                            ].map(tab => (
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

                    {status.connected && (
                        <section className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
                            <h2 className="text-xs font-semibold text-slate-500 uppercase tracking-[0.2em] mb-3">Enclave Identity</h2>
                            <div className="space-y-4">
                                <div>
                                    <label className="text-xs text-slate-500 block mb-1">TEE Wallet Address</label>
                                    <code className="text-xs bg-slate-50 px-2 py-1 rounded block truncate border border-slate-200 text-slate-700">
                                        {status.teeAddress}
                                    </code>
                                </div>
                                <div>
                                    <label className="text-xs text-slate-500 block mb-1">App Contract Address</label>
                                    <code className="text-xs bg-slate-50 px-2 py-1 rounded block truncate border border-slate-200 text-slate-700">
                                        {responsesByTab.identity?.data?.statusInfo?.contract_address || 'Not configured'}
                                    </code>
                                </div>
                                <div className="flex gap-2 text-xs">
                                    <span className="bg-emerald-50 text-emerald-700 px-2 py-0.5 rounded border border-emerald-200">Active</span>
                                    <span className="bg-blue-50 text-blue-700 px-2 py-0.5 rounded border border-blue-200">Verifiable</span>
                                </div>
                            </div>
                        </section>
                    )}
                </div>

                {/* Right: Content Area */}
                <div className="lg:col-span-2 space-y-6">
                    <div className="bg-white rounded-2xl border border-slate-200 p-8 min-h-[400px] shadow-lg shadow-slate-200/60">
                        {activeTab === 'identity' && (
                            <div className="space-y-6">
                                <h2 className="text-xl font-semibold mb-4">Identity & RA-TLS</h2>
                                <p className="text-slate-600 text-sm leading-relaxed mb-6">
                                    Establish a secure, hardware-verifiable channel with the enclave using AWS Nitro Attestation
                                    and ECDH key exchange.
                                </p>

                                <div className="space-y-4">
                                    <div className="flex gap-4">
                                        <button
                                            onClick={handleViewAttestation}
                                            disabled={loading || !status.connected}
                                            className="text-sm text-blue-600 hover:text-blue-700 font-medium"
                                        >
                                            Fetch Attestation →
                                        </button>
                                        <button
                                            onClick={() => setShowRATlsTrace((v) => !v)}
                                            disabled={loading || !status.connected || !ratlsTrace}
                                            className="text-sm text-slate-600 hover:text-slate-800 font-medium disabled:opacity-50"
                                        >
                                            {showRATlsTrace ? 'Hide RA‑TLS Trace →' : 'Show RA‑TLS Trace →'}
                                        </button>
                                        <button
                                            onClick={() => {
                                                setShowAttestation(false);
                                                setShowRATlsTrace(false);
                                                callApi('/api/random', 'GET');
                                            }}
                                            disabled={loading || !status.connected}
                                            className="text-sm text-emerald-600 hover:text-emerald-700 font-medium"
                                        >
                                            Fetch Hardware Entropy (NSM) →
                                        </button>
                                    </div>
                                </div>

                                {ratlsTrace && showRATlsTrace && (
                                    <div className="mt-6 rounded-2xl border border-slate-200 bg-slate-50 p-5">
                                        <div className="flex items-center justify-between gap-4">
                                            <div>
                                                <p className="text-xs uppercase tracking-widest text-slate-500">RA-TLS Establishment Trace</p>
                                                <p className="text-sm text-slate-700 break-all mt-1">{ratlsTrace.baseUrl}</p>
                                            </div>
                                            <button
                                                onClick={() => copyToClipboard(JSON.stringify(ratlsTrace, null, 2))}
                                                className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-white hover:bg-slate-100 text-slate-700 border border-slate-200"
                                            >
                                                Copy Trace JSON
                                            </button>
                                        </div>

                                        <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
                                            <div className="bg-white border border-slate-200 rounded-xl p-4">
                                                <p className="text-xs uppercase tracking-widest text-slate-500 mb-2">Key Material (metadata)</p>
                                                <div className="text-xs text-slate-700 space-y-1">
                                                    <div><span className="text-slate-500">Curve:</span> {ratlsTrace.encryptionPublicKey?.curve || '—'}</div>
                                                    <div className="break-all"><span className="text-slate-500">Server encryption public key:</span> {ratlsTrace.encryptionPublicKey?.public_key_der || '—'}</div>
                                                    <div><span className="text-slate-500">Client pubkey DER length:</span> {ratlsTrace.client?.client_public_key_der_len ?? '—'}</div>
                                                </div>
                                            </div>

                                            <div className="bg-white border border-slate-200 rounded-xl p-4">
                                                <p className="text-xs uppercase tracking-widest text-slate-500 mb-2">Attestation (summary)</p>
                                                <div className="text-xs text-slate-700 space-y-1">
                                                    <div className="break-all"><span className="text-slate-500">Module ID:</span> {ratlsTrace.attestation?.decoded?.module_id || '—'}</div>
                                                    <div><span className="text-slate-500">Timestamp:</span> {ratlsTrace.attestation?.decoded?.timestamp ? new Date(ratlsTrace.attestation.decoded.timestamp * 1000).toISOString() : '—'}</div>
                                                    <div><span className="text-slate-500">PCR count:</span> {ratlsTrace.attestation?.decoded?.pcr_count ?? '—'}</div>
                                                </div>
                                            </div>
                                        </div>

                                        <div className="mt-4 bg-white border border-slate-200 rounded-xl p-4">
                                            <p className="text-xs uppercase tracking-widest text-slate-500 mb-3">Steps</p>
                                            <div className="space-y-2">
                                                {ratlsTrace.steps.map((s, idx) => (
                                                    <div key={idx} className={`flex items-start justify-between gap-3 rounded-lg border px-3 py-2 ${s.ok ? 'border-emerald-200 bg-emerald-50/50' : 'border-red-200 bg-red-50/50'}`}>
                                                        <div>
                                                            <div className="text-xs font-semibold text-slate-800">{s.name}</div>
                                                            {!s.ok && s.error && (
                                                                <div className="text-xs text-red-700 mt-1 break-words">{s.error}</div>
                                                            )}
                                                        </div>
                                                        <div className="text-[11px] text-slate-500 whitespace-nowrap">
                                                            {(s.endedAt - s.startedAt)}ms
                                                        </div>
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}

                        {activeTab === 'secure-echo' && (
                            <div className="space-y-6">
                                <h2 className="text-xl font-semibold mb-4">Secure Echo</h2>
                                <p className="text-slate-600 text-sm leading-relaxed mb-6">
                                    Send an encrypted request to the enclave using ECDH + AES-GCM and (optionally) inspect the full
                                    end-to-end interaction.
                                </p>

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
                                                    <p className="text-sm text-slate-700 break-all mt-1">
                                                        {echoTrace.url}
                                                    </p>
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

                        {activeTab === 'storage' && (
                            <div className="space-y-6">
                                <h2 className="text-xl font-semibold mb-4">S3 Persistent Storage</h2>
                                <p className="text-slate-600 text-sm leading-relaxed mb-6">
                                    Store and retrieve sensitive state in encrypted S3 objects. For <code className="bg-slate-100 px-1 rounded">user_settings</code> key,
                                    the value hash is anchored on-chain and verified on retrieval.
                                </p>

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
                                        className="bg-slate-100 hover:bg-slate-200 text-slate-700 px-6 py-2 rounded-lg font-semibold flex-1"
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

                                {/* On-chain verification details for storage operations */}
                                {activeResponse?.type?.includes('/api/storage') && activeResponse.success && activeResponse.data && (
                                    <div className="bg-gradient-to-br from-slate-50 to-white border border-slate-200 rounded-2xl p-5 mt-4">
                                        <h3 className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-3">On-Chain Anchoring Status</h3>
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                                            {/* TEE Address */}
                                            {activeResponse.data.tee_address && (
                                                <div className="bg-white border border-slate-200 rounded-xl p-3">
                                                    <p className="text-slate-500 mb-1">TEE Wallet Address</p>
                                                    <code className="text-slate-800 break-all">{activeResponse.data.tee_address}</code>
                                                </div>
                                            )}
                                            {/* TEE Balance */}
                                            {activeResponse.data.tee_balance_eth !== undefined && (
                                                <div className="bg-white border border-slate-200 rounded-xl p-3">
                                                    <p className="text-slate-500 mb-1">TEE Wallet Balance</p>
                                                    <code className="text-slate-800">{activeResponse.data.tee_balance_eth.toFixed(6)} ETH</code>
                                                </div>
                                            )}
                                            {/* Contract Address */}
                                            {activeResponse.data.contract_address && (
                                                <div className="bg-white border border-slate-200 rounded-xl p-3">
                                                    <p className="text-slate-500 mb-1">Contract Address</p>
                                                    <code className="text-slate-800 break-all">{activeResponse.data.contract_address}</code>
                                                </div>
                                            )}
                                            {/* State Hash */}
                                            {activeResponse.data.state_hash && (
                                                <div className="bg-white border border-slate-200 rounded-xl p-3">
                                                    <p className="text-slate-500 mb-1">State Hash (computed)</p>
                                                    <code className="text-slate-800 break-all">{activeResponse.data.state_hash}</code>
                                                </div>
                                            )}
                                            {/* Anchor Tx */}
                                            {activeResponse.data.anchor_tx && (
                                                <div className="bg-white border border-slate-200 rounded-xl p-3 col-span-2">
                                                    <p className="text-slate-500 mb-1">Anchor Transaction</p>
                                                    <code className="text-blue-700 break-all">{activeResponse.data.anchor_tx.transaction_hash || '—'}</code>
                                                    {activeResponse.data.broadcast !== undefined && (
                                                        <span className={`ml-2 ${activeResponse.data.anchor_tx.broadcasted ? 'text-emerald-600' : 'text-slate-500'}`}>
                                                            {activeResponse.data.anchor_tx.broadcasted ? '(broadcasted)' : '(not broadcasted)'}
                                                        </span>
                                                    )}
                                                </div>
                                            )}
                                            {/* Anchor Skipped */}
                                            {activeResponse.data.anchor_skipped && (
                                                <div className="bg-yellow-50 border border-yellow-200 rounded-xl p-3 col-span-2">
                                                    <p className="text-yellow-700 font-semibold">⚠ Anchoring Skipped</p>
                                                    <p className="text-yellow-600 mt-1">{activeResponse.data.anchor_note}</p>
                                                </div>
                                            )}
                                            {/* Anchor Error */}
                                            {activeResponse.data.anchor_error && (
                                                <div className="bg-red-50 border border-red-200 rounded-xl p-3 col-span-2">
                                                    <p className="text-red-700 font-semibold">✗ Anchor Failed</p>
                                                    <p className="text-red-600 mt-1">{activeResponse.data.anchor_error}</p>
                                                    {activeResponse.data.error_type && (
                                                        <p className="text-red-500 text-xs mt-1">Error Type: {activeResponse.data.error_type}</p>
                                                    )}
                                                    {activeResponse.data.hint && (
                                                        <p className="text-red-500 text-xs mt-1">Hint: {activeResponse.data.hint}</p>
                                                    )}
                                                </div>
                                            )}
                                            {/* On-chain Hash (for retrieve) */}
                                            {activeResponse.data.onchain_hash && (
                                                <div className="bg-white border border-slate-200 rounded-xl p-3">
                                                    <p className="text-slate-500 mb-1">On-Chain Hash</p>
                                                    <code className="text-slate-800 break-all">{activeResponse.data.onchain_hash}</code>
                                                </div>
                                            )}
                                            {/* Computed Hash (for retrieve) */}
                                            {activeResponse.data.computed_hash && (
                                                <div className="bg-white border border-slate-200 rounded-xl p-3">
                                                    <p className="text-slate-500 mb-1">Computed Hash (from S3)</p>
                                                    <code className="text-slate-800 break-all">{activeResponse.data.computed_hash}</code>
                                                </div>
                                            )}
                                            {/* Verification Status */}
                                            {activeResponse.data.verified !== undefined && (
                                                <div className={`rounded-xl p-3 col-span-2 ${activeResponse.data.verified === true ? 'bg-emerald-50 border border-emerald-200' : activeResponse.data.verified === false ? 'bg-red-50 border border-red-200' : 'bg-yellow-50 border border-yellow-200'}`}>
                                                    <p className={`font-semibold ${activeResponse.data.verified === true ? 'text-emerald-700' : activeResponse.data.verified === false ? 'text-red-700' : 'text-yellow-700'}`}>
                                                        {activeResponse.data.verified === true ? '✓ Data Verified — S3 data matches on-chain hash' : activeResponse.data.verified === false ? '✗ Verification Failed — Hash mismatch, data untrusted' : '⚠ Verification Skipped'}
                                                    </p>
                                                    {activeResponse.data.verification_note && (
                                                        <p className="text-xs text-slate-600 mt-1">{activeResponse.data.verification_note}</p>
                                                    )}
                                                </div>
                                            )}
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}

                        {activeTab === 'oracle' && (
                            <div className="space-y-6">
                                <h2 className="text-xl font-semibold mb-4">Oracle: Internet → Chain</h2>
                                <p className="text-slate-600 text-sm leading-relaxed mb-6">
                                    The enclave fetches real-time data from the internet, processes it, and signs a
                                    cryptographically secure transaction for on-chain execution.
                                </p>

                                <div className="bg-gradient-to-br from-slate-50 to-white border border-slate-200 rounded-2xl p-8 flex flex-col items-center justify-center gap-6 shadow-sm">
                                    <div className="text-center">
                                        <div className="text-4xl mb-2">💎</div>
                                        <div className="text-2xl font-mono text-slate-900 tracking-tight">ETH / USD</div>
                                    </div>
                                    <button
                                        onClick={() => callApi('/api/oracle/update-now', 'POST')}
                                        disabled={loading || !status.connected}
                                        className="bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white px-8 py-3 rounded-xl font-semibold shadow-lg shadow-blue-200/60"
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
                                    className="w-full py-3 border border-slate-200 rounded-xl text-sm font-medium hover:bg-slate-50 transition"
                                >
                                    Refresh Background Job Stats
                                </button>
                            </div>
                        )}

                        {activeTab === 'events' && (
                            <div className="space-y-6">
                                <h2 className="text-xl font-semibold mb-4">On-Chain Event Monitor</h2>
                                <p className="text-slate-600 text-sm leading-relaxed mb-6">
                                    The enclave automatically monitors on-chain events. When an <code className="bg-slate-100 px-1 rounded">EthPriceUpdateRequested</code> event
                                    is detected, it fetches ETH/USD and submits an on-chain update automatically.
                                </p>

                                {/* Status Bar */}
                                <div className="bg-slate-50 border border-slate-200 rounded-xl p-4">
                                    <div className="flex items-center justify-between">
                                        <div className="flex items-center gap-3">
                                            {eventMonitorLoading ? (
                                                <div className="w-3 h-3 rounded-full bg-blue-500 animate-pulse"></div>
                                            ) : eventMonitorError ? (
                                                <div className="w-3 h-3 rounded-full bg-red-500"></div>
                                            ) : eventMonitorData?.status === 'active' ? (
                                                <div className="w-3 h-3 rounded-full bg-emerald-500 animate-pulse"></div>
                                            ) : (
                                                <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
                                            )}
                                            <span className="text-sm font-medium text-slate-700">
                                                {eventMonitorLoading ? 'Loading...' :
                                                 eventMonitorError ? 'Error' :
                                                 eventMonitorData?.status === 'active' ? 'Monitoring Active' :
                                                 eventMonitorData?.status === 'not_configured' ? 'Contract Not Configured' :
                                                 'Initializing...'}
                                            </span>
                                        </div>
                                        <div className="text-xs text-slate-500">
                                            {eventMonitorData?.last_poll && (
                                                <span>Last poll: {new Date(eventMonitorData.last_poll).toLocaleTimeString()}</span>
                                            )}
                                        </div>
                                    </div>
                                    {eventMonitorData?.contract_address && (
                                        <div className="mt-2 text-xs text-slate-500">
                                            Contract: <code className="bg-slate-100 px-1 rounded">{eventMonitorData.contract_address}</code>
                                        </div>
                                    )}
                                    {eventMonitorData?.current_block && (
                                        <div className="mt-1 text-xs text-slate-500">
                                            Block: <span className="font-mono">{eventMonitorData.current_block}</span>
                                        </div>
                                    )}
                                </div>

                                {/* Error Display */}
                                {eventMonitorError && (
                                    <div className="bg-red-50 border border-red-200 rounded-xl p-4">
                                        <p className="text-red-700 font-semibold">✗ {eventMonitorError}</p>
                                    </div>
                                )}

                                {/* Recent Events */}
                                {eventMonitorData?.recent_events?.length > 0 && (
                                    <div className="bg-white border border-slate-200 rounded-2xl p-4">
                                        <div className="flex items-center justify-between mb-3">
                                            <div className="text-xs font-bold text-slate-500 uppercase tracking-widest">
                                                Recent Events
                                            </div>
                                            {eventMonitorData.pending_count > 0 && (
                                                <span className="bg-amber-100 text-amber-700 text-xs px-2 py-1 rounded-full">
                                                    {eventMonitorData.pending_count} pending
                                                </span>
                                            )}
                                        </div>
                                        <div className="overflow-auto max-h-[200px]">
                                            <table className="w-full text-xs">
                                                <thead className="text-slate-500">
                                                    <tr className="border-b border-slate-200">
                                                        <th className="text-left py-2 pr-3">Block</th>
                                                        <th className="text-left py-2 pr-3">Request ID</th>
                                                        <th className="text-left py-2 pr-3">Status</th>
                                                        <th className="text-left py-2 pr-3">Price</th>
                                                    </tr>
                                                </thead>
                                                <tbody className="text-slate-700">
                                                    {eventMonitorData.recent_events.map((e: any, idx: number) => (
                                                        <tr key={idx} className={`border-b border-slate-100 ${!e.handled ? 'bg-amber-50' : ''}`}>
                                                            <td className="py-2 pr-3 font-mono">{e.block_number}</td>
                                                            <td className="py-2 pr-3 font-mono">#{e.request_id}</td>
                                                            <td className="py-2 pr-3">
                                                                {e.handled ? (
                                                                    <span className="text-emerald-600">✓ handled</span>
                                                                ) : (
                                                                    <span className="text-amber-600">⏳ pending</span>
                                                                )}
                                                            </td>
                                                            <td className="py-2 pr-3 font-mono">
                                                                {e.price_usd ? `$${e.price_usd}` : '-'}
                                                            </td>
                                                        </tr>
                                                    ))}
                                                </tbody>
                                            </table>
                                        </div>
                                    </div>
                                )}

                                {/* Activity Logs */}
                                {eventMonitorData?.logs?.length > 0 && (
                                    <div className="bg-slate-900 rounded-2xl p-4">
                                        <div className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-3">
                                            Activity Log
                                        </div>
                                        <div className="font-mono text-xs text-slate-300 space-y-1 max-h-[200px] overflow-auto">
                                            {eventMonitorData.logs.slice().reverse().map((log: any, idx: number) => (
                                                <div key={idx} className="flex gap-2">
                                                    <span className="text-slate-500 shrink-0">
                                                        {new Date(log.time).toLocaleTimeString()}
                                                    </span>
                                                    <span className={
                                                        log.message.includes('✓') ? 'text-emerald-400' :
                                                        log.message.includes('✗') ? 'text-red-400' :
                                                        'text-slate-300'
                                                    }>
                                                        {log.message}
                                                    </span>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}

                                {/* Last Price Info */}
                                {eventMonitorData?.last_price_usd && (
                                    <div className="bg-gradient-to-br from-emerald-50 to-white border border-emerald-200 rounded-xl p-4">
                                        <div className="text-xs text-slate-500 mb-1">Last Updated Price</div>
                                        <div className="text-2xl font-mono text-emerald-700">${eventMonitorData.last_price_usd}</div>
                                        <div className="text-xs text-slate-500 mt-1">
                                            {eventMonitorData.last_updated_at && (
                                                <span>Updated: {new Date(eventMonitorData.last_updated_at * 1000).toLocaleString()}</span>
                                            )}
                                            {eventMonitorData.last_reason && (
                                                <span className="ml-2">({eventMonitorData.last_reason})</span>
                                            )}
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}

                        {/* Universal Response Viewer */}
                        {activeResponse && (
                            <div className="mt-8 border-t border-slate-200 pt-8 animate-in fade-in slide-in-from-top-4 duration-300">
                                <div className="flex justify-between items-center mb-3">
                                    <h3 className="text-xs font-bold text-slate-500 uppercase tracking-widest">
                                        Latest Response: {activeResponse.type}
                                    </h3>
                                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${activeResponse.success ? 'bg-emerald-100 text-emerald-700' : 'bg-red-100 text-red-700'}`}>
                                        {activeResponse.success ? 'SUCCESS' : 'FAILED'}
                                    </span>
                                </div>
                                {/* Show error summary for failed requests */}
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
                                                {activeResponse.data.tee_address && (
                                                    <p><span className="font-semibold">TEE Address:</span> <code className="bg-red-100 px-1 rounded">{activeResponse.data.tee_address}</code></p>
                                                )}
                                                {activeResponse.data.contract_address && (
                                                    <p><span className="font-semibold">Contract:</span> <code className="bg-red-100 px-1 rounded">{activeResponse.data.contract_address}</code></p>
                                                )}
                                            </div>
                                        )}
                                    </div>
                                )}
                                <pre className="bg-slate-50 rounded-xl p-5 text-xs font-mono text-slate-700 overflow-auto max-h-[300px] border border-slate-200 whitespace-pre-wrap">
                                    {JSON.stringify(activeResponse.data || activeResponse.error, null, 2)}
                                </pre>
                            </div>
                        )}
                    </div>
                </div>
            </main>

            <footer className="max-w-6xl mx-auto mt-12 text-center text-slate-500 text-sm">
                Built with <span className="text-blue-600 font-semibold">Nova Platform</span> • Powered by AWS Nitro Enclaves
            </footer>

            {showAttestation && (
                <div className="fixed inset-0 bg-slate-900/30 backdrop-blur-sm flex items-center justify-center z-50 p-6">
                    <div className="bg-white border border-slate-200 rounded-3xl shadow-2xl max-w-5xl w-full max-h-[90vh] flex flex-col overflow-hidden">
                        <div className="px-8 py-5 border-b border-slate-200 flex items-center justify-between">
                            <div>
                                <h2 className="text-lg font-semibold text-slate-900">Fetch Attestation</h2>
                                <p className="text-xs text-slate-500">Hardware-backed proof from AWS Nitro Enclave</p>
                            </div>
                            <button
                                onClick={() => setShowAttestation(false)}
                                className="text-slate-400 hover:text-slate-600 text-2xl font-bold"
                                aria-label="Close"
                            >
                                ×
                            </button>
                        </div>

                        <div className="px-8 py-6 overflow-auto flex-1">
                            {attestationLoading ? (
                                <div className="text-center py-12">
                                    <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
                                    <p className="mt-4 text-slate-500">Loading attestation...</p>
                                </div>
                            ) : attestationError ? (
                                <div className="py-8">
                                    <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                                        <h3 className="text-red-700 font-semibold mb-2">Failed to fetch attestation</h3>
                                        <p className="text-red-600 text-sm">{attestationError}</p>
                                    </div>
                                </div>
                            ) : attestationData ? (
                                <div className="space-y-4">
                                    <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                                        <div className="space-y-1">
                                            <p className="text-xs uppercase tracking-widest text-slate-500">Attestation URL (POST only)</p>
                                            <p className="text-sm text-slate-800 break-all">
                                                {(status.enclaveUrl || '').replace(/\/$/, '')}/.well-known/attestation
                                            </p>
                                        </div>
                                        <div className="flex flex-wrap gap-2">
                                            <button
                                                onClick={() => copyToClipboard(`${(status.enclaveUrl || '').replace(/\/$/, '')}/.well-known/attestation`)}
                                                className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-200"
                                            >
                                                Copy URL
                                            </button>
                                            <button
                                                onClick={() => copyToClipboard(attestationData.raw_doc)}
                                                className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-200"
                                            >
                                                Copy Raw
                                            </button>
                                        </div>
                                    </div>

                                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                                        <div className="bg-slate-50 border border-slate-200 rounded-2xl p-4">
                                            <p className="text-xs uppercase tracking-widest text-slate-500">Module ID</p>
                                            <p className="mt-2 text-sm text-slate-800 break-all">
                                                {attestationData.attestation_document?.module_id || '—'}
                                            </p>
                                        </div>
                                        <div className="bg-slate-50 border border-slate-200 rounded-2xl p-4">
                                            <p className="text-xs uppercase tracking-widest text-slate-500">Timestamp</p>
                                            <p className="mt-2 text-sm text-slate-800">
                                                {attestationData.attestation_document?.timestamp
                                                    ? new Date(attestationData.attestation_document.timestamp * 1000).toISOString()
                                                    : '—'}
                                            </p>
                                        </div>
                                        <div className="bg-slate-50 border border-slate-200 rounded-2xl p-4">
                                            <p className="text-xs uppercase tracking-widest text-slate-500">PCRs</p>
                                            <p className="mt-2 text-sm text-slate-800">
                                                {attestationData.attestation_document?.pcrs
                                                    ? Object.keys(attestationData.attestation_document.pcrs).length
                                                    : 0} slots
                                            </p>
                                        </div>
                                    </div>

                                    {attestationData.attestation_document?.pcrs && (
                                        <div className="bg-slate-50 border border-slate-200 rounded-2xl p-4">
                                            <p className="text-xs uppercase tracking-widest text-slate-500 mb-3">PCR Values</p>
                                            <div className="space-y-2">
                                                {Object.entries(attestationData.attestation_document.pcrs)
                                                    .sort(([a], [b]) => Number(a) - Number(b))
                                                    .map(([idx, value]) => (
                                                        <div key={idx} className="flex flex-col md:flex-row md:items-start md:gap-3">
                                                            <span className="text-xs font-semibold text-slate-600 w-12 shrink-0">PCR{idx}</span>
                                                            <code className="text-xs text-slate-700 break-all bg-white border border-slate-200 rounded-lg px-2 py-1">
                                                                {value}
                                                            </code>
                                                        </div>
                                                    ))}
                                            </div>
                                        </div>
                                    )}

                                    <div className="flex flex-wrap gap-2">
                                        {[
                                            { id: 'decoded', label: 'Decoded' },
                                            { id: 'raw', label: 'Raw (base64)' },
                                            { id: 'full', label: 'Full JSON' },
                                        ].map(tab => (
                                            <button
                                                key={tab.id}
                                                onClick={() => setAttestationView(tab.id as any)}
                                                className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition ${attestationView === tab.id
                                                    ? 'bg-blue-600 text-white border-blue-600'
                                                    : 'bg-white text-slate-700 border-slate-200 hover:bg-slate-50'
                                                    }`}
                                            >
                                                {tab.label}
                                            </button>
                                        ))}
                                    </div>

                                    {attestationView === 'raw' ? (
                                        <div className="bg-slate-50 border border-slate-200 rounded-2xl p-4 overflow-auto max-h-[50vh]">
                                            <code className="text-xs text-slate-700 block whitespace-pre-wrap break-words">
                                                {attestationData.raw_doc}
                                            </code>
                                        </div>
                                    ) : (
                                        <div className="bg-slate-50 border border-slate-200 rounded-2xl p-4 overflow-auto max-h-[50vh]">
                                            <code
                                                className="text-xs text-slate-700 block whitespace-pre-wrap break-words"
                                                dangerouslySetInnerHTML={{
                                                    __html: syntaxHighlight(
                                                        JSON.stringify(
                                                            attestationView === 'decoded'
                                                                ? attestationData.attestation_document
                                                                : attestationData,
                                                            null,
                                                            2
                                                        )
                                                    ),
                                                }}
                                            />
                                        </div>
                                    )}
                                </div>
                            ) : null}
                        </div>

                        <div className="px-8 py-5 border-t border-slate-200 flex justify-end">
                            <button
                                onClick={() => setShowAttestation(false)}
                                className="px-4 py-2 bg-slate-100 text-slate-700 rounded-lg hover:bg-slate-200"
                            >
                                Close
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
