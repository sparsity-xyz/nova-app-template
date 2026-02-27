import React, { useState } from 'react';

export default function KmsDemo({ callApi, isOffline }: { callApi: any, isOffline: boolean }) {
    const [key, setKey] = useState('demo_key');
    const [value, setValue] = useState('{"message": "hello KMS"}');
    const [ttlMs, setTtlMs] = useState('0'); // 0 means no expiration
    const [response, setResponse] = useState<any>(null);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const handleKmsOp = async (op: 'get' | 'put' | 'delete') => {
        setIsLoading(true);
        setError(null);
        setResponse(null);

        try {
            let path = `/api/kms/kv/${op}`;
            let body: any = { key };

            if (op === 'put') {
                const parsedTtl = parseInt(ttlMs, 10);
                body = { key, value, ttl_ms: isNaN(parsedTtl) ? 0 : parsedTtl };
            }

            const res = await callApi(path, 'POST', body);
            setResponse(res);
        } catch (err: any) {
            setError(err.message || 'Operation failed');
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="space-y-6">
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 shadow-md">
                <h2 className="text-xl font-semibold mb-4 text-white flex items-center">
                    <svg className="w-5 h-5 mr-2 text-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8V7a4 4 0 00-8 0v4h8z" />
                    </svg>
                    KMS Key-Value Store
                </h2>

                <p className="text-gray-400 mb-6 text-sm">
                    Interact directly with the Nova Platform Key Management Service (KMS).
                    Data is securely stored and isolated per application.
                </p>

                <div className="space-y-4">
                    <div>
                        <label className="block text-sm font-medium text-gray-300 mb-1">Key Name</label>
                        <input
                            type="text"
                            value={key}
                            onChange={(e) => setKey(e.target.value)}
                            className="w-full bg-gray-900 border border-gray-700 rounded p-2 text-white focus:ring-primary focus:border-primary disabled:opacity-50"
                            placeholder="e.g., config/theme"
                            disabled={isLoading || isOffline}
                        />
                    </div>

                    <div>
                        <label className="block text-sm font-medium text-gray-300 mb-1">Value (for PUT)</label>
                        <textarea
                            value={value}
                            onChange={(e) => setValue(e.target.value)}
                            className="w-full bg-gray-900 border border-gray-700 rounded p-2 text-white font-mono text-sm focus:ring-primary focus:border-primary disabled:opacity-50"
                            rows={3}
                            placeholder='e.g., {"theme": "dark"}'
                            disabled={isLoading || isOffline}
                        />
                    </div>

                    <div>
                        <label className="block text-sm font-medium text-gray-300 mb-1">TTL (ms) (Optional, 0 = no expiration)</label>
                        <input
                            type="number"
                            value={ttlMs}
                            onChange={(e) => setTtlMs(e.target.value)}
                            className="w-full bg-gray-900 border border-gray-700 rounded p-2 text-white focus:ring-primary focus:border-primary disabled:opacity-50"
                            placeholder="0"
                            disabled={isLoading || isOffline}
                        />
                    </div>

                    <div className="flex space-x-3 pt-2">
                        <button
                            onClick={() => handleKmsOp('put')}
                            disabled={isLoading || isOffline || !key}
                            className="bg-primary hover:bg-primary-dark text-white font-medium py-2 px-4 rounded transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex-1"
                        >
                            Put
                        </button>
                        <button
                            onClick={() => handleKmsOp('get')}
                            disabled={isLoading || isOffline || !key}
                            className="bg-gray-700 hover:bg-gray-600 text-white font-medium py-2 px-4 rounded transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex-1"
                        >
                            Get
                        </button>
                        <button
                            onClick={() => handleKmsOp('delete')}
                            disabled={isLoading || isOffline || !key}
                            className="bg-red-900 hover:bg-red-800 text-white font-medium py-2 px-4 rounded transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex-1"
                        >
                            Delete
                        </button>
                    </div>
                </div>

                {error && (
                    <div className="mt-4 p-3 bg-red-900/40 border border-red-800 rounded text-red-200 text-sm">
                        {error}
                    </div>
                )}

                {response && (
                    <div className="mt-4">
                        <h3 className="text-sm font-medium text-gray-300 mb-2">Result:</h3>
                        <pre className="bg-gray-900 border border-gray-800 p-3 rounded text-sm text-gray-300 overflow-x-auto">
                            {JSON.stringify(response, null, 2)}
                        </pre>
                    </div>
                )}
            </div>
        </div>
    );
}
