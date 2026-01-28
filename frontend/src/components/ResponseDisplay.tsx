'use client';

import { FC } from 'react';
import { txLink } from './StatusPanel';

interface ApiResponse {
    success: boolean;
    data?: any;
    error?: string;
    type?: string;
}

interface ResponseDisplayProps {
    response: ApiResponse | null;
    loading: boolean;
    syntaxHighlight: (json: string) => string;
}

/**
 * Display API response with syntax highlighting and anchor transaction details.
 */
export const ResponseDisplay: FC<ResponseDisplayProps> = ({ response, loading, syntaxHighlight }) => {
    if (loading) {
        return (
            <div className="mt-6 bg-slate-50 rounded-xl p-6 border border-slate-200">
                <div className="flex items-center gap-3">
                    <div className="w-5 h-5 border-2 border-slate-300 border-t-blue-500 rounded-full animate-spin" />
                    <span className="text-slate-600">Processing request...</span>
                </div>
            </div>
        );
    }

    if (!response) return null;

    const { success, data, error, type } = response;

    return (
        <div className={`mt-6 rounded-xl border ${success ? 'bg-emerald-50 border-emerald-200' : 'bg-red-50 border-red-200'} p-4`}>
            <div className="flex items-center gap-2 mb-3">
                <span className={`text-lg ${success ? 'text-emerald-600' : 'text-red-600'}`}>
                    {success ? '✓' : '✗'}
                </span>
                <span className={`font-semibold ${success ? 'text-emerald-700' : 'text-red-700'}`}>
                    {type || (success ? 'Success' : 'Error')}
                </span>
            </div>

            {error && (
                <div className="bg-white/50 rounded-lg p-3 mb-3">
                    <p className="text-red-700 text-sm">{error}</p>
                </div>
            )}

            {data && (
                <div className="space-y-4">
                    {/* Anchor Transaction */}
                    {data.anchor_tx && (
                        <div className="bg-white border border-slate-200 rounded-xl p-3">
                            <p className="text-slate-500 text-xs mb-1">Anchor Transaction</p>
                            {data.anchor_tx.transaction_hash ? (
                                <a
                                    href={txLink(data.anchor_tx.transaction_hash)}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-blue-600 hover:text-blue-800 hover:underline break-all text-sm"
                                >
                                    {data.anchor_tx.transaction_hash}
                                </a>
                            ) : (
                                <code className="text-slate-500">—</code>
                            )}
                            {data.anchor_tx.broadcasted !== undefined && (
                                <span className={`ml-2 text-xs ${data.anchor_tx.broadcasted ? 'text-emerald-600' : 'text-slate-500'}`}>
                                    {data.anchor_tx.broadcasted ? '(broadcasted)' : '(not broadcasted)'}
                                </span>
                            )}
                        </div>
                    )}

                    {/* Anchor Error */}
                    {data.anchor_error && (
                        <div className="bg-red-50 border border-red-200 rounded-xl p-3">
                            <p className="text-red-700 font-semibold text-sm">✗ Anchor Failed</p>
                            <p className="text-red-600 text-sm mt-1">{data.anchor_error}</p>
                            {data.error_type && (
                                <p className="text-red-500 text-xs mt-1">Error Type: {data.error_type}</p>
                            )}
                        </div>
                    )}

                    {/* Generic JSON display */}
                    <div className="bg-white border border-slate-200 rounded-xl p-3">
                        <p className="text-slate-500 text-xs mb-2">Response Data</p>
                        <pre
                            className="text-xs font-mono whitespace-pre-wrap break-words text-slate-700 max-h-64 overflow-auto"
                            dangerouslySetInnerHTML={{ __html: syntaxHighlight(JSON.stringify(data, null, 2)) }}
                        />
                    </div>
                </div>
            )}
        </div>
    );
};

export default ResponseDisplay;
