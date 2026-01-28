'use client';

import { FC } from 'react';

interface OracleDemoProps {
    loading: boolean;
    connected: boolean;
    cronInfo?: {
        last_run?: string;
        counter?: number;
    };
    onUpdateNow: () => void;
    onRefreshStats: () => void;
}

/**
 * Oracle demo panel - ETH/USD price oracle with on-chain updates.
 */
export const OracleDemo: FC<OracleDemoProps> = ({
    loading,
    connected,
    cronInfo,
    onUpdateNow,
    onRefreshStats,
}) => {
    return (
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
                    onClick={onUpdateNow}
                    disabled={loading || !connected}
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
                        {cronInfo?.last_run
                            ? new Date(cronInfo.last_run).toLocaleTimeString()
                            : 'Awaiting sync...'}
                    </span>
                </div>
                <div className="bg-slate-50 p-4 rounded-xl border border-slate-200">
                    <label className="text-xs text-slate-500 block mb-1">Background Runner Status</label>
                    <div className="flex items-center gap-2">
                        <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                        <span className="text-xs text-slate-600">
                            Worker active • {cronInfo?.counter || 0} tasks completed
                        </span>
                    </div>
                </div>
            </div>

            <button
                onClick={onRefreshStats}
                disabled={loading || !connected}
                className="w-full py-3 border border-slate-200 rounded-xl text-sm font-medium hover:bg-slate-50 transition disabled:opacity-50"
            >
                Refresh Background Job Stats
            </button>
        </div>
    );
};

export default OracleDemo;
