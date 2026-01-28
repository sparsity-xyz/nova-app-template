'use client';

import { FC } from 'react';

// Constants
export const BASESCAN_URL = 'https://sepolia.basescan.org';
export const addressLink = (addr: string) => `${BASESCAN_URL}/address/${addr}`;
export const txLink = (hash: string) => `${BASESCAN_URL}/tx/${hash}`;

interface StatusPanelProps {
    connected: boolean;
    teeAddress?: string;
    contractAddress?: string;
}

/**
 * Enclave Identity status panel - shows TEE wallet and contract addresses.
 */
export const StatusPanel: FC<StatusPanelProps> = ({ connected, teeAddress, contractAddress }) => {
    if (!connected) return null;

    return (
        <section className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
            <h2 className="text-xs font-semibold text-slate-500 uppercase tracking-[0.2em] mb-3">Enclave Identity</h2>
            <div className="space-y-4">
                <div>
                    <label className="text-xs text-slate-500 block mb-1">TEE Wallet Address</label>
                    {teeAddress ? (
                        <a
                            href={addressLink(teeAddress)}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-xs bg-slate-50 px-2 py-1 rounded block truncate border border-slate-200 text-blue-600 hover:text-blue-800 hover:underline"
                        >
                            {teeAddress}
                        </a>
                    ) : (
                        <code className="text-xs bg-slate-50 px-2 py-1 rounded block truncate border border-slate-200 text-slate-700">
                            Not available
                        </code>
                    )}
                </div>
                <div>
                    <label className="text-xs text-slate-500 block mb-1">App Contract Address</label>
                    {contractAddress ? (
                        <a
                            href={addressLink(contractAddress)}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-xs bg-slate-50 px-2 py-1 rounded block truncate border border-slate-200 text-blue-600 hover:text-blue-800 hover:underline"
                        >
                            {contractAddress}
                        </a>
                    ) : (
                        <code className="text-xs bg-slate-50 px-2 py-1 rounded block truncate border border-slate-200 text-slate-700">
                            Not configured
                        </code>
                    )}
                </div>
                <div className="flex gap-2 text-xs">
                    <span className="bg-emerald-50 text-emerald-700 px-2 py-0.5 rounded border border-emerald-200">Active</span>
                    <span className="bg-blue-50 text-blue-700 px-2 py-0.5 rounded border border-blue-200">Verifiable</span>
                </div>
            </div>
        </section>
    );
};

export default StatusPanel;
