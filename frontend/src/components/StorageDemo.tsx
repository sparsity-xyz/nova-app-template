'use client';

import { FC } from 'react';

interface StorageDemoProps {
    loading: boolean;
    connected: boolean;
    storageKey: string;
    storageValue: string;
    onKeyChange: (key: string) => void;
    onValueChange: (value: string) => void;
    onStore: () => void;
    onRetrieve: () => void;
    onListKeys: () => void;
}

/**
 * S3 Storage demo panel - store and retrieve data with on-chain anchoring.
 */
export const StorageDemo: FC<StorageDemoProps> = ({
    loading,
    connected,
    storageKey,
    storageValue,
    onKeyChange,
    onValueChange,
    onStore,
    onRetrieve,
    onListKeys,
}) => {
    return (
        <div className="space-y-6">
            <h2 className="text-xl font-semibold mb-4">S3 Persistent Storage</h2>
            <p className="text-slate-600 text-sm leading-relaxed mb-6">
                Store and retrieve sensitive state in encrypted S3 objects. For <code className="bg-slate-100 px-1 rounded">user_settings</code> key,
                the value hash is anchored on-chain and verified on retrieval.
            </p>

            <div className="grid grid-cols-2 gap-4">
                <div className="flex flex-col gap-2">
                    <label className="text-sm text-slate-600">Key</label>
                    <input
                        className="bg-white border border-slate-300 rounded-lg px-4 py-2 outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-100"
                        value={storageKey}
                        onChange={(e) => onKeyChange(e.target.value)}
                    />
                </div>
                <div className="flex flex-col gap-2">
                    <label className="text-sm text-slate-600">Value (JSON/Text)</label>
                    <input
                        className="bg-white border border-slate-300 rounded-lg px-4 py-2 outline-none focus:border-emerald-500 focus:ring-2 focus:ring-emerald-100"
                        value={storageValue}
                        onChange={(e) => onValueChange(e.target.value)}
                    />
                </div>
            </div>

            <div className="flex gap-3">
                <button
                    onClick={onStore}
                    disabled={loading || !connected}
                    className="bg-emerald-600 hover:bg-emerald-500 text-white px-6 py-2 rounded-lg font-semibold shadow-sm flex-1 disabled:opacity-50"
                >
                    Store Value
                </button>
                <button
                    onClick={onRetrieve}
                    disabled={loading || !connected}
                    className="bg-slate-100 hover:bg-slate-200 text-slate-700 px-6 py-2 rounded-lg font-semibold flex-1 disabled:opacity-50"
                >
                    Retrieve Key
                </button>
            </div>

            <button
                onClick={onListKeys}
                className="text-sm text-slate-500 hover:text-slate-700"
            >
                List all stored keys...
            </button>
        </div>
    );
};

export default StorageDemo;
