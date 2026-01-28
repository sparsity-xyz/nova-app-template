'use client';

import { FC } from 'react';

interface TabItem {
    id: string;
    label: string;
    icon: string;
}

interface TabNavigationProps {
    tabs: TabItem[];
    activeTab: string;
    onTabChange: (tabId: string) => void;
    disabled?: boolean;
}

/**
 * Horizontal tab navigation component.
 */
export const TabNavigation: FC<TabNavigationProps> = ({ tabs, activeTab, onTabChange, disabled }) => {
    return (
        <nav className="flex items-center justify-center flex-wrap gap-2 bg-slate-100 rounded-xl p-1.5">
            {tabs.map((tab) => (
                <button
                    key={tab.id}
                    onClick={() => onTabChange(tab.id)}
                    disabled={disabled}
                    className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${activeTab === tab.id
                            ? 'bg-white text-slate-900 shadow-sm'
                            : 'text-slate-600 hover:text-slate-900'
                        } disabled:opacity-50`}
                >
                    <span className="mr-1.5">{tab.icon}</span>
                    {tab.label}
                </button>
            ))}
        </nav>
    );
};

export default TabNavigation;
