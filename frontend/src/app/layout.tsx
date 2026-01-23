import './globals.css';
import type { Metadata } from 'next';

export const metadata: Metadata = {
    title: 'Nova App Template',
    description: 'A production-ready template for building verified TEE applications',
};

export default function RootLayout({
    children,
}: {
    children: React.ReactNode;
}) {
    return (
        <html lang="en">
            <body>{children}</body>
        </html>
    );
}
