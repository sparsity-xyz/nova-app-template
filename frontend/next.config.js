/** @type {import('next').NextConfig} */
const nextConfig = {
    output: 'export',
    basePath: '/frontend',
    trailingSlash: true,
    images: {
        unoptimized: true,
    },
};

module.exports = nextConfig;

