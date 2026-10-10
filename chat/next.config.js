const dev = process.env.NODE_ENV !== "production";
const { version } = await import("./package.json", { with: { type: "json" } }).then((m) => m.default);

const nextConfig = {
  env: { APP_VERSION: version },
  images: { unoptimized: true },
  poweredByHeader: false,
  reactStrictMode: true,
  agentRules: false,
  compress: true,
  productionBrowserSourceMaps: false,
  async headers() {
    const base = [
      { key: "X-Frame-Options", value: "DENY" },
      { key: "X-Content-Type-Options", value: "nosniff" },
      { key: "Referrer-Policy", value: "no-referrer" },
      { key: "Permissions-Policy", value: "geolocation=(), camera=(), microphone=(), payment=(), usb=(), interest-cohort=()" },
      { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
      { key: "Cross-Origin-Resource-Policy", value: "same-origin" },
      { key: "X-DNS-Prefetch-Control", value: "off" },
      { key: "X-Permitted-Cross-Domain-Policies", value: "none" }
    ];
    const secure = [{ key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" }];
    return [
      { source: "/:path*", headers: dev ? base : [...base, ...secure] },
      { source: "/api/:path*", headers: [{ key: "Cache-Control", value: "no-store" }] },
      {
        source: "/api/v1/events",
        headers: [
          { key: "Cache-Control", value: "no-store, no-transform" },
          { key: "X-Accel-Buffering", value: "no" }
        ]
      }
    ];
  }
};

export default nextConfig;