import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  transpilePackages: [
    "@warden/brand",
    "@warden/policy-schema",
    "@warden/detectors",
    "@warden/eval",
  ],
};

export default nextConfig;