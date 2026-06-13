import type { NextConfig } from "next";
import path from "node:path";

const nextConfig: NextConfig = {
  output: "export",
  // Pin the workspace root so Next/Turbopack does not mis-infer it from a
  // competing lockfile in a parent directory (that misinference 404s every
  // route in dev). This is the maintainer-recommended fix from the warning.
  turbopack: {
    root: path.resolve(__dirname),
  },
};

export default nextConfig;
