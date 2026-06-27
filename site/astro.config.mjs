import { defineConfig } from "astro/config";
import sitemap from "@astrojs/sitemap";

const isVercel = process.env.VERCEL === "1";
const site = process.env.PUBLIC_SITE_URL
  ?? (isVercel && process.env.VERCEL_PROJECT_PRODUCTION_URL
    ? `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}`
    : "https://danielcadev.github.io");

export default defineConfig({
  site,
  base: isVercel ? "/" : "/secure",
  integrations: [sitemap()],
  build: {
    format: "directory"
  }
});
