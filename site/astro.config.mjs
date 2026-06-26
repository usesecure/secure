import { defineConfig } from "astro/config";
import sitemap from "@astrojs/sitemap";

export default defineConfig({
  site: "https://danielcadev.github.io",
  base: "/secure",
  integrations: [sitemap()],
  build: {
    format: "directory"
  }
});
