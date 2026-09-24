// @ts-check
import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';

// The canonical origin is pinned to the production Pages URL for this MVP.
// When a custom domain is attached later, change `site` (canonical/OG/sitemap
// all read from it) and redeploy.
export default defineConfig({
  site: 'https://localcertkit.pages.dev',
  output: 'static',
  integrations: [sitemap()],
  trailingSlash: 'ignore',
  build: {
    format: 'directory',
  },
});
