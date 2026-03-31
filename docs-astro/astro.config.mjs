// @ts-check
import { defineConfig } from 'astro/config';
import mdx from '@astrojs/mdx';
import cloudflare from '@astrojs/cloudflare';

export default defineConfig({
  integrations: [mdx()],
  adapter: cloudflare({
    imageService: 'compile',
  }),
  site: 'https://qu-ira.com',
  server: { port: 8903 },
  markdown: {
    shikiConfig: {
      theme: 'github-dark',
    },
  },
});
