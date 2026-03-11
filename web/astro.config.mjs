import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://pilotprotocol.network',
  build: {
    format: 'preserve',
  },
  trailingSlash: 'ignore',
});
