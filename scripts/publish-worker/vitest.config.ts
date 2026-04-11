import { defineWorkersConfig } from '@cloudflare/vitest-pool-workers/config';

export default defineWorkersConfig({
  test: {
    poolOptions: {
      workers: {
        wrangler: { configPath: './wrangler.toml' },
        miniflare: {
          bindings: {
            PUBLISH_SECRET: 'test-publish-secret',
            GITHUB_TOKEN: 'ghp_test_token',
            GITHUB_OWNER: 'TeoSlayer',
            GITHUB_REPO: 'pilotprotocol',
          },
        },
      },
    },
  },
});
