import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    name: 'api',
    environment: 'node',
    include: ['src/**/*.test.ts'],
    // Deterministic, hermetic configuration: never read the developer's .env
    // for the values that matter, and never touch a real database or queue.
    env: {
      NODE_ENV: 'test',
      LOG_LEVEL: 'silent',
      MONGO_URI: 'mongodb://127.0.0.1:27017/aishield-test',
      REDIS_URL: 'redis://127.0.0.1:6379/15',
    },
  },
});
