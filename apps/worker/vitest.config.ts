import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    name: 'worker',
    environment: 'node',
    include: ['src/**/*.test.ts'],
    exclude: ['dist/**', 'node_modules/**'],
    env: {
      NODE_ENV: 'test',
      LOG_LEVEL: 'silent',
      MONGO_URI: 'mongodb://127.0.0.1:27017/aishield-test',
      REDIS_URL: 'redis://127.0.0.1:6379/15',
    },
  },
});
