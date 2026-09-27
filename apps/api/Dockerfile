# syntax=docker/dockerfile:1.4

# ==============================================================================
# Stage 1: Build & Compile TypeScript
# ==============================================================================
FROM node:20-alpine AS builder

WORKDIR /app

# Copy root workspace configurations and package definitions
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/shared/package.json ./packages/shared/
COPY apps/api/package.json ./apps/api/

# Install build dependencies across workspaces
RUN npm ci --workspace @aishield/shared --workspace @aishield/api

# Copy source files
COPY packages/shared/ ./packages/shared/
COPY apps/api/ ./apps/api/

# Compile packages in dependency order
RUN npm run build:shared && npm run build --workspace @aishield/api

# ==============================================================================
# Stage 2: Minimal Production Runtime
# ==============================================================================
FROM node:20-alpine AS runner

WORKDIR /app

# Install tini for graceful PID 1 signal management and wget for health checks
RUN apk add --no-cache tini wget

ENV NODE_ENV=production \
    PORT=4000

# Copy root package metadata and compiled distribution artifacts
COPY package.json package-lock.json ./
COPY packages/shared/package.json ./packages/shared/
COPY --from=builder /app/packages/shared/dist ./packages/shared/dist
COPY apps/api/package.json ./apps/api/
COPY --from=builder /app/apps/api/dist ./apps/api/dist

# Install production dependencies only
RUN npm ci --omit=dev --workspace @aishield/shared --workspace @aishield/api && \
    npm cache clean --force

# Run as non-root user
USER node

EXPOSE 4000

# Graceful termination handling with tini
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "apps/api/dist/index.js"]
