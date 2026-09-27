# syntax=docker/dockerfile:1.4

# ==============================================================================
# Stage 1: Build & Compile TypeScript
# ==============================================================================
FROM node:20-alpine AS builder

WORKDIR /app

# Copy root workspace configurations and package definitions
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/shared/package.json ./packages/shared/
COPY services/ai-analyzer/package.json ./services/ai-analyzer/
COPY apps/worker/package.json ./apps/worker/

# Install build dependencies across all needed workspaces
RUN npm ci --workspace @aishield/shared --workspace @aishield/ai-analyzer --workspace @aishield/worker

# Copy source files
COPY packages/shared/ ./packages/shared/
COPY services/ai-analyzer/ ./services/ai-analyzer/
COPY apps/worker/ ./apps/worker/

# Compile packages in dependency order
RUN npm run build:shared && \
    npm run build --workspace @aishield/ai-analyzer && \
    npm run build --workspace @aishield/worker

# ==============================================================================
# Stage 2: Minimal Production Runtime
# ==============================================================================
FROM node:20-alpine AS runner

WORKDIR /app

# Install tini for graceful PID 1 signal management, git and docker-cli for scanner execution
RUN apk add --no-cache tini git docker-cli

ENV NODE_ENV=production \
    SCANNER_WORK_DIR=/tmp/aishield-scans

# Create scanner work directory with proper ownership for non-root user
RUN mkdir -p /tmp/aishield-scans && chown -R node:node /tmp/aishield-scans

# Copy root package metadata and compiled distribution artifacts
COPY package.json package-lock.json ./
COPY packages/shared/package.json ./packages/shared/
COPY --from=builder /app/packages/shared/dist ./packages/shared/dist
COPY services/ai-analyzer/package.json ./services/ai-analyzer/
COPY --from=builder /app/services/ai-analyzer/dist ./services/ai-analyzer/dist
COPY apps/worker/package.json ./apps/worker/
COPY --from=builder /app/apps/worker/dist ./apps/worker/dist

# Install production dependencies only
RUN npm ci --omit=dev --workspace @aishield/shared --workspace @aishield/ai-analyzer --workspace @aishield/worker && \
    npm cache clean --force

# Run as non-root user
USER node

# Graceful termination handling with tini
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "apps/worker/dist/index.js"]
