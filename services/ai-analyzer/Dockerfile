FROM node:20-alpine AS builder

WORKDIR /app

# Copy root workspace manifests
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/shared/package.json ./packages/shared/
COPY services/ai-analyzer/package.json ./services/ai-analyzer/

# Install dependencies
RUN npm ci --workspace @aishield/shared --workspace @aishield/ai-analyzer

# Copy source
COPY packages/shared/ ./packages/shared/
COPY services/ai-analyzer/ ./services/ai-analyzer/

# Build
RUN npm run build:shared
RUN npm run build --workspace @aishield/ai-analyzer

FROM node:20-alpine AS runner

WORKDIR /app
ENV NODE_ENV=production

COPY package.json package-lock.json ./
COPY packages/shared/package.json ./packages/shared/
COPY packages/shared/dist ./packages/shared/dist
COPY services/ai-analyzer/package.json ./services/ai-analyzer/
COPY services/ai-analyzer/dist ./services/ai-analyzer/dist

RUN npm ci --omit=dev --workspace @aishield/shared --workspace @aishield/ai-analyzer

USER node

CMD ["node", "services/ai-analyzer/dist/index.js"]
