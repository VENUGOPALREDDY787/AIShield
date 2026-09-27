# syntax=docker/dockerfile:1.4

# ==============================================================================
# Stage 1: Build & Compile Web Dashboard SPA
# ==============================================================================
FROM node:20-alpine AS builder

WORKDIR /app

# Copy root workspace configurations and package definitions
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/shared/package.json ./packages/shared/
COPY apps/web/package.json ./apps/web/

# Install build dependencies
RUN npm ci --workspace @aishield/shared --workspace @aishield/web

# Copy source code
COPY packages/shared/ ./packages/shared/
COPY apps/web/ ./apps/web/

# Build shared package and Vite SPA bundle
RUN npm run build:shared && npm run build --workspace @aishield/web

# ==============================================================================
# Stage 2: Hardened Nginx Web Server
# ==============================================================================
FROM nginx:1.27-alpine AS runner

# Install wget/curl for container health checks
RUN apk add --no-cache wget

# Remove default configuration and copy custom hardened configuration
RUN rm -rf /etc/nginx/conf.d/default.conf
COPY apps/web/nginx.conf /etc/nginx/conf.d/default.conf

# Copy compiled static assets from builder stage
COPY --from=builder /app/apps/web/dist /usr/share/nginx/html

EXPOSE 80

# Run nginx in foreground with proper signal termination
STOPSIGNAL SIGQUIT

CMD ["nginx", "-g", "daemon off;"]
