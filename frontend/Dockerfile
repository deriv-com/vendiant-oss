# Frontend Dockerfile for Vendiant Next.js Application
# Pin to specific digest for security and reproducibility
FROM node:18-alpine@sha256:8d6421d663b4c28fd3ebc498332f249011d118945588d0a35cb9bc4b8ca09d9e AS base

# CVE-2025-15467: stack buffer overflow in CMS AuthEnvelopedData parsing (OpenSSL 3.x).
# Upgrade Alpine openssl packages to >= 3.3.6-r0 before application layers.
RUN apk update && apk upgrade --no-cache openssl libssl3 libcrypto3

# Metadata labels
LABEL maintainer="vendiant-team"
LABEL version="1.0"
LABEL description="Vendiant Security Scanning Frontend"
LABEL org.opencontainers.image.source="https://github.com/your-org/vendiant"

# Install dependencies only when needed
FROM base AS deps
# Check https://github.com/nodejs/docker-node/tree/b4117f9333da4138b03a546ec926ef50a31506c3#nodealpine to understand why libc6-compat might be needed.
RUN apk add --no-cache libc6-compat
WORKDIR /app

# Install dependencies based on the preferred package manager
COPY package.json package-lock.json* ./
RUN npm ci

# Development server (used by docker-compose.dev.yml; not part of the
# production image, which is built from the final stage)
FROM deps AS dev
# curl for the compose healthcheck
RUN apk add --no-cache curl
# Run next dev as the image's unprivileged node user (VND-009): it only needs
# to write .next and next-env.d.ts, so own the app dir, not node_modules.
COPY --chown=node:node . .
RUN mkdir -p .next && chown node:node /app .next
USER node
ENV NODE_ENV=development
EXPOSE 3005
CMD ["npm", "run", "dev", "--", "-H", "0.0.0.0"]

# Rebuild the source code only when needed
FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Build-time args that Next.js bakes into the client bundle (NEXT_PUBLIC_*).
# Pass them with --build-arg (docker compose: build.args) to change the
# SSO group names or logout URL at build time.
ARG NEXT_PUBLIC_SSO_LOGOUT_URL=
ENV NEXT_PUBLIC_SSO_LOGOUT_URL=${NEXT_PUBLIC_SSO_LOGOUT_URL}
ARG NEXT_PUBLIC_SSO_GROUP_ADMIN=vendiant-admin
ENV NEXT_PUBLIC_SSO_GROUP_ADMIN=${NEXT_PUBLIC_SSO_GROUP_ADMIN}
ARG NEXT_PUBLIC_SSO_GROUP_VENDOR_MANAGEMENT=vendiant-vendor-management
ENV NEXT_PUBLIC_SSO_GROUP_VENDOR_MANAGEMENT=${NEXT_PUBLIC_SSO_GROUP_VENDOR_MANAGEMENT}
ARG NEXT_PUBLIC_SSO_GROUP_USER=vendiant-user
ENV NEXT_PUBLIC_SSO_GROUP_USER=${NEXT_PUBLIC_SSO_GROUP_USER}
ARG NEXT_PUBLIC_SSO_GROUP_VENDORS_ONLY=vendiant-vendors-only
ENV NEXT_PUBLIC_SSO_GROUP_VENDORS_ONLY=${NEXT_PUBLIC_SSO_GROUP_VENDORS_ONLY}

# Internal backend URL (docker compose service name).
ARG INTERNAL_API_URL_PRODUCTION=http://backend:5005
ENV INTERNAL_API_URL_PRODUCTION=${INTERNAL_API_URL_PRODUCTION}

# Next.js collects completely anonymous telemetry data about general usage.
# Learn more here: https://nextjs.org/telemetry
# Uncomment the following line in case you want to disable telemetry during the build.
ENV NEXT_TELEMETRY_DISABLED 1

RUN npm run build

# Production image, copy all the files and run next
FROM base AS runner
WORKDIR /app

ENV NODE_ENV production
# Uncomment the following line in case you want to disable telemetry during runtime.
ENV NEXT_TELEMETRY_DISABLED=1

# Install curl for health checks
RUN apk add --no-cache curl

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

# Set the correct permission for prerender cache
RUN mkdir .next
RUN chown nextjs:nodejs .next

# Automatically leverage output traces to reduce image size
# https://nextjs.org/docs/advanced-features/output-file-tracing
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

# Copy public folder for static assets (favicon, images, etc.)
COPY --from=builder --chown=nextjs:nodejs /app/public ./public

USER nextjs

EXPOSE 3005

ENV PORT=3005
ENV HOSTNAME="0.0.0.0"

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:3005/api/health || exit 1

# server.js is created by next build from the standalone output
# https://nextjs.org/docs/pages/api-reference/next-config-js/output
CMD ["node", "server.js"] 