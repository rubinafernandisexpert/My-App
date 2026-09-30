# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# Brio — production image
#   docker build -t brio:1.0.0 .
#   docker run -p 8080:8080 -e SESSION_SECRET=$(openssl rand -hex 32) brio:1.0.0
# ---------------------------------------------------------------------------
FROM node:20-alpine

ENV NODE_ENV=production \
    PORT=8080 \
    DB_FILE=/app/data/db.json

WORKDIR /app

# Dependencies first so the layer caches across code edits.
COPY package*.json ./
RUN npm ci --omit=dev || npm install --omit=dev

# Application code
COPY . .

# Build the catalog index and seed the demo account (both idempotent)
RUN node scripts/build-catalog.js && node scripts/seed.js

RUN mkdir -p /app/data && chown -R node:node /app
USER node

EXPOSE 8080
VOLUME ["/app/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1

CMD ["node", "server/index.js"]
