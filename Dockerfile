# ===== Stage 1: Build dependencies =====
FROM node:22-alpine AS builder

WORKDIR /app

# Build tools needed for native modules (sqlite3, bcrypt)
RUN apk add --no-cache python3 make g++

COPY package*.json ./
RUN npm ci --omit=dev

# ===== Stage 2: Production runtime =====
FROM node:22-alpine

WORKDIR /app

# Remove npm/npx — reduce attack surface
RUN rm -rf /usr/local/lib/node_modules/npm \
    && rm -f /usr/local/bin/npm \
    && rm -f /usr/local/bin/npx

# Copy only production dependencies from builder
COPY --from=builder /app/node_modules ./node_modules

# Copy application code
COPY . .

# Run as non-root user
RUN chown -R node:node /app
USER node

EXPOSE 3000

CMD ["node", "app.js"]
