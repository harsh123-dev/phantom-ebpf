# frontend Dockerfile
# Multi-stage build: Node builder + nginx static server.

FROM node:20-slim AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY src/ ./src/
COPY public/ ./public/
COPY tsconfig.json ./
RUN npm run build

FROM nginx:1.27-alpine AS runtime
LABEL org.opencontainers.image.title="PHANTOM frontend"
LABEL org.opencontainers.image.source="https://github.com/phantom-research/phantom"
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
