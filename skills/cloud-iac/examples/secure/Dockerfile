# Pinned base, build secrets mounted at build time, non-root runtime user
FROM node:20.11.1-bookworm-slim AS build
WORKDIR /src
COPY package*.json ./
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm ci
COPY . .
RUN npm run build

FROM node:20.11.1-bookworm-slim@sha256:0000000000000000000000000000000000000000000000000000000000000000
ENV NODE_ENV=production
ARG API_TOKEN_FILE=/run/secrets/api_token
COPY --from=build --chown=10001:10001 /src/dist /app
USER 10001
CMD ["node", "/app/server.js"]
