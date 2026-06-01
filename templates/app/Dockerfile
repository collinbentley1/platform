# syntax=docker/dockerfile:1

FROM dhi.io/bun:1 AS build
WORKDIR /app
RUN bun upgrade --canary
COPY package.json bun.lock bunfig.toml tsconfig.json ./
COPY src ./src
COPY tools ./tools
RUN bun install --frozen-lockfile
RUN bun run build

FROM dhi.io/bun:1 AS runtime
WORKDIR /app
RUN bun upgrade --canary
COPY --from=build /app/dist ./dist
ENV NODE_ENV=production
EXPOSE 8080
CMD ["bun", "dist/server.js"]
