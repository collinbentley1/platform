# syntax=docker/dockerfile:1

FROM dhi.io/bun:1 AS build
WORKDIR /app
RUN bun upgrade --stable
RUN bun -e 'if (!Bun.version.startsWith("1.4.")) throw new Error("Bun 1.4 native image requires Bun 1.4.x, got " + Bun.version)'
COPY package.json bun.lock bunfig.toml tsconfig.json ./
COPY src ./src
COPY tools ./tools
RUN bun install --frozen-lockfile
RUN bun run build

FROM dhi.io/bun:1 AS runtime
WORKDIR /app
RUN bun upgrade --stable
RUN bun -e 'if (!Bun.version.startsWith("1.4.")) throw new Error("Bun 1.4 native image requires Bun 1.4.x, got " + Bun.version)'
COPY --from=build /app/dist ./dist
ENV NODE_ENV=production
EXPOSE 8080
CMD ["bun", "dist/server.js"]
