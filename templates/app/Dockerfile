# syntax=docker/dockerfile:1

FROM dhi.io/bun:1-dev AS deps
WORKDIR /app

RUN apt-get update \
  && apt-get install --no-install-recommends --yes curl unzip \
  && rm -rf /var/lib/apt/lists/* \
  && curl -fsSL https://bun.com/install | BUN_INSTALL=/usr/local bash -s "bun-v1.4.0"
RUN bun -e 'if (Bun.version !== "1.4.0") throw new Error("Bun 1.4 native image requires Bun 1.4.0, got " + Bun.version)'

COPY package.json bun.lock bunfig.toml tsconfig.json ./
RUN bun ci

FROM deps AS build
COPY src ./src
COPY test ./test
COPY tools ./tools
RUN bun run verify:ci

FROM dhi.io/bun:1 AS runtime
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=8080

COPY --from=deps /usr/local/bin/bun /usr/local/bin/bun
COPY --from=build /app/dist ./dist
RUN ["bun", "-e", "if (Bun.version !== \"1.4.0\") throw new Error(\"Bun 1.4 native image requires Bun 1.4.0, got \" + Bun.version)"]

EXPOSE 8080
CMD ["bun", "dist/server.js"]
