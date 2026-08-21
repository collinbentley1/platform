FROM oven/bun:1.4.0@sha256:5ff609364c049b54eb0ff560ec96319729a972078ef2c755d758f0c6ef89c2d6 AS bun-release

FROM dhi.io/bun:1-dev@sha256:67209598b7e7db266ae5630f9b27662d3a80b0915615bbcb9f703f562c5b5a52 AS deps
WORKDIR /app

COPY --from=bun-release /usr/local/bin/bun /usr/local/bin/bun
RUN bun -e 'if (Bun.version !== "1.4.0") throw new Error("Bun 1.4 native image requires Bun 1.4.0, got " + Bun.version)'

COPY package.json bun.lock bunfig.toml tsconfig.json ./
RUN --mount=type=secret,id=socket_api_token,required=true \
  SOCKET_API_KEY="$(cat /run/secrets/socket_api_token)"; export SOCKET_API_KEY; \
  test -n "$SOCKET_API_KEY"; \
  unset BUN_CONFIG_SKIP_LOAD_LOCKFILE BUN_FEATURE_FLAG_DISABLE_IGNORE_SCRIPTS BUN_CONFIG_REGISTRY NPM_CONFIG_REGISTRY; \
  if ! install_output="$(bun ci --no-env-file --ignore-scripts --registry=https://registry.npmjs.org 2>&1)"; then printf '%s\n' "$install_output"; exit 1; fi; \
  printf '%s\n' "$install_output"; \
  if printf '%s\n' "$install_output" | grep -Fq 'Socket Security Scanner free mode'; then echo 'Socket must enforce the owner-approved organization policy.' >&2; exit 1; fi

FROM deps AS build
COPY Dockerfile ./
COPY public ./public
COPY src ./src
COPY test ./test
COPY tools ./tools
RUN bun --no-env-file run verify:ci

FROM dhi.io/bun:1@sha256:3f3bcd8aeebefe5a4477ad5cd3a1a0154213c028f63a4d6ea84eeafe5dc69a38 AS runtime
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=8080
ENV PUBLIC_DIR=/app/dist/public

COPY --from=deps /usr/local/bin/bun /usr/local/bin/bun
COPY --from=build /app/dist ./dist
RUN ["bun", "-e", "if (Bun.version !== \"1.4.0\") throw new Error(\"Bun 1.4 native image requires Bun 1.4.0, got \" + Bun.version)"]

EXPOSE 8080
CMD ["bun", "dist/server.js"]
