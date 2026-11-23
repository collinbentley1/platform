FROM --platform=$BUILDPLATFORM oven/bun:1.4.5@sha256:3aa040e5445efa09d75bb428a64ba50db13e2b3ac9b6b0c7f145615f62b2ee18 AS dependencies
WORKDIR /app
COPY package.json bun.lock bunfig.toml ./
RUN bun ci --no-env-file --ignore-scripts --registry=https://registry.npmjs.org

FROM dependencies AS build
COPY . .
RUN bun --no-env-file run verify:ci && mkdir -p /app/.local

FROM dependencies AS production-dependencies
ARG TARGETARCH
ARG TARGETOS
RUN if [ "$TARGETARCH" = "amd64" ]; then target_cpu=x64; else target_cpu="$TARGETARCH"; fi; rm -rf node_modules && bun ci --cpu="$target_cpu" --os="$TARGETOS" --production --no-env-file --ignore-scripts --registry=https://registry.npmjs.org

FROM oven/bun:1.4.5-distroless@sha256:3a210956422ad81cf7532e1fc1f2eb9275d6ef4c2337a9d25d530f798e80726a
WORKDIR /app
ENV NODE_ENV=production PORT=8080
COPY --from=production-dependencies --chown=1000:1000 /app/node_modules ./node_modules
COPY --from=production-dependencies --chown=1000:1000 /app/package.json /app/bun.lock ./
COPY --from=build --chown=1000:1000 /app/dist ./dist
COPY --from=build --chown=1000:1000 /app/.local ./.local
USER 1000:1000
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/bun"]
CMD ["--no-env-file", "dist/server.js"]
