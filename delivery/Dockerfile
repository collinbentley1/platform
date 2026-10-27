FROM oven/bun:1.4.2@sha256:d888c0ae6c86d7866ff10c5aafdd9077b36aee6455b33dd270fb93c0dd5cef6f AS dependencies
WORKDIR /app
COPY package.json bun.lock bunfig.toml ./
RUN bun ci --no-env-file --ignore-scripts --registry=https://registry.npmjs.org

FROM dependencies AS build
COPY . .
RUN bun --no-env-file run verify:ci

FROM dependencies AS production-dependencies
RUN rm -rf node_modules && bun ci --production --no-env-file --ignore-scripts --registry=https://registry.npmjs.org

FROM oven/bun:1.4.2@sha256:d888c0ae6c86d7866ff10c5aafdd9077b36aee6455b33dd270fb93c0dd5cef6f
WORKDIR /app
ENV NODE_ENV=production PORT=8080
COPY --from=production-dependencies --chown=1000:1000 /app/node_modules ./node_modules
COPY --from=production-dependencies --chown=1000:1000 /app/package.json /app/bun.lock ./
COPY --from=build --chown=1000:1000 /app/dist ./
USER 1000:1000
EXPOSE 8080
CMD ["bun", "--no-env-file", "server.js"]
