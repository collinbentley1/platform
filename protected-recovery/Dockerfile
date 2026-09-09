# The broker has no dependencies: one digest-pinned Bun runtime, the service,
# the canonical workflow-authority manifest and parser it derives every target
# from, and the fixed-resource coordinates. Build from the repository root.
FROM docker.io/oven/bun@sha256:d73746a3e6cd8de6d7abff1c4c678028b6fe25e0c39808f9a71214589fa8b023

WORKDIR /app
COPY tools/ci/workflow-authority.ts tools/ci/workflow-authority.ts
COPY terraform/modules/bootstrap/workflow-authority.json terraform/modules/bootstrap/workflow-authority.json
COPY protected-recovery/authority.json protected-recovery/package.json protected-recovery/
COPY protected-recovery/src protected-recovery/src

USER bun
ENV PORT=8080
EXPOSE 8080
CMD ["bun", "run", "--no-env-file", "protected-recovery/src/http.ts"]
