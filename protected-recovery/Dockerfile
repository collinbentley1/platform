# The broker has no dependencies: one digest-pinned Bun runtime, the service,
# the canonical workflow-authority manifest and parser it derives every target
# from, and the fixed-resource coordinates. Build from the repository root.
FROM docker.io/oven/bun@sha256:8aac45197595035f697ea6b11cd73ce2401d82503fcb2540b5fac606973b242b

WORKDIR /app
COPY tools/ci/workflow-authority.ts tools/ci/workflow-authority.ts
COPY terraform/modules/bootstrap/workflow-authority.json terraform/modules/bootstrap/workflow-authority.json
COPY protected-recovery/authority.json protected-recovery/package.json protected-recovery/
COPY protected-recovery/src protected-recovery/src

USER bun
ENV PORT=8080
EXPOSE 8080
CMD ["bun", "run", "--no-env-file", "protected-recovery/src/http.ts"]
