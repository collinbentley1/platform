#!/bin/bash
# Prove that the protected-recovery module's live Deny and service-state reads
# write no bearer into Terraform state. A minimal root configuration applies
# the exact credential-free readers (tools/ci/protected-recovery-deny-state.sh
# and tools/ci/protected-recovery-service-state.sh) through the exact pinned
# external provider, against a stub gcloud that mints a sentinel bearer and
# stub IAM and Service Usage endpoints that require it; the resulting state
# must carry the typed projections and must not carry the sentinel anywhere.
# The test runs entirely offline.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
module="$root/terraform/modules/protected-recovery"
sentinel="DAYBREAK_SENTINEL_DO_NOT_USE_$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"; kill "${server_pid:-}" 2> /dev/null || true' EXIT

# A stub gcloud: the credential the reader obtains internally.
mkdir -p "$work/bin"
cat > "$work/bin/gcloud" <<EOF
#!/bin/bash
if [ "\$1" = auth ] && [ "\$2" = application-default ] && [ "\$3" = print-access-token ]; then
  printf '%s\n' '$sentinel'
  exit 0
fi
echo "unexpected gcloud invocation: \$*" >&2
exit 1
EOF
chmod +x "$work/bin/gcloud"

# A stub IAM v2 endpoint that lists one deny policy, and a stub Service Usage endpoint that reports one
# disabled API, both serving only the sentinel bearer.
cat > "$work/server.ts" <<EOF
const sentinel = "$sentinel";
const attachment = "cloudresourcemanager.googleapis.com/projects/scan-test";
const name = "policies/" + encodeURIComponent(attachment) + "/denypolicies/scan";
const server = Bun.serve({
  hostname: "127.0.0.1",
  port: 0,
  fetch(request) {
    if (request.headers.get("authorization") !== "Bearer " + sentinel) return Response.json({ error: { status: "UNAUTHENTICATED" } }, { status: 401 });
    const path = new URL(request.url).pathname;
    if (path === "/v2/policies/" + encodeURIComponent(attachment) + "/denypolicies") return Response.json({ policies: [{ name, etag: "scan-etag" }] });
    if (path === "/v2/" + name) return Response.json({ name, etag: "scan-etag", rules: [{ denyRule: { deniedPrincipals: ["principalSet://goog/public:all"], deniedPermissions: ["iam.googleapis.com/roles.create"], exceptionPrincipals: [] } }] });
    if (path === "/v1/projects/scan-test/services/compute.googleapis.com") return Response.json({ name: "projects/scan-test/services/compute.googleapis.com", state: "DISABLED" });
    return Response.json({ error: { status: "NOT_FOUND" } }, { status: 404 });
  },
});
console.log(server.port);
await new Promise(() => {});
EOF
bun --no-env-file run "$work/server.ts" > "$work/port" 2> "$work/server.log" &
server_pid=$!
for _ in $(seq 1 50); do
  [ -s "$work/port" ] && break
  sleep 0.1
done
port="$(head -n 1 "$work/port")"
[[ "$port" =~ ^[0-9]+$ ]] || { cat "$work/server.log" >&2; echo "the stub IAM endpoint did not start" >&2; exit 1; }

# The minimal root: the exact readers through the exact pinned external
# provider, whose lock entry is the module's own.
mkdir -p "$work/root"
awk '/^provider "registry.terraform.io\/hashicorp\/external" \{/ { keep = 1 } keep { print } keep && /^\}/ { exit }' "$module/.terraform.lock.hcl" > "$work/root/.terraform.lock.hcl"
grep -q 'version     = "2.3.5"' "$work/root/.terraform.lock.hcl"
cat > "$work/root/main.tf" <<EOF
terraform {
  required_version = "~> 1.14.0"
  required_providers {
    external = {
      source  = "hashicorp/external"
      version = "= 2.3.5"
    }
  }
}

data "external" "deny_state" {
  program = ["bash", "$root/tools/ci/protected-recovery-deny-state.sh"]
  query = {
    attachment = "cloudresourcemanager.googleapis.com/projects/scan-test"
  }
}

data "external" "service_state" {
  program = ["bash", "$root/tools/ci/protected-recovery-service-state.sh"]
  query = {
    project = "scan-test"
    service = "compute.googleapis.com"
  }
}

output "policies" {
  value = jsondecode(data.external.deny_state.result.policies)
}

output "status" {
  value = data.external.deny_state.result.status
}

output "service_state" {
  value = data.external.service_state.result.state
}
EOF
export PATH="$work/bin:$PATH" PROTECTED_RECOVERY_IAM_ENDPOINT="http://127.0.0.1:${port}" PROTECTED_RECOVERY_SERVICEUSAGE_ENDPOINT="http://127.0.0.1:${port}"
terraform -chdir="$work/root" init -backend=false -input=false -lockfile=readonly -no-color > "$work/init.log"
terraform -chdir="$work/root" apply -input=false -auto-approve -no-color > "$work/apply.log"
test "$(terraform -chdir="$work/root" output -raw status)" = 200
test "$(terraform -chdir="$work/root" output -json policies | jq -r '.[0].etag')" = scan-etag
test "$(terraform -chdir="$work/root" output -json policies | jq -r '.[0].rules[0].deniedPermissions[0]')" = iam.googleapis.com/roles.create
test "$(terraform -chdir="$work/root" output -raw service_state)" = DISABLED
if grep -q -- "$sentinel" "$work/root/terraform.tfstate"; then
  echo "The sentinel bearer was written into terraform.tfstate." >&2
  exit 1
fi
if grep -qi "bearer" "$work/root/terraform.tfstate"; then
  echo "A bearer header was written into terraform.tfstate." >&2
  exit 1
fi
echo "state scan: the live Deny and service-state reads wrote their typed projections and no bearer into state (1 policy, status 200; compute.googleapis.com DISABLED)"
