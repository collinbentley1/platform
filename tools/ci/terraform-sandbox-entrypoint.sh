#!/bin/sh
set -eu

# The short-lived executor token arrives only over the container's attached
# stdin. It is never present in docker create argv/config or the host Docker
# client's environment. Consume the one-line bundle and close fd 0 before any
# Terraform or provider process starts.
IFS= read -r executor_token
case "$executor_token" in
  ''|*[!A-Za-z0-9._~-]*)
    echo "invalid protected executor token" >&2
    exit 64
    ;;
esac
[ "${#executor_token}" -ge 20 ] && [ "${#executor_token}" -le 4096 ] || {
  echo "invalid protected executor token length" >&2
  exit 64
}
exec 0<&-

terraform_version="$(/opt/terraform version | sed -n '1p')"
[ "$terraform_version" = "Terraform v1.14.5" ] || {
  echo "unexpected Terraform sandbox binary" >&2
  exit 70
}

exec /usr/bin/env -i \
  CHECKPOINT_DISABLE=1 \
  GIT_CONFIG_GLOBAL=/dev/null \
  GIT_CONFIG_NOSYSTEM=1 \
  GIT_TERMINAL_PROMPT=0 \
  GOOGLE_OAUTH_ACCESS_TOKEN="$executor_token" \
  HOME=/work/home \
  PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  TF_DATA_DIR=/work/tfdata \
  TF_IN_AUTOMATION=1 \
  /opt/terraform "$@"
