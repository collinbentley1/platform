#!/bin/bash

set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: fetch-exact-platform.sh DESTINATION" >&2
  exit 64
fi

destination="$1"
repository="${WORKFLOW_REPOSITORY:-}"
revision="${WORKFLOW_SHA:-}"

if [ "$repository" != "collinbentley1/platform" ] ||
   [[ ! "$revision" =~ ^[0-9a-f]{40}$ ]]; then
  echo "Refusing an untrusted reusable-workflow source." >&2
  exit 1
fi
if [ -z "${RUNNER_TEMP:-}" ] || [[ "$destination" != "$RUNNER_TEMP"/* ]] ||
   [ -e "$destination" ] || [ -L "$destination" ]; then
  echo "Refusing an unsafe exact-platform destination." >&2
  exit 1
fi

git_home="$RUNNER_TEMP/platform-git-home"
if [ -e "$git_home" ] || [ -L "$git_home" ]; then
  echo "Refusing a pre-existing Git isolation directory." >&2
  exit 1
fi
install -d -m 0700 "$git_home" "$destination"

export GIT_CONFIG_NOSYSTEM=1
export XDG_CONFIG_HOME="$git_home"
export PATH=/usr/bin:/bin
export GIT_CONFIG_GLOBAL=/dev/null
unset BASH_ENV CDPATH ENV GLOBIGNORE GIT_CONFIG_SYSTEM
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY
unset GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_CEILING_DIRECTORIES
unset GIT_SSH GIT_SSH_COMMAND GIT_ASKPASS SSH_ASKPASS

git_safe() {
  /usr/bin/git \
    -c core.fsmonitor=false \
    -c core.hooksPath=/dev/null \
    -c core.pager=cat \
    -c credential.helper= \
    -c diff.external= \
    -c filter.lfs.process= \
    -c filter.lfs.required=false \
    -c protocol.ext.allow=never \
    -c protocol.file.allow=never \
    -c submodule.recurse=false \
    "$@"
}

git_safe -C "$destination" init --quiet
git_safe -C "$destination" remote add origin "https://github.com/${repository}.git"
git_safe -C "$destination" fetch --quiet --depth=1 --no-tags origin "$revision"
git_safe -C "$destination" checkout --quiet --detach FETCH_HEAD

test "$(git_safe -C "$destination" rev-parse --verify HEAD^{commit})" = "$revision"
test "$(git_safe -C "$destination" status --porcelain=v1 --untracked-files=all)" = ""
for path in \
  tools/ci/container-artifact-contract.sh \
  tools/ci/grype-blocking.jq \
  tools/ci/grype-db.json \
  tools/ci/grype.yaml \
  tools/ci/syft.yaml \
  tools/ci/trust/docker-dhi-community-20260822.pub; do
  case "$(git_safe -C "$destination" ls-tree "$revision" -- "$path")" in
    100644\ blob\ *$'\t'"$path"|100755\ blob\ *$'\t'"$path") ;;
    *) echo "Trusted container policy path is missing or not a regular Git blob: $path" >&2; exit 1 ;;
  esac
  test -f "$destination/$path" && test ! -L "$destination/$path"
  expected_blob="$(git_safe -C "$destination" rev-parse "$revision:$path")"
  actual_blob="$(git_safe -C "$destination" hash-object --no-filters "$destination/$path")"
  test "$actual_blob" = "$expected_blob"
done

rm -rf -- "$git_home"
test ! -e "$git_home" && test ! -L "$git_home"
