#!/usr/bin/env bash
# Optional GitHub publish: repository history preserved. Source package default; --include-runtime explicit.
set -Eeuo pipefail
ROOT=/opt/opencode
DEST=/root/opencode-github-publish
REPO=https://github.com/yblmmen/opencode.git
[[ "${1:-}" == '' || "${1:-}" == '--include-runtime' ]] || { echo 'Usage: bash scripts/github-push.sh [--include-runtime]' >&2; exit 2; }
for bin in git rsync; do command -v "$bin" >/dev/null || { echo "필수 명령어: $bin" >&2; exit 1; }; done
cd /root
# First clone preserves existing GitHub main history; never git init on top of the remote.
if [[ ! -d "$DEST/.git" ]]; then git clone --branch main "$REPO" "$DEST"; fi
git -C "$DEST" pull --ff-only origin main
RSYNC_ARGS=(--archive --delete --exclude=/.git/ --exclude=/CLI-Anything/.git/ --exclude='*.zip' --exclude='__pycache__/')
if [[ "${1:-}" != '--include-runtime' ]]; then
  RSYNC_ARGS+=(--exclude=/config/ --exclude=/data/ --exclude=/secrets/ --exclude=/dashboard-data/ --exclude=/prometheus-data/ --exclude=/grafana-data/)
  echo '소스 및 설정 템플릿만 업로드. 전체 런타임 포함은 --include-runtime 명시.'
fi
rsync "${RSYNC_ARGS[@]}" "$ROOT/" "$DEST/"
git -C "$DEST" add -f -A
if ! git -C "$DEST" diff --cached --quiet; then
  git -C "$DEST" commit -m "Clean OpenCode Hubble v2 $(date +%Y-%m-%d_%H-%M)"
fi
git -C "$DEST" push origin main
