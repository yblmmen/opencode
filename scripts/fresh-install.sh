#!/usr/bin/env bash
# New deployment only; refuses to overwrite an existing namespace or installation.
set -Eeuo pipefail
STAGING=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
[[ "$STAGING" == /root/opencode-v2 ]] || { echo '먼저 /root에 ZIP 압축 해제하십시오.' >&2; exit 1; }
[[ $(id -u) -eq 0 ]] || { echo 'root 권한 필요' >&2; exit 1; }
if kubectl get ns opencode >/dev/null 2>&1 || [[ -e /opt/opencode ]]; then
  echo '기존 설치 존재. 완전 초기화/재설치는 bash /root/opencode-v2/scripts/reinstall.sh 이용.' >&2
  exit 1
fi
mkdir -p /opt/opencode
cp -a "$STAGING/." /opt/opencode/
cd /opt/opencode
bash scripts/install.sh
bash scripts/install-cloudflare.sh
bash scripts/check.sh
