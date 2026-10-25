#!/usr/bin/env bash
# One-command clean reinstall: calls reset, copies staged package, installs, then Cloudflare
set -Eeuo pipefail
STAGING=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
[[ "$STAGING" == /root/opencode-v2 ]] || { echo '압축 파일을 /root에 풀어 /root/opencode-v2에서 실행하십시오.' >&2; exit 1; }
[[ $(id -u) -eq 0 ]] || { echo 'root 권한 필요' >&2; exit 1; }
bash "$STAGING/scripts/reset.sh"
mkdir -p /opt/opencode
cp -a "$STAGING/." /opt/opencode/
cd /opt/opencode
bash scripts/install.sh
bash scripts/install-cloudflare.sh
bash scripts/check.sh
echo 'v2 재설치 완료. Cloudflare DNS/Published Route는 기존 설정 유지: dash.innerinfo.org -> http://192.168.9.221:31800'
