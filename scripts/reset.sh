#!/usr/bin/env bash
# v2-only destructive reset: backup, scale to zero, delete opencode namespace, remove /opt/opencode
set -Eeuo pipefail
ROOT=/opt/opencode
BACKUPS=/root/opencode-backups
STAGING=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
[[ $(id -u) -eq 0 ]] || { echo 'root 권한 필요'; exit 1; }
[[ "$STAGING" != "$ROOT" ]] || { echo '초기화는 /root/opencode-v2에서 실행해야 합니다.' >&2; exit 1; }
[[ "$STAGING" == /root/opencode-v2 ]] || { echo "예상 위치: /root/opencode-v2 (현재 $STAGING)" >&2; exit 1; }
command -v kubectl >/dev/null || { echo 'kubectl 명령어가 없습니다.'; exit 1; }
echo '==== OpenCode v2 RESET ===='
echo '삭제: Kubernetes namespace/opencode 전체, /opt/opencode, 전용 로컬 이미지(가능한 경우)'
echo '보존: /home/toss, kube-system Cilium/Hubble, Cloudflare 웹 설정, /root/opencode-v2, /root/opencode-backups'
read -r -p '확인하려면 DELETE OPENCODE V2 입력: ' ANSWER
[[ "$ANSWER" == 'DELETE OPENCODE V2' ]] || { echo '취소'; exit 1; }
# Stop standalone OpenCode Docker containers before backup; do not touch other containers.
if command -v docker >/dev/null; then
  mapfile -t STANDALONE < <(docker ps --format '{{.ID}} {{.Image}}' | awk '$2 ~ /^local\/opencode:/ {print $1}')
  if ((${#STANDALONE[@]})); then docker stop "${STANDALONE[@]}"; docker rm "${STANDALONE[@]}" || true; fi
fi
if kubectl get namespace opencode >/dev/null 2>&1; then
  echo '[1/4] Scale down workloads to stop database writes'
  mapfile -t DEPLOYS < <(kubectl -n opencode get deploy -o name)
  if ((${#DEPLOYS[@]})); then kubectl -n opencode scale "${DEPLOYS[@]}" --replicas=0; fi
  for i in {1..90}; do
    PODS=$(kubectl -n opencode get pods -o name 2>/dev/null || true)
    [[ -z "$PODS" ]] && break
    sleep 2
  done
  [[ -z "$(kubectl -n opencode get pods -o name 2>/dev/null || true)" ]] || { echo 'Pod가 완전히 종료되지 않아 백업/삭제 중단' >&2; exit 1; }
fi
mkdir -p "$BACKUPS"
if [[ -d "$ROOT" ]]; then
  echo '[2/4] Full backup of /opt/opencode'
  STAMP=$(date +%Y%m%d-%H%M%S)
  ARCHIVE="$BACKUPS/opencode-before-v2-$STAMP.tar.gz"
  umask 077
  tar -C /opt -czf "$ARCHIVE" opencode
  tar -tzf "$ARCHIVE" >/dev/null
  echo "BACKUP: $ARCHIVE"
fi
if kubectl get namespace opencode >/dev/null 2>&1; then
  echo '[3/4] Delete opencode namespace; Cilium/Hubble untouched'
  kubectl delete namespace opencode --wait=true --timeout=300s
fi
echo '[4/4] Remove old source/runtime directories'
[[ "$ROOT" == /opt/opencode ]] || exit 1
rm -rf -- "$ROOT"
# Remove local images for this project on master1 only; ignore if in use or not present.
if command -v docker >/dev/null; then
  while IFS= read -r image; do
    [[ -n "$image" ]] && docker image rm "$image" >/dev/null 2>&1 || true
  done < <(docker images --format '{{.Repository}}:{{.Tag}}' | grep -E '^local/(opencode|https-dashboard|hubble-collector|lifecycle-grafana):' || true)
fi
if command -v ctr >/dev/null; then
  while IFS= read -r image; do
    [[ -n "$image" ]] && ctr -n k8s.io images rm "$image" >/dev/null 2>&1 || true
  done < <(ctr -n k8s.io images ls -q | grep -E '^local/(opencode|https-dashboard|hubble-collector|lifecycle-grafana):' || true)
fi
echo 'RESET 완료. /root/opencode-v2/scripts/reinstall.sh 로 신규 설치하십시오.'
