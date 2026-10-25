#!/usr/bin/env bash
# Read-only operational verification after clean v2 installation.
set -u
printf '\n[1/5] Nodes and namespace\n'
kubectl get nodes -o wide
kubectl -n opencode get pods,deploy,svc -o wide
printf '\n[2/5] Hubble Relay and Collector\n'
kubectl -n kube-system get svc hubble-relay || true
kubectl -n opencode logs deploy/hubble-collector --tail=35 || true
printf '\n[3/5] Dashboard data from master1 NodePort 31800\n'
NODE_IP=$(kubectl get node master1 -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')
if command -v curl >/dev/null; then
  curl -fsS --max-time 12 "http://${NODE_IP}:31800/api/summary?minutes=5" | python3 -c 'import sys,json; d=json.load(sys.stdin);print("flow events last5m:",d["metrics"]["total"]);print("collector:",json.dumps(d.get("collector"),ensure_ascii=False))' || echo '대시보드 API 확인 필요'
  printf '\n[4/5] Dashboard metrics\n'
  curl -fsS --max-time 12 "http://${NODE_IP}:31800/metrics" | grep '^opencode_hubble_collector_connected\|^opencode_hubble_flow_events_last5m' || true
else echo 'curl 명령이 필요합니다.'; fi
printf '\n[5/5] Cloudflare logs, GitHub, external DNS\n'
kubectl -n opencode logs deploy/cloudflared --tail=20 2>/dev/null || echo 'cloudflared 미배포 또는 초기화됨'
printf '외부: https://dash.innerinfo.org / NodePort: %s:31800\n' "$NODE_IP"
printf 'Hubble 이벤트가 0이고 Collector connected=0 이면 Relay 접근/로그를 확인하십시오.\n'

if [[ -n "${TCP_TEST_IP:-}" ]]; then
  printf '
[TCP Lifecycle] IP %s 검색 API 확인
' "$TCP_TEST_IP"
  curl -fsS --get --data-urlencode "ip=$TCP_TEST_IP" --data-urlencode 'minutes=15' "http://${NODE_IP}:31800/api/tcp/connections" |
    python3 -c 'import json,sys;d=json.load(sys.stdin);print("connections:",len(d.get("connections",[])),"observed events:",d.get("matching_events",0))' || echo 'TCP 연결 조회 API 오류'
fi

printf '\n[Grafana NodePort 31300]\n'
curl -fsS --max-time 10 "http://${NODE_IP}:31300/api/health" || echo 'Grafana 31300 확인 필요'
printf '\n[Collector auth]\n'
kubectl -n opencode logs deployment/hubble-collector --tail=30 | grep -E 'Hubble Relay connected|Posted events:|Post failed|heartbeat failed|restart' || true
