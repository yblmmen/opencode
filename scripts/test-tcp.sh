#!/usr/bin/env bash
set -Eeuo pipefail
IP="${1:?사용법: bash scripts/test-tcp.sh 10.0.0.219}"
NODE_IP=$(kubectl get node master1 -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')
if [[ -z "$NODE_IP" ]]; then echo 'master1 IP 조회 실패'; exit 1; fi
printf '검색: %s / NodePort: %s:31800\n' "$IP" "$NODE_IP"
curl -fsS --get --data-urlencode "ip=$IP" --data-urlencode 'minutes=60' "http://${NODE_IP}:31800/api/tcp/connections" |
 python3 -c 'import sys,json;d=json.load(sys.stdin);print("관측 TCP 이벤트:",d["matching_events"]);print("연결 구간:",len(d["connections"]));[print(c["client_ip"],c["client_port"],"<->",c["server_ip"],c["server_port"],c["status"],"anchor:",c["anchor_id"]) for c in d["connections"][:10]]'
echo 'TCP 플래그는 v2 Collector가 실제 관측한 이벤트를 기준으로 표시됩니다.'
