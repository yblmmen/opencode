#!/usr/bin/env bash
set -Eeuo pipefail
set +x
cd /opt/opencode
kubectl apply -f k8s/00-namespace.yaml
if [[ -s secrets/cloudflare_tunnel_token ]]; then
  CF_TOKEN=$(cat secrets/cloudflare_tunnel_token)
  echo 'Cloudflare Tunnel token: secrets/cloudflare_tunnel_token 재사용'
else
  read -rs -p 'Cloudflare Tunnel token (eyJ... 값만): ' CF_TOKEN; echo
fi
[[ "$CF_TOKEN" == eyJ* && ${#CF_TOKEN} -gt 80 && ! "$CF_TOKEN" =~ [[:space:]] ]] || { echo '토큰 형식 확인 필요' >&2; exit 1; }
(umask 077; printf '%s' "$CF_TOKEN" > secrets/cloudflare_tunnel_token)
printf '%s' "$CF_TOKEN" | kubectl -n opencode create secret generic cloudflared-tunnel --from-file=TUNNEL_TOKEN=/dev/stdin --dry-run=client -o yaml | kubectl apply -f -
unset CF_TOKEN
kubectl apply -f k8s/30-cloudflared.yaml
kubectl -n opencode rollout restart deploy/cloudflared
kubectl -n opencode rollout status deploy/cloudflared --timeout=180s
printf '\nCloudflare 웹 화면에 등록할 Published Route:\n'
printf 'Hostname: dash.innerinfo.org\nOrigin: http://192.168.9.221:31800\n'
printf 'DNS: Cloudflare authoritative DNS, 외부 PC DNS 확인\n'
