#!/usr/bin/env bash
# OpenCode Hubble v2 - clean installation, run only from /opt/opencode
set -Eeuo pipefail
trap 'echo "[ERROR] install.sh line $LINENO (status $?)" >&2' ERR
ROOT=/opt/opencode
cd "$ROOT"
[[ $(id -u) -eq 0 ]] || { echo 'root 계정에서 실행하십시오.' >&2; exit 1; }
for bin in kubectl git docker ctr openssl curl python3; do
  command -v "$bin" >/dev/null || { echo "필수 명령어 없음: $bin" >&2; exit 1; }
done
[[ -f k8s/25-hubble-collector.yaml && -f Dockerfile.collector ]] || { echo 'v2 패키지를 /opt/opencode에 복사해야 합니다.' >&2; exit 1; }
if kubectl get ns opencode >/dev/null 2>&1; then
  echo '기존 opencode 네임스페이스가 있습니다. 전체 재설치는 /root/opencode-v2/scripts/reinstall.sh를 사용하십시오.' >&2
  exit 1
fi
kubectl get node master1 >/dev/null
RUNTIME=$(kubectl get node master1 -o jsonpath='{.status.nodeInfo.containerRuntimeVersion}')
[[ "$RUNTIME" == containerd* ]] || { echo "master1 containerd 필요. 현재: $RUNTIME" >&2; exit 1; }
# Existing shared Hubble Relay only. No modification of kube-system.
if ! kubectl -n kube-system get svc hubble-relay >/dev/null 2>&1; then
  echo 'kube-system/hubble-relay 서비스를 찾지 못했습니다. kubectl get svc -A | grep hubble-relay 실행 후 확인하십시오.' >&2; exit 1
fi
RELAY_PORT=$(kubectl -n kube-system get svc hubble-relay -o jsonpath='{.spec.ports[0].port}')
HUBBLE_SERVER=${HUBBLE_SERVER:-hubble-relay.kube-system.svc.cluster.local:${RELAY_PORT}}
HUBBLE_TLS=${HUBBLE_TLS:-false}
FILTER_PORTS=${FILTER_PORTS:-}
FILTER_NAMESPACES=${FILTER_NAMESPACES:-}
# Prevent other namespaces' collision with fixed NodePorts.
for p in 31800 31300; do
  if kubectl get svc -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{" "}{range .spec.ports[*]}{.nodePort}{" "}{end}{"\n"}{end}' | awk -v p="$p" '$0 ~ "(^| )"p"( |$)" {found=1} END{exit !found}'; then
    echo "NodePort $p is already allocated. Do not overwrite another Service." >&2; exit 1
  fi
done
mkdir -p config/commands data/share data/cache secrets /home/toss
install -d -m 0750 -o 10001 -g 10001 dashboard-data
install -d -m 0750 -o 65534 -g 65534 prometheus-data
install -d -m 0750 -o 472 -g 472 grafana-data
if [[ ! -s secrets/ollama_api_key ]]; then
  read -rs -p 'Ollama API Key (OpenCode, 입력 후 Enter): ' OLLAMA_KEY; echo
  [[ -n "$OLLAMA_KEY" ]] || { echo 'Ollama API Key가 비어 있습니다.' >&2; exit 1; }
  (umask 077; printf '%s' "$OLLAMA_KEY" > secrets/ollama_api_key)
  unset OLLAMA_KEY
fi
if [[ ! -s secrets/dashboard_ingest_token ]]; then
  (umask 077; printf '%s' "$(openssl rand -hex 32)" > secrets/dashboard_ingest_token)
fi
# FIX: Never include CR/LF in auth token. Collector/Dashboard get exactly same bytes.
INGEST_TOKEN_NORMALIZED="$(tr -d '\r\n' < secrets/dashboard_ingest_token)"
[[ -n "$INGEST_TOKEN_NORMALIZED" ]] || { echo '수집 API 토큰이 비었습니다.' >&2; exit 1; }
printf '%s' "$INGEST_TOKEN_NORMALIZED" > secrets/dashboard_ingest_token
unset INGEST_TOKEN_NORMALIZED
if [[ ! -s secrets/grafana_admin_password ]]; then
  (umask 077; printf '%s' "$(openssl rand -base64 24 | tr -d '\r\n')" > secrets/grafana_admin_password)
fi
chmod 600 secrets/*
if [[ ! -s config/opencode.json ]]; then cp examples/opencode.sample.json config/opencode.json; fi
# Install OpenCode native custom commands; do not overwrite project source /home/toss
if [[ ! -f CLI-Anything/cli-anything-plugin/HARNESS.md ]]; then
  git clone --depth 1 https://github.com/HKUDS/CLI-Anything.git CLI-Anything
fi
shopt -s nullglob
COMMANDS=(CLI-Anything/opencode-commands/*.md)
((${#COMMANDS[@]})) || { echo 'CLI-Anything 명령어 파일이 없습니다.' >&2; exit 1; }
cp "${COMMANDS[@]}" config/commands/
cp CLI-Anything/cli-anything-plugin/HARNESS.md config/commands/
sed -i 's#\./HARNESS\.md#/root/.config/opencode/commands/HARNESS.md#g' config/commands/cli-anything*.md
cat > config/commands/https-lifecycle.md <<'CMD'
---
description: Analyze observed HTTPS TCP/TLS lifecycle in a PCAP file
---
Use /workspace/opencode-project/scripts/https-lifecycle.sh to analyze the PCAP given by the user.
Never invent TCP/TLS phases or errors that are not present in the capture.
Request: $ARGUMENTS
CMD
printf '\n[1/5] Build image v2\n'
docker build -f Dockerfile -t local/opencode:v2 .
docker build -f Dockerfile.dashboard -t local/https-dashboard:v2 .
docker build -f Dockerfile.collector -t local/hubble-collector:v2 .
docker build -f Dockerfile.grafana -t local/lifecycle-grafana:v2 .
printf '\n[2/5] Import to master1 containerd\n'
for img in local/opencode:v2 local/https-dashboard:v2 local/hubble-collector:v2 local/lifecycle-grafana:v2; do
  docker save "$img" | ctr -n k8s.io images import -
done
printf '\n[3/5] Namespace, Secret, ConfigMap\n'
kubectl apply -f k8s/00-namespace.yaml
kubectl -n opencode create secret generic ollama-api-key --from-file=OLLAMA_API_KEY=secrets/ollama_api_key --dry-run=client -o yaml | kubectl apply -f -
kubectl -n opencode create secret generic dashboard-ingest --from-file=token=secrets/dashboard_ingest_token --dry-run=client -o yaml | kubectl apply -f -
kubectl -n opencode create secret generic lifecycle-grafana-admin --from-file=password=secrets/grafana_admin_password --dry-run=client -o yaml | kubectl apply -f -
kubectl -n opencode create configmap opencode-runtime-settings \
  --from-literal=HUBBLE_SERVER="$HUBBLE_SERVER" \
  --from-literal=HUBBLE_TLS="$HUBBLE_TLS" \
  --from-literal=FILTER_PORTS="$FILTER_PORTS" \
  --from-literal=FILTER_NAMESPACES="$FILTER_NAMESPACES" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n opencode create configmap lifecycle-grafana-dashboards --from-file=dashboard.json=grafana/dashboard.json --dry-run=client -o yaml | kubectl apply -f -
printf '\n[4/5] Kubernetes Deployment v2\n'
for f in 10-opencode.yaml 20-dashboard.yaml 25-hubble-collector.yaml 40-prometheus.yaml 50-grafana.yaml; do kubectl apply -f "k8s/$f"; done
for name in opencode https-dashboard hubble-collector lifecycle-prometheus lifecycle-grafana; do
  kubectl -n opencode rollout status "deploy/$name" --timeout=300s
done
printf '\n[5/5] Ready; install Cloudflare Tunnel as separate step\n'
kubectl -n opencode get pods,svc -o wide
printf '\nDashboard: http://192.168.9.221:31800 (outside HTTPS: https://dash.innerinfo.org)\n'
printf 'Grafana: http://192.168.9.221:31300\n'
printf 'OpenCode: kubectl -n opencode exec -it deployment/opencode -- opencode\n'
printf 'Next: bash scripts/install-cloudflare.sh && bash scripts/check.sh\n'
