#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if command -v tshark >/dev/null 2>&1; then
  exec python3 "$ROOT/scripts/lifecycle.py" "$@"
fi
# On master1 tshark may not be installed. The OpenCode container has it.
command -v kubectl >/dev/null || { echo 'tshark 또는 kubectl이 필요합니다.' >&2; exit 1; }
echo '호스트에 tshark가 없어 OpenCode 컨테이너에서 분석합니다. PCAP은 /home/toss 내에 있어야 합니다.' >&2
exec kubectl -n opencode exec deploy/opencode -- python3 /workspace/opencode-project/scripts/lifecycle.py "$@"
