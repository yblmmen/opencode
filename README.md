# OpenCode · Cilium Hubble · TCP Lifecycle Monitor v2

> **기준 환경:** Kubernetes v1.36.x / Rocky Linux 9.8 / containerd / master1(192.168.9.221), worker1~3. 기존 Cilium/Hubble Relay는 정상 운영 중이며 **변경하지 않습니다**.
>
> **목표:** 과거 OpenCode 설치를 백업·완전 삭제한 후 v2를 새로 배포합니다. 전체 네임스페이스 Hubble 흐름, 실시간 관계도, IP별 TCP SYN/SYN/ACK/ACK/FIN/RST·Drop 분석, Grafana/Prometheus, Cloudflare Tunnel 포함. Draw.io 제외.

## 1. 최종 배포 정보

| 항목 | 값 |
|---|---|
| 설치 소스 보관 | `/root/opencode-v2` (압축 해제한 원본, 삭제 금지) |
| 실제 운영 소스·데이터 | `/opt/opencode` |
| 원래 사용자 작업 | `/home/toss` (초기화 시 보존) |
| Kubernetes Namespace | `opencode` (완전 삭제 후 재생성) |
| OpenCode | `ghcr.io/anomalyco/opencode:2.0.7` 기반 커스텀 이미지 `local/opencode:v2` |
| CLI-Anything | `HKUDS/CLI-Anything` 공식 명령어를 설치 시 가져옴 |
| Hubble Relay | `hubble-relay.kube-system.svc.cluster.local:80` (환경에 따라 자동 서비스 포트 확인) |
| Dashboard | `https://dash.innerinfo.org` / `http://192.168.9.221:31800` |
| Grafana | `http://192.168.9.221:31300` |
| Prometheus | `lifecycle-prometheus.opencode.svc.cluster.local:9090` (ClusterIP) |
| Cloudflare Tunnel Origin | `http://192.168.9.221:31800` |
| GitHub (선택) | `https://github.com/yblmmen/opencode.git`, `main` |
| 백업 위치 | `/root/opencode-backups/` |

### 구성도
![Uploading image.png…](https://chatgpt.com/c/6add8119-f788-83e8-83a7-e560a1813dcb)

 

- 기존 Cilium/Hubble은 모든 네임스페이스의 네트워크 이벤트를 Relay에서 제공.
- `hubble-collector`는 TCP/UDP Flow를 수집하고 대시보드의 인증된 수집 API로 전송.
- 대시보드는 이벤트, 출발지/목적지 연결, 네임스페이스, IP별 TCP 연결 수명주기, Drop/RST 이벤트를 표시.
- Prometheus는 대시보드 `/metrics`를 스크레이프; Grafana는 통계 및 Node Graph를 표현.
- Cloudflare Tunnel은 외부 HTTPS를 처리하고 **HTTP**로 NodePort 31800에 접근.

## 2. 설치 전 조건

`master1` root에서 점검합니다. `docker build`, `ctr` 이미지 가져오기 때문에 **Docker와 containerd가 모두 필요**합니다. 사용 중인 Cilium/Hubble은 그대로 두십시오.

```bash
kubectl get nodes -o wide
kubectl -n kube-system get svc hubble-relay
kubectl get svc -A | grep -E '31800|31300' || true
for c in git docker ctr kubectl openssl curl python3 unzip; do command -v "$c" || echo "MISSING: $c"; done
```

- 이미지 빌드를 위한 외부 접근: GitHub, GHCR, Docker Hub, Grafana Plugin, Cilium Hubble release.
- 설치 시 **Ollama API Key**와 **Cloudflare Tunnel Token**을 직접 입력할 수 있어야 합니다. 토큰을 설치 스크립트나 YAML에 평문으로 기재할 필요는 없습니다.
- `master1` 노드의 hostname 레이블이 `master1`인지 확인하십시오. 이미지·hostPath 데이터는 master1에 위치하도록 배포합니다.
- NodePort 31800, 31300이 다른 서비스와 충돌하면 배포하지 마십시오.

## 3. v1/v1.1 등 기존 `opencode` 전체 삭제 후 v2 신규 설치

**이 한 가지 절차로 충분합니다.** 파일을 `/root/opencode-hubble-v2-final.zip`에 올린 후 실행하십시오.

```bash
cd /root
unzip -oq opencode-hubble-v2-final.zip -d /root
bash /root/opencode-v2/scripts/reinstall.sh
```

스크립트 동작:

1. 사용자에게 `DELETE OPENCODE V2` 정확한 문구 입력 요청.
2. 과거 OpenCode Docker 컨테이너(해당 이미지) 중지, `opencode` Deployment 0개로 축소하여 쓰기 중지.
3. `/opt/opencode` 전체를 `/root/opencode-backups/opencode-before-v2-날짜.tar.gz`에 보관·검증.
4. Kubernetes `opencode` 네임스페이스 **전체 삭제 완료 확인**.
5. `/opt/opencode` 삭제 후 `/root/opencode-v2` 새 설치 소스 복사, 이미지 v2 빌드·containerd 등록.
6. `opencode` 네임스페이스·Secret·ConfigMap·OpenCode·Dashboard·Collector·Prometheus·Grafana 새로 배포.
7. Cloudflared 배포 및 NodePort/Relay 점검.

**삭제 범위 주의:** `opencode` 네임스페이스에 별도로 만든 다른 서비스도 함께 삭제됩니다. `kube-system`의 Cilium/Hubble, `/home/toss`, Cloudflare 웹 설정, GitHub 원격 저장소는 삭제하지 않습니다. 이전 `/opt/opencode`에 있던 설정과 DB는 *자동 복원하지 않으며* 백업 파일에 남습니다. 완전 신규 설치에서는 기존 수집 통계가 0부터 시작합니다.

설치 도중 문제가 생기면 `bash /root/opencode-v2/scripts/reinstall.sh`를 다시 실행할 수 있지만, 먼저 해당 오류 로그를 확인하는 것을 권장합니다. 사용자가 이미 설치한 `opencode` 네임스페이스를 무조건 덮어쓰지 않습니다.

### 완전 새 서버에서 최초 설치 (기존 `opencode` 자체가 없을 때)

```bash
cd /root
unzip -oq opencode-hubble-v2-final.zip -d /root
bash /root/opencode-v2/scripts/fresh-install.sh
```

### 초기화만 수행

```bash
bash /root/opencode-v2/scripts/reset.sh
```

이후 신규 설치는 `bash /root/opencode-v2/scripts/fresh-install.sh`입니다. 초기화 스크립트를 `/opt/opencode` 내부에서 실행해서는 안 됩니다.

## 4. Cloudflare Tunnel 설정

설치 중 Cloudflare 토큰을 새로 입력하고 Pod가 실행됩니다. Cloudflare Zero Trust에서 해당 터널의 Published application 경로가 **아래와 동일한지 한 번만 확인**하십시오.

| 항목 | 값 |
|---|---|
| Public Hostname | `dash.innerinfo.org` |
| Service Type | `HTTP` |
| Origin URL | `http://192.168.9.221:31800` |
| 외부 브라우저 | `https://dash.innerinfo.org` |

Cloudflare 관리 화면의 DNS는 이 도메인에 대한 레코드가 현재 Tunnel에 연결되어 있어야 합니다. 외부 PC가 오래된 DNS 응답을 기억하면 `nslookup dash.innerinfo.org 1.1.1.1`와 외부 DNS를 비교하십시오.

## 5. 설치 완료 검증 (필수)

```bash
cd /opt/opencode
kubectl -n opencode get pods,svc -o wide
bash scripts/check.sh
kubectl -n opencode logs deploy/hubble-collector --tail=50
```

**정상 판정은 Pod Running만으로 하지 않습니다.** Collector 로그의 `Hubble Relay connected` 및 이후 `Posted events` 증가, 대시보드 API의 `collector connected`, 최근 이벤트 카운트 증가까지 확인하십시오.

```bash
curl -sS 'http://192.168.9.221:31800/api/summary?minutes=5'
curl -sS 'http://192.168.9.221:31300/api/health'
```

대시보드에서 이벤트가 0이면 `kubectl -n opencode logs deploy/hubble-collector --since=5m`를 확인합니다. 401이면 Collector와 Dashboard가 사용하는 `dashboard-ingest` Secret 값 일치 여부를 확인하고 설치본의 줄바꿈 정규화 로직을 사용합니다.

## 6. 기능 사용

### 실시간 네트워크 화면

`https://dash.innerinfo.org`에서 네임스페이스·포트·조회 시간 필터, 네트워크 관계도, 이벤트 추이, 최근 Flow를 확인합니다.

### 특정 IP별 TCP 3-way / 4-way 수명주기

1. 화면의 **IP별 TCP 연결 수명주기** 영역에서 검색 IP를 입력합니다(예: `10.0.0.219`).
2. 필요 시 상대 IP, 포트, 조회기간을 설정합니다.
3. 연결 목록 중 IP:Port 양쪽 조합(4-tuple)의 원하는 연결을 선택합니다.
4. SYN → SYN/ACK → ACK, 데이터 구간, FIN/ACK 종료 또는 RST 및 Drop 이벤트를 시간순으로 확인합니다.
5. 관측 노드·정책 Drop 사유·연결 방향을 확인합니다.

CLI 검색:

```bash
bash /opt/opencode/scripts/test-tcp.sh 10.0.0.219
```

**해석 원칙:** Hubble은 전체 패킷 보존 수집기가 아닙니다. SYN/ACK 등이 표시되지 않으면 **미관측**일 수 있으며 TCP 장애로 단정하지 않습니다. Hubble Flow는 한 패킷이 여러 관측 지점에서 중복될 수도 있습니다. `RST`의 출발 방향은 근거지만 장애의 최종 원인 진단은 애플리케이션·서버 로그와 함께 해야 합니다. 정확한 SEQ/ACK, 재전송 여부, TLS 협상은 PCAP/tshark를 사용합니다.

### PCAP에서 TCP/TLS 연결 시간순 다이어그램 만들기

```bash
bash /opt/opencode/scripts/https-lifecycle.sh \\
  /home/toss/captures/session.pcapng 0 \\
  --out /home/toss/captures/session.html
```

클라이언트 또는 TLS가 실제로 보이는 구간에서 캡처한 PCAP이 필요합니다. Cloudflare에서 외부 HTTPS가 종료되므로 클러스터 내부 HTTP NodePort 트래픽만으로 외부 TLS 핸드셰이크는 복원할 수 없습니다. Draw.io 수동 내보내기 기능은 포함하지 않습니다.

### Grafana

`http://192.168.9.221:31300`으로 접속합니다. 관리자 계정은 `admin`, 암호는 서버에서 다음 명령으로 확인합니다.

```bash
cat /opt/opencode/secrets/grafana_admin_password
```

Prometheus는 ClusterIP를 유지하며, Grafana에는 시계열 및 Node Graph용 데이터 소스를 자동 구성합니다.

### OpenCode / CLI-Anything

```bash
kubectl -n opencode exec -it deploy/opencode -- opencode
```

OpenCode에서 `/cli-anything-list` 등을 확인하고 PCAP 분석용 `/https-lifecycle` 명령을 사용할 수 있습니다. OpenCode 모델의 API 오류는 Hubble 수집 및 대시보드 실행과 별개입니다.

## 7. 일상 운영 명령

```bash
kubectl -n opencode get pods,deploy,svc
kubectl -n opencode logs deploy/hubble-collector --since=5m
kubectl -n opencode logs deploy/https-dashboard --tail=60
kubectl -n opencode logs deploy/cloudflared --tail=40
bash /opt/opencode/scripts/check.sh
```

필터 변경이 필요하면 `opencode-runtime-settings` ConfigMap의 `FILTER_PORTS`(예: `443,8080`), `FILTER_NAMESPACES`(예: `default,opencode`)를 수정하고 Collector를 재시작합니다. 초기 기본값은 **전체 네임스페이스/전체 TCP·UDP 포트**입니다.

## 8. GitHub 소스 등록 (선택)

기존 저장소는 `https://github.com/yblmmen/opencode.git`, 브랜치는 `main`입니다. 배포와 Git 업로드를 혼동하지 않도록 **설치 후 별도 실행**합니다.

```bash
# 최초 인증만 PAT를 입력하도록 Git credential helper 설정
 git config --global credential.helper 'store --file=/root/.git-credentials'
# 설치본에서 GitHub로 소스 복사·커밋·Push
cd /opt/opencode
bash scripts/github-push.sh
```

전체 런타임 파일(인증·세션·DB)까지 저장할 때만 `bash scripts/github-push.sh --include-runtime`를 사용합니다. 이 경우 GitHub 파일 제한 및 비밀정보 노출 위험이 있으며, 실행 중 DB를 파일 복사하면 시점 일관성이 보장되지 않습니다. 백업을 위해서는 **reset.sh의 정지 후 백업**을 사용하십시오.

## 9. 자주 확인할 오류와 조치

| 증상 | 확인 위치 |
|---|---|
| Collector `HTTP 401` | `dashboard-ingest` Secret / 토큰 줄바꿈; 새 설치 스크립트가 정규화 |
| Dashboard 0건 | Collector 로그의 Relay 연결 및 Posted events; 401/Relay 실패 분리 |
| Pod `ImagePullBackOff` | master1에 v2 이미지 import 여부 및 `imagePullPolicy: Never` |
| 대시보드 내부 접속 실패 | NodePort 31800, Pod/Service Endpoint 확인 |
| Grafana 접속 실패 | NodePort 31300, Grafana Pod·로그 확인 |
| 외부 접속만 실패 | DNS 조회, Cloudflare Published Route, Tunnel Pod 및 Origin URL 확인 |
| TLS 단계 미표시 | Hubble과 NodePort HTTP는 외부 TLS 핸드셰이크를 관측하지 못함 |

## 10. 구성·기술 제한

- 고정 노드 `master1`와 `hostPath` 데이터를 사용하는 단일 노드 종속 운영입니다. 노드 장애 시 자동 데이터 재배치는 보장되지 않습니다.
- NodePort는 사용자 지정 포트 `31800`, `31300`을 사용하며 다른 Kubernetes 서비스가 점유하고 있으면 설치 전에 해결해야 합니다.
- 네트워크 정책과 Hubble 설정에 따라 패킷이 미관측되거나 중복될 수 있습니다. Flow 이벤트는 활성 TCP 세션 수가 아닙니다.
- Prometheus/Grafana는 이벤트 지표 및 관계도, Hubble TCP 플래그는 연결 이벤트; 100% 완전한 TCP 패킷 수명주기 증명이 필요한 경우 PCAP이 필요합니다.

## 11. 공식 문서

- Cilium Hubble CLI: https://docs.cilium.io/en/stable/observability/hubble/hubble-cli/
- Kubernetes NodePort: https://kubernetes.io/docs/concepts/services-networking/service/
- Cloudflare Kubernetes Tunnel: https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/deployment-guides/kubernetes/
- Grafana Node Graph: https://grafana.com/docs/grafana/latest/visualizations/panels-visualizations/visualizations/node-graph/
- Wireshark tshark: https://www.wireshark.org/docs/man-pages/tshark.html
