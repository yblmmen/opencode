# OpenCode version deliberately matches the previous master1 deployment.
FROM ghcr.io/anomalyco/opencode:2.0.7
USER root
RUN apk add --no-cache git openssh-client ca-certificates bash curl jq python3 py3-pip tshark
WORKDIR /home/toss
