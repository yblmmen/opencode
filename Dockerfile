FROM ghcr.io/anomalyco/opencode:2.0.7

USER root

RUN apk add --no-cache \
    git \
    openssh-client \
    ca-certificates \
    bash \
    curl \
    jq \
    python3

WORKDIR /workspace/toss
