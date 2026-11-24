FROM python:3.12-slim-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
        socat \
        netcat-openbsd \
        procps \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /opt/runner /workspace /run/agent \
    && chmod 0755 /opt/runner \
    && chmod 0777 /workspace /run/agent

COPY hub_server.py /opt/runner/hub_server.py
RUN chmod 0644 /opt/runner/hub_server.py

WORKDIR /workspace
