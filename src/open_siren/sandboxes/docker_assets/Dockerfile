FROM python:3.12-slim-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bubblewrap \
        util-linux \
        strace \
        curl \
        socat \
        netcat-openbsd \
        procps \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /opt/runner /workspace /run/agent /outer \
    && chmod 0755 /opt/runner \
    && chmod 0777 /workspace /run/agent /outer

COPY hub_server.py /opt/runner/hub_server.py
COPY _fd_exec.py /opt/runner/_fd_exec.py
COPY _nested_exec.py /opt/runner/_nested_exec.py
RUN chmod 0644 /opt/runner/hub_server.py /opt/runner/_fd_exec.py /opt/runner/_nested_exec.py

WORKDIR /workspace
