FROM python:3.12-slim AS runtime

# System deps for aiortc (libavcodec / libopus / libsrtp)
RUN apt-get update && apt-get install -y --no-install-recommends \
        libavcodec-extra \
        libopus0 \
        libsrtp2-1 \
        libssl3 \
        ca-certificates \
        tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY gateway /app/gateway
COPY config /app/config

# Non-root runtime user
RUN useradd -r -u 10001 -s /sbin/nologin mccg && \
    mkdir -p /var/log/mccg && chown mccg:mccg /var/log/mccg
USER mccg

EXPOSE 5060/udp 5061/tcp 8443/tcp 9100/tcp
EXPOSE 16384-32767/udp

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "-m", "gateway.main", "--config", "/app/config", "--local-ip", "0.0.0.0"]
