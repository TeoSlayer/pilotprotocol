FROM debian:12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      curl ca-certificates tini python3 python3-pip iproute2 \
 && rm -rf /var/lib/apt/lists/* \
 && pip3 install --no-cache-dir --break-system-packages prometheus_client==0.20.0

RUN useradd -m -u 1000 -s /bin/bash pilot

COPY probe.py /opt/probe.py
COPY entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/entrypoint.sh /opt/probe.py

USER pilot
WORKDIR /home/pilot
EXPOSE 8080
ENTRYPOINT ["/usr/bin/tini", "--", "/opt/entrypoint.sh"]
