FROM debian:12-slim

ARG GCLOUD_VERSION=508.0.0

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates curl bash python3 && \
    rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-${GCLOUD_VERSION}-linux-arm.tar.gz" \
      -o /tmp/gcloud.tgz && \
    tar -xzf /tmp/gcloud.tgz -C /opt && \
    rm /tmp/gcloud.tgz && \
    /opt/google-cloud-sdk/install.sh --quiet --usage-reporting=false --path-update=false

ENV PATH=/opt/google-cloud-sdk/bin:$PATH
