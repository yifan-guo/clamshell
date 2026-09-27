FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends \
      swtpm swtpm-tools tpm2-tools cryptsetup curl jq openssl python3 util-linux \
    && rm -rf /var/lib/apt/lists/*

COPY tpm-common.sh /usr/local/bin/tpm-common.sh
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/tpm-common.sh /usr/local/bin/entrypoint.sh
RUN mkdir -p /var/lib/battery

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
