FROM node:24.22.1-bookworm-slim@sha256:be8204d4bd327363357f532187b752ff62759c31bedf98e9e18fc08c9cbd605c AS node
FROM ubuntu:24.04@sha256:9c7f200c07e3d4a03e7249d2c16bf66a51120fb876aa2242cf31451412543289

LABEL org.opencontainers.image.title="Prometheus Apprentice"
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates curl unzip build-essential openjdk-21-jdk-headless python3 python3-venv \
    file binutils jq tini && rm -rf /var/lib/apt/lists/*
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm

ENV GHIDRA_INSTALL_DIR=/opt/ghidra_12.1.4_PUBLIC \
    GHIDRA_MCP_EXTENSION_JAR=/opt/GhidraMCP.jar \
    JAVA_HOME=/opt/java \
    PATH=/opt/python/bin:/opt/rea/node_modules/.bin:$PATH

RUN ln -s /usr/lib/jvm/java-21-openjdk-* /opt/java && \
    curl -fsLS --retry 3 -o /tmp/ghidra.zip https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip && \
    echo 'ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db  /tmp/ghidra.zip' | sha256sum -c - && \
    unzip -q /tmp/ghidra.zip -d /opt && rm /tmp/ghidra.zip
RUN curl -fsLS --retry 3 -o /tmp/extension.zip https://github.com/LaurieWired/GhidraMCP/releases/download/2.0/GhidraMCP-release-2-0.zip && \
    echo 'ebf904fd6782e429e95a60a24fe0724b20c0acb2dedb304135a5281f6b5f2e72  /tmp/extension.zip' | sha256sum -c - && \
    unzip -j /tmp/extension.zip '*/ghidra_12.1.4_PUBLIC_20261010_GhidraMCP.zip' '*/ghidra_mcp-2.0.0-py3-none-any.whl' -d /opt && \
    unzip -j /opt/ghidra_12.1.4_PUBLIC_20261010_GhidraMCP.zip '*/GhidraMCP.jar' -d /opt && \
    rm /tmp/extension.zip /opt/ghidra_12.1.4_PUBLIC_20261010_GhidraMCP.zip

COPY docker/requirements.lock /opt/requirements.lock
RUN python3 -m venv /opt/python && pip install --no-cache-dir --require-hashes -r /opt/requirements.lock && \
    pip install --no-cache-dir --no-deps /opt/ghidra_mcp-2.0.0-py3-none-any.whl && pip check
COPY docker/package.json docker/package-lock.json /opt/rea/
RUN npm --prefix /opt/rea ci --ignore-scripts --omit=optional --no-audit --no-fund && npm cache clean --force && \
    rea --version && ghidra-mcp --help >/dev/null

COPY re_harness /opt/harness/re_harness
RUN mkdir -p /case /opt/fixtures && chown 65532:65532 /case && \
    touch /case/.static-re-volume && chown 65532:65532 /case/.static-re-volume && \
    printf '%s\n' 'int example(int x) { return x + 3; }' 'int main(void) { return example(2); }' | \
    cc -g -O0 -x c - -o /opt/fixtures/benign.elf && chmod 0444 /opt/fixtures/benign.elf
ENV HOME=/tmp REA_GHIDRA_STARTUP_TIMEOUT_MS=110000 GHIDRA_HEADLESS_MAXMEM=1536M \
    JAVA_TOOL_OPTIONS=-XX:ActiveProcessorCount=2 PYTHONUNBUFFERED=1
WORKDIR /opt/harness
USER 65532:65532
ENTRYPOINT ["/usr/bin/tini", "-g", "--", "/opt/python/bin/python", "-m", "re_harness.worker"]
