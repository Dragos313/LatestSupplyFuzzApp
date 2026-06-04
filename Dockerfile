FROM ubuntu:22.04

# Evităm prompt-urile interactive în timpul instalării
ENV DEBIAN_FRONTEND=noninteractive

# Am adăugat nodejs și npm în lista de instalare
RUN apt-get update && apt-get install -y \
    build-essential python3 python3-pip git clang llvm llvm-dev lld \
    libsqlite3-dev libnode-dev nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# --- NOU: Descărcăm headerele specifice ecosistemului Node.js ---
# Creăm un folder global unde instalăm node-addon-api și nan
RUN mkdir -p /opt/node_headers && cd /opt/node_headers && \
    npm init -y && \
    npm install node-addon-api nan

# Instalăm AFL++
RUN git clone https://github.com/AFLplusplus/AFLplusplus.git /AFLplusplus
WORKDIR /AFLplusplus
RUN make distrib
ENV PATH="/AFLplusplus:${PATH}"

WORKDIR /fuzz_target
CMD ["/bin/bash"]