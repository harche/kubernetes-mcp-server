FROM alpine:3.21

# Install common CLI tools and kubectl
RUN apk add --no-cache \
    bash \
    curl \
    wget \
    jq \
    yq \
    git \
    ca-certificates \
    openssh-client \
    bind-tools \
    procps \
    vim \
    coreutils \
    util-linux \
    gawk \
    grep \
    sed \
    findutils \
    diffutils \
    gettext \
    openssl \
    netcat-openbsd \
    && curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/$(uname -m | sed 's/aarch64/arm64/' | sed 's/x86_64/amd64/')/kubectl" \
    && chmod +x kubectl \
    && mv kubectl /usr/local/bin/

# Create a non-root user for running commands
RUN adduser -D -s /bin/bash sandbox
USER sandbox
WORKDIR /home/sandbox

# Keep the container running
ENTRYPOINT ["sleep", "infinity"]
