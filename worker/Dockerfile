FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99no-check-valid \
    && echo 'Acquire::Check-Date "false";' >> /etc/apt/apt.conf.d/99no-check-valid \
    && apt-get update && apt-get install -y \
    clang \
    lldb \
    gdb \
    valgrind \
    build-essential \
    cmake \
    autoconf \
    automake \
    libtool \
    pkg-config \
    git \
    python3 \
    python3-pip \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Jinja2 for prompt rendering in entrypoint
RUN pip3 install --break-system-packages jinja2

# Agent loop dependencies (litellm for provider-agnostic LLM access)
COPY agent/ /agent/
RUN pip3 install --break-system-packages --no-cache-dir -r /agent/requirements.txt

# Create non-root user (UID 1001 — 1000 may be taken in base image)
RUN useradd -m -u 1001 researcher
USER researcher
WORKDIR /workspace

# Prompts and entrypoint
COPY --chown=researcher:researcher prompts/ /prompts/
COPY --chown=researcher:researcher entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
