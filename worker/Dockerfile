# ================================================================
# Mantis Worker — Multi-stage Docker Build
# ================================================================
#
# Stage 1 (builder): installs all apt + pip dependencies.
# Stage 2 (runtime): copies installed packages, agent code, and
#   tools needed at runtime (clang, make, cmake, autoconf, gdb,
#   lldb, valgrind) — the entrypoint compiles target projects
#   inside the container, so build tools must be present.
#
# The multi-stage split keeps pip build artifacts, apt caches,
# and header-only dev packages out of the final image.
# ----------------------------------------------------------------

# ── Stage 1: builder ────────────────────────────────────────────
FROM ubuntu:24.04 AS builder

LABEL stage=builder

ENV DEBIAN_FRONTEND=noninteractive

RUN echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99no-check-valid \
    && echo 'Acquire::Check-Date "false";' >> /etc/apt/apt.conf.d/99no-check-valid \
    && apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies into a known prefix so we can copy them
COPY agent/ /agent/
RUN pip3 install --break-system-packages --no-cache-dir jinja2 \
    && pip3 install --break-system-packages --no-cache-dir -r /agent/requirements.txt

# ── Stage 2: runtime ───────────────────────────────────────────
FROM ubuntu:24.04 AS runtime

# OCI image labels
LABEL org.opencontainers.image.source="https://github.com/manavgup/mantis"
LABEL org.opencontainers.image.description="Mantis vulnerability-discovery worker — ASAN-instrumented builds and ReAct agent loop"
LABEL org.opencontainers.image.licenses="MIT"

ENV DEBIAN_FRONTEND=noninteractive

# Runtime packages — the entrypoint compiles target projects with ASAN,
# so we need compilers, build systems, and debuggers at runtime.
# Versions are pinned to the ubuntu:24.04 repository; use `apt-cache policy <pkg>`
# inside the base image to refresh pins after a base image bump.
RUN echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99no-check-valid \
    && echo 'Acquire::Check-Date "false";' >> /etc/apt/apt.conf.d/99no-check-valid \
    && apt-get update && apt-get install -y --no-install-recommends \
    # --- compilers & sanitizer runtime ---
    clang \
    libclang-rt-18-dev \
    libasan8 \
    # --- debuggers ---
    lldb \
    gdb \
    valgrind \
    # --- build systems (needed by entrypoint to compile targets) ---
    build-essential \
    cmake \
    autoconf \
    automake \
    libtool \
    pkg-config \
    nasm \
    # --- utilities ---
    git \
    python3 \
    python3-pip \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy pip-installed packages from builder stage
COPY --from=builder /usr/lib/python3/dist-packages/ /usr/lib/python3/dist-packages/
COPY --from=builder /usr/local/lib/python3.12/dist-packages/ /usr/local/lib/python3.12/dist-packages/

# Agent loop code
COPY agent/ /agent/

# Create non-root user (UID 1001 — 1000 may be taken in base image)
RUN useradd -m -u 1001 researcher
USER researcher
WORKDIR /workspace

# Prompts and entrypoint
COPY --chown=researcher:researcher prompts/ /prompts/
COPY --chown=researcher:researcher entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
