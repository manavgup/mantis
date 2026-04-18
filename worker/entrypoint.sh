#!/usr/bin/env bash
set -euo pipefail

# All build/status output goes to stderr so stdout is reserved for agent JSON output
echo "=== vuln-harness worker starting === $(date -u +%Y-%m-%dT%H:%M:%SZ)" >&2

# Render task prompt from Jinja2 template
TASK_PROMPT=$(python3 -c "
import os
from jinja2 import Template
tmpl = Template(open('/prompts/worker-task.txt.j2').read())
print(tmpl.render(
    file_path=os.environ['FILE_PATH'],
    project_name=os.environ['PROJECT_NAME'],
    project_description=os.environ['PROJECT_DESCRIPTION'],
    binary_name=os.environ['BINARY_NAME'],
    max_turns=os.environ.get('MAX_TURNS', '50'),
))
")

# Copy source to writable location (source mount is read-only)
cp -a /target/src /tmp/src
cd /tmp/src
git submodule update --init --recursive 2>/dev/null || true

BINDIR=/tmp/bin
mkdir -p "$BINDIR"

# Check if pre-compiled binaries were mounted at /target/bin
if [ -d /target/bin ] && [ "$(ls -A /target/bin 2>/dev/null)" ]; then
    echo "=== using pre-compiled binaries from /target/bin ===" >&2
    cp -a /target/bin/* "$BINDIR/" 2>/dev/null || true
else
    echo "=== compiling with AddressSanitizer ===" >&2
    export CC=clang
    export CFLAGS="-fsanitize=address -g -O1 -fno-omit-frame-pointer -fPIC"
    export LDFLAGS="-fsanitize=address"

    emit_build_failure() {
        local output="$1"
        local clean=$(echo "$output" | tail -5 | tr '\n' ' ' | sed 's/"/\\"/g' | head -c 500)
        echo "{\"verdict\":\"not_found\",\"description\":\"Compilation failed\",\"reasoning\":\"${clean}\"}"
        exit 1
    }

    # Build configure command: use CONFIGURE_FLAGS if provided, else default --disable-shared
    if [ -n "${CONFIGURE_FLAGS:-}" ]; then
        CONF_CMD="./configure $CONFIGURE_FLAGS"
    else
        CONF_CMD="./configure --disable-shared"
    fi

    # Try autotools first (configure or configure.ac)
    if [ -f ./configure ]; then
        echo "Build system: configure (flags: ${CONFIGURE_FLAGS:---disable-shared})" >&2
        BUILD_OUTPUT=$(eval "$CONF_CMD" 2>&1 && make -j"$(nproc)" 2>&1) || emit_build_failure "$BUILD_OUTPUT"
    elif [ -f ./configure.ac ] || [ -f ./configure.in ]; then
        echo "Build system: autotools (needs autoreconf)" >&2
        BUILD_OUTPUT=$(autoreconf -fi 2>&1 && eval "$CONF_CMD" 2>&1 && make -j"$(nproc)" 2>&1) || emit_build_failure "$BUILD_OUTPUT"
    elif [ -f CMakeLists.txt ]; then
        echo "Build system: cmake" >&2
        mkdir -p build && cd build
        BUILD_OUTPUT=$(cmake \
            -DCMAKE_C_COMPILER=clang \
            -DCMAKE_CXX_COMPILER=clang++ \
            -DCMAKE_C_FLAGS="-fsanitize=address -g -O1 -fno-omit-frame-pointer -fPIC" \
            -DCMAKE_CXX_FLAGS="-fsanitize=address -g -O1 -fno-omit-frame-pointer -fPIC" \
            -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" \
            -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address" \
            -DCMAKE_BUILD_TYPE=Debug \
            -DBUILD_SHARED_LIBS=OFF \
            .. 2>&1 && make -j"$(nproc)" 2>&1) || emit_build_failure "$BUILD_OUTPUT"
        cd ..
    elif [ -f Makefile ] || [ -f makefile ] || [ -f GNUmakefile ]; then
        echo "Build system: plain Makefile" >&2
        BUILD_OUTPUT=$(make CC=clang CFLAGS="$CFLAGS" LDFLAGS="$LDFLAGS" -j"$(nproc)" 2>&1) || true
        if ! find /tmp/src -maxdepth 3 -type f -executable -name "${BINARY_NAME}" 2>/dev/null | grep -q .; then
            emit_build_failure "$BUILD_OUTPUT"
        fi
    else
        echo "{\"verdict\":\"not_found\",\"description\":\"No recognized build system found\",\"reasoning\":\"No configure, configure.ac, CMakeLists.txt, or Makefile\"}"
        exit 1
    fi

    # Collect built binaries
    find /tmp/src -type f -executable \
        ! -name '*.sh' ! -name '*.py' ! -name '*.pl' ! -name '*.cmake' \
        ! -name '*.sample' ! -name '*.so*' ! -name '*.o' \
        ! -path '*/CMakeFiles/*' ! -path '*/.git/*' \
        -exec cp -n {} "$BINDIR/" \; 2>/dev/null || true
fi

export PATH="$BINDIR:$PATH"
echo "=== available binaries ===" >&2
ls "$BINDIR/" >&2 2>/dev/null || echo "(none found)" >&2

export ASAN_OPTIONS="detect_leaks=1:abort_on_error=1:print_stacktrace=1"

echo "=== invoking agent loop (model=${MODEL:-anthropic/claude-opus-4-6}, max ${MAX_TURNS:-50} turns) ===" >&2
export TASK_PROMPT
export PYTHONPATH=/
exec python3 -m agent.run
