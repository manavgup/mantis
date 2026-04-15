#!/usr/bin/env bash
set -euo pipefail

# All build/status output goes to stderr so stdout is reserved for Claude Code JSON
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

# Try autotools first (configure or configure.ac)
if [ -f ./configure ]; then
    echo "Build system: autotools (configure)" >&2
    BUILD_OUTPUT=$(./configure --disable-shared 2>&1 && make -j"$(nproc)" 2>&1) || emit_build_failure "$BUILD_OUTPUT"
elif [ -f ./configure.ac ] || [ -f ./configure.in ]; then
    echo "Build system: autotools (needs autoreconf)" >&2
    BUILD_OUTPUT=$(autoreconf -fi 2>&1 && ./configure --disable-shared 2>&1 && make -j"$(nproc)" 2>&1) || emit_build_failure "$BUILD_OUTPUT"
elif [ -f CMakeLists.txt ]; then
    echo "Build system: cmake" >&2
    mkdir -p build && cd build
    # Pass ASAN flags via cmake variables (not shell expansion)
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
    # For Makefile projects, partial build is OK if we got the target binary
    if ! find /tmp/src -maxdepth 3 -type f -executable -name "${BINARY_NAME}" 2>/dev/null | grep -q .; then
        emit_build_failure "$BUILD_OUTPUT"
    fi
else
    echo "{\"verdict\":\"not_found\",\"description\":\"No recognized build system found\",\"reasoning\":\"No configure, configure.ac, CMakeLists.txt, or Makefile\"}"
    exit 1
fi

# Collect built binaries into a known location
BINDIR=/tmp/bin
mkdir -p "$BINDIR"
find /tmp/src -type f -executable \
    ! -name '*.sh' ! -name '*.py' ! -name '*.pl' ! -name '*.cmake' \
    ! -name '*.sample' ! -name '*.so*' ! -name '*.o' \
    ! -path '*/CMakeFiles/*' ! -path '*/.git/*' \
    -exec cp -n {} "$BINDIR/" \; 2>/dev/null || true
export PATH="$BINDIR:$PATH"
echo "=== built binaries ===" >&2
ls "$BINDIR/" >&2 2>/dev/null || echo "(none found)" >&2

export ASAN_OPTIONS="detect_leaks=1:abort_on_error=1:print_stacktrace=1"

echo "=== invoking claude-code (max ${MAX_TURNS:-50} turns) ===" >&2
exec claude \
    --print \
    --model "${WORKER_MODEL:-claude-opus-4-6}" \
    --allowedTools "Bash,Read" \
    --disallowedTools "WebFetch,WebSearch" \
    --max-turns "${MAX_TURNS:-50}" \
    --output-format json \
    --system-prompt "$(cat /prompts/worker-system.txt)" \
    --dangerously-skip-permissions \
    "$TASK_PROMPT"
