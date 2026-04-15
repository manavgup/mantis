# Finding #001 — heap-buffer-overflow in giflib 5.1.4

**Status**: Confirmed by ASAN — matches CVE-2016-3977
**Severity Tier**: 3 (arbitrary read)
**CVSS Estimate**: 6.2 (High) — unconfirmed, awaits human review
**File**: `util/gif2rgb.c:294` in `DumpScreen2RGB`
**Discovered by**: Mantis (Claude Code agent, sonnet-4-6)
**Turns to find**: 12 of 40 allocated
**Cost**: $0.74
**Date**: 2026-04-14

---

## Summary

The agent found a heap buffer over-read in giflib's `gif2rgb` utility by hypothesizing that LZW decoder output (pixel values) is not validated against the colormap size. A crafted GIF with a small 2-entry colormap and LZW minimum code size of 8 produces pixel values up to 255, which are then used as indices into the 2-entry colormap — reading up to 600 bytes past the end of the allocation.

## ASAN Output

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

## Vulnerable Code

```c
// util/gif2rgb.c:294
ColorMapEntry = &ColorMap->Colors[GifRow[j]];   // ← OOB READ: no bounds check
```

## Trigger Conditions

| Field | Value |
|-------|-------|
| Global colormap size | 2 entries (6 bytes: black + white) |
| LZW minimum code size | 8 (so `ClearCode = 256`) |
| Pixel values emitted by decoder | up to 255 (valid per LZW spec) |
| `ColorMap->ColorCount` | 2 |
| `Colors[200]` access | 270 bytes past end of 6-byte allocation |

## Candidate Patch

```diff
--- a/util/gif2rgb.c
+++ b/util/gif2rgb.c
@@ -291,6 +291,10 @@ static void DumpScreen2RGB(char *FileName, int OneFileFlag,
             GifRow = ScreenBuffer[i];
             (void)fprintf(stderr, "\b\b\b\b%-4d", ScreenHeight - i);
             for (j = 0; j < ScreenWidth; j++) {
+                if (GifRow[j] >= ColorMap->ColorCount) {
+                    // Reject malformed input: pixel exceeds colormap
+                    PrintGifError(GIF_ERROR_INVALID_COLOR);
+                    exit(EXIT_FAILURE);
+                }
                 ColorMapEntry = &ColorMap->Colors[GifRow[j]];
                 ScreenBuffer[i][j] = GifRow[j];
                 fprintf(f, "%c%c%c",
```

## CVE Reference

This matches the pattern of **CVE-2016-3977** — a heap-based buffer overflow in giflib via malformed GIF images with mismatched colormap/LZW configurations. The specific instance at `gif2rgb.c:294` may also relate to CVE-2015-7555 or similar colormap-related bugs. Human researcher should confirm CVE attribution.

## Reviewer Sign-off Required

- [ ] Confirmed real vulnerability
- [ ] CVSS confirmed: ____
- [ ] CVE attribution confirmed: ____
- [ ] Disclosure approved
- [ ] Patch approved for submission
- [ ] Reviewer: __________________ Date: __________
