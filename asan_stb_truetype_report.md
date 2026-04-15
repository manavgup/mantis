# 🔴 ASAN Crash Report: `stb_truetype.h` Memory Safety Bugs

**11 malformed TTF inputs produced confirmed ASAN crashes across 5 distinct root-cause bugs.**

---

## 🚨 Bug 1 — Heap Buffer Overflow: Unbounded `loca`/`glyf` Offset

- **Severity:** Critical (arbitrary OOB read)  
- **Files:**  
  - `attack1_loca_oob.ttf`  
  - `attack5_glyf_offset_past_eof.ttf`  
  - `attack17_composite_loca_oob.ttf`  

### Root Cause
`stbtt__GetGlyfOffset` (lines 1603–1621) computes glyph offsets without validating bounds:

```c
g1 = info->glyf + ttULONG(info->data + info->loca + glyph_index * 4);
g2 = info->glyf + ttULONG(info->data + info->loca + glyph_index * 4 + 4);
return g1==g2 ? -1 : g1;
```

**Issue:**  
Neither `g1` nor `g2` is checked against buffer size.

### Trigger Paths
- `loca[n]` → points past allocation
- `glyf` offset → near EOF
- Inflated `maxp.numGlyphs` → invalid `loca` read

---

## 🚨 Bug 2 — Heap Buffer Overflow: `numberOfContours`

- **Severity:** High  
- **File:** `attack2_numcontours_huge.ttf`

### Root Cause
`numberOfContours = 0x7FFF` leads to:
1. OOB read of `endPtsOfContours`
2. Large but valid allocation
3. **Off-by-one access** (`vertices[m]`)

---

## 🚨 Bug 3 — Stack Overflow: Infinite Recursion

- **Severity:** Critical (DoS / stack exhaustion)  
- **Files:** `attack6_*`, `attack11_*`, `attack25_*`

### Root Cause
```c
comp_num_verts = stbtt_GetGlyphShape(info, gidx, &comp_verts);
```

**Issue:** No recursion depth limit.

---

## 🚨 Bug 4 — Heap OOB / SEGV: `cmap` Format-12

- **Severity:** Critical  
- **File:** `attack10_cmap_fmt12_ngroups_huge.ttf`

### Root Cause
```c
stbtt_uint32 ngroups = ttULONG(data+index_map+12);
...
ttULONG(data+index_map+16+mid*12);
```

---

## 🚨 Bug 5 — Heap Buffer Overflow: `kern` Table

- **Severity:** High  
- **File:** `attack16f_kern_no_gpos.ttf`

### Root Cause
```c
r = ttUSHORT(data+10) - 1;
straw = ttULONG(data+18+(m*6));
```

---

## 🚨 Bug 6 — Heap Buffer Overflow: `hhea` Offset

- **Severity:** High  
- **File:** `attack22_hhea_oob.ttf`

### Root Cause
```c
*ascent = ttSHORT(info->data + info->hhea + 4);
```

---

## 🚨 Bug 7 — Heap Buffer Overflow: `head` Offset

- **Severity:** Critical  
- **File:** `attack23_head_oob.ttf`

### Root Cause
```c
info->indexToLocFormat = ttUSHORT(data + info->head + 50);
```

---

## 📊 Summary Table

| # | Bug Class | ASAN Type | Location | Trigger |
|---|----------|----------|----------|--------|
| 1 | `loca/glyf` offset | heap-buffer-overflow | GetGlyfOffset | Corrupt offsets |
| 2 | Contour overflow | heap-buffer-overflow | GetGlyphShapeTT | `0x7FFF` |
| 3 | Recursion | stack-overflow | GetGlyphShape | Self-reference |
| 4 | cmap format-12 | SEGV | FindGlyphIndex | Huge `ngroups` |
| 5 | kern pairs | heap-buffer-overflow | KernInfoAdvance | Large `nPairs` |
| 6 | hhea offset | heap-buffer-overflow | GetFontVMetrics | Invalid offset |
| 7 | head offset | heap-buffer-overflow | InitFont | Invalid offset |

---

## ⚠️ Key Takeaways

- All 7 bugs are triggerable via untrusted TTF input
- Minimal mutations → reliable crashes
- Systemic issue: lack of bounds validation across table offsets
