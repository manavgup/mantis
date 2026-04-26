"""Sanitizer validation and compiler flag generation."""

from __future__ import annotations

from dataclasses import dataclass

SUPPORTED_SANITIZERS = {"asan", "ubsan", "msan", "tsan"}


@dataclass(frozen=True)
class SanitizerBuildFlags:
    sanitizers: tuple[str, ...]
    sanitize_flag: str
    cflags: str
    ldflags: str


def validate_sanitizers(sanitizers: list[str]) -> list[str]:
    """Validate configured sanitizers and return normalized order-preserving list."""
    if not sanitizers:
        raise ValueError("sanitizers must contain at least one entry")

    normalized: list[str] = []
    for sanitizer in sanitizers:
        if sanitizer not in SUPPORTED_SANITIZERS:
            supported = ", ".join(sorted(SUPPORTED_SANITIZERS))
            raise ValueError(f"unsupported sanitizer '{sanitizer}'; supported: {supported}")
        if sanitizer not in normalized:
            normalized.append(sanitizer)

    selected = set(normalized)
    if "asan" in selected and "msan" in selected:
        raise ValueError("invalid sanitizer combination: asan and msan cannot be combined")
    if "asan" in selected and "tsan" in selected:
        raise ValueError("invalid sanitizer combination: asan and tsan cannot be combined")
    if "msan" in selected and "tsan" in selected:
        raise ValueError("invalid sanitizer combination: msan and tsan cannot be combined")

    return normalized


def build_sanitizer_flags(sanitizers: list[str]) -> SanitizerBuildFlags:
    """Generate compiler/linker flags for the configured sanitizer set."""
    normalized = validate_sanitizers(sanitizers)

    fsanitize_parts: list[str] = []
    cflag_parts: list[str] = []
    ldflag_parts: list[str] = []

    for sanitizer in normalized:
        if sanitizer == "asan":
            fsanitize_parts.append("address")
        elif sanitizer == "ubsan":
            fsanitize_parts.append("undefined")
            cflag_parts.append("-fno-sanitize-recover=all")
        elif sanitizer == "msan":
            fsanitize_parts.append("memory")
            cflag_parts.append("-fPIE")
            ldflag_parts.append("-pie")
        elif sanitizer == "tsan":
            fsanitize_parts.append("thread")

    sanitize_flag = f"-fsanitize={','.join(fsanitize_parts)}"
    cflags = " ".join(
        part for part in [sanitize_flag, "-g", "-O1", "-fno-omit-frame-pointer", "-fPIC", *cflag_parts] if part
    )
    ldflags = " ".join(part for part in [sanitize_flag, *ldflag_parts] if part)

    return SanitizerBuildFlags(
        sanitizers=tuple(normalized),
        sanitize_flag=sanitize_flag,
        cflags=cflags,
        ldflags=ldflags,
    )
