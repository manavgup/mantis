# Mantis — Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           TARGET REPOSITORY                                 │
│                     (C/C++ open-source project)                             │
└──────────────────────────────┬──────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STAGE 1 — FILE RANKING                                                     │
│                                                                             │
│  Claude Code / Anthropic API                                                │
│  "Score each file 1-5 by vulnerability likelihood"                          │
│                                                                             │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐         │
│  │parser.c  │ │decode.c  │ │alloc.c   │ │utils.c   │ │config.h  │         │
│  │ score: 5 │ │ score: 5 │ │ score: 4 │ │ score: 2 │ │ score: 1 │         │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘         │
└──────────────────────────────┬──────────────────────────────────────────────┘
                               │ priority queue
                               ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STAGE 2 — JOB DISPATCH                                                     │
│                                                                             │
│  ┌───────────┐    ┌──────────────────────────────────┐                      │
│  │   Redis    │◄──│  Orchestrator (Python/asyncio)    │                      │
│  │  Priority  │    │  • Semaphore (N parallel)        │                      │
│  │   Queue    │    │  • Spend limit enforcement       │                      │
│  └───────────┘    │  • Timeout management (SIGKILL)   │                      │
│                    └──────────────────────────────────┘                      │
└────────┬───────────────┬───────────────┬───────────────┬────────────────────┘
         │               │               │               │
         ▼               ▼               ▼               ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│  STAGE 3     │ │  STAGE 3     │ │  STAGE 3     │ │  STAGE 3     │
│  WORKER      │ │  WORKER      │ │  WORKER      │ │  WORKER      │
│  CONTAINER   │ │  CONTAINER   │ │  CONTAINER   │ │  CONTAINER   │
│              │ │              │ │              │ │              │
│ ┌──────────┐ │ │ ┌──────────┐ │ │ ┌──────────┐ │ │ ┌──────────┐ │
│ │Claude    │ │ │ │Claude    │ │ │ │Claude    │ │ │ │Claude    │ │
│ │Code      │ │ │ │Code      │ │ │ │Code      │ │ │ │Code      │ │
│ │(headless)│ │ │ │(headless)│ │ │ │(headless)│ │ │ │(headless)│ │
│ └────┬─────┘ │ │ └────┬─────┘ │ │ └────┬─────┘ │ │ └────┬─────┘ │
│      │       │ │      │       │ │      │       │ │      │       │
│      ▼       │ │      ▼       │ │      ▼       │ │      ▼       │
│ ┌──────────┐ │ │ ┌──────────┐ │ │ ┌──────────┐ │ │ ┌──────────┐ │
│ │ Bash     │ │ │ │ Bash     │ │ │ │ Bash     │ │ │ │ Bash     │ │
│ │ GDB/LLDB │ │ │ │ GDB/LLDB │ │ │ │ GDB/LLDB │ │ │ │ GDB/LLDB │ │
│ │ ASAN     │ │ │ │ ASAN     │ │ │ │ ASAN     │ │ │ │ ASAN     │ │
│ │ Binary   │ │ │ │ Binary   │ │ │ │ Binary   │ │ │ │ Binary   │ │
│ └──────────┘ │ │ └──────────┘ │ │ └──────────┘ │ │ └──────────┘ │
│              │ │              │ │              │ │              │
│  parser.c    │ │  decode.c    │ │  alloc.c     │ │  io.c        │
│  Egress:     │ │  Egress:     │ │  Egress:     │ │  Egress:     │
│  api.anthropic│ │  api.anthropic│ │  api.anthropic│ │  api.anthropic│
│  .com:443    │ │  .com:443    │ │  .com:443    │ │  .com:443    │
│  ONLY        │ │  ONLY        │ │  ONLY        │ │  ONLY        │
└──────┬───────┘ └──────┬───────┘ └──────┬───────┘ └──────┬───────┘
       │                │                │                │
       │   ┌────────────────────────────────────────┐     │
       └──►│         Raw findings (JSONL)            │◄───┘
            └───────────────────┬────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STAGE 4 — ASAN PARSER + TRIAGE                                             │
│                                                                             │
│  Extract crash metadata → Assign severity tier → Estimate CVSS              │
│                                                                             │
│  Tier 5: Control flow hijack (RIP/PC control)          CVSS 9.0-10.0       │
│  Tier 4: Arbitrary write (heap-buffer-overflow WRITE)  CVSS 7.5-9.0        │
│  Tier 3: Arbitrary read (use-after-free READ)          CVSS 5.0-7.5        │
│  Tier 2: Crash / DoS (null deref, stack overflow)      CVSS 3.5-5.0        │
│  Tier 1: Memory leak only                              CVSS 1.0-3.5        │
└──────────────────────────────┬──────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  STAGE 5 — VALIDATION AGENT                                                 │
│                                                                             │
│  Separate Claude instance per finding:                                      │
│  "Is the ASAN output real? Is the repro plausible? Is this meaningful?"     │
│                                                                             │
│  ┌─────────┐     ┌──────────────────┐     ┌─────────┐                      │
│  │VALIDATE │     │NEEDS_HUMAN_TRIAGE│     │ REJECT  │                      │
│  │→ review │     │→ review (flagged)│     │→ log    │                      │
│  └────┬────┘     └────────┬─────────┘     └────┬────┘                      │
│       │                   │                     │                           │
└───────┼───────────────────┼─────────────────────┼───────────────────────────┘
        │                   │                     │
        ▼                   ▼                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────────┐ │
│  │  FINDINGS STORE  │  │  AUDIT LOG      │  │  HUMAN REVIEW PACKAGE      │ │
│  │  (Postgres)      │  │  (JSONL)        │  │  (Markdown per finding)    │ │
│  │                  │  │                 │  │                            │ │
│  │  • AES-256-GCM   │  │  • SHA-3 hash   │  │  • Description             │ │
│  │    encrypted     │  │    chained      │  │  • Reproduction steps      │ │
│  │  • Exploit code  │  │  • Every action │  │  • ASAN output             │ │
│  │    never in      │  │    logged BEFORE│  │  • Candidate patch         │ │
│  │    plaintext     │  │    execution    │  │  • Reviewer sign-off box   │ │
│  │                  │  │  • Tamper-      │  │                            │ │
│  │                  │  │    evident      │  │  ☐ Confirmed real          │ │
│  │                  │  │  • watsonx.gov  │  │  ☐ CVSS confirmed: ___    │ │
│  │                  │  │    compatible   │  │  ☐ Disclosure approved     │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────────────────┘ │
│                                                                             │
│  HUMAN SIGN-OFF REQUIRED BEFORE ANY EXTERNAL ACTION (P2)                    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘


                    ┌─────────────────────────────┐
                    │  AGENTIC HYPOTHESIS-TEST     │
                    │  LOOP (inside each worker)   │
                    │                              │
                    │  ┌────────────────────────┐  │
                    │  │ 1. Read source code     │  │
                    │  └───────────┬────────────┘  │
                    │              ▼                │
                    │  ┌────────────────────────┐  │
                    │  │ 2. Form hypothesis      │  │
                    │  │    "integer overflow in  │  │
                    │  │     image dimensions"    │  │
                    │  └───────────┬────────────┘  │
                    │              ▼                │
                    │  ┌────────────────────────┐  │
                    │  │ 3. Craft malformed input │  │
                    │  │    (python3 script)      │  │
                    │  └───────────┬────────────┘  │
                    │              ▼                │
                    │  ┌────────────────────────┐  │
                    │  │ 4. Run ASAN binary      │  │
                    │  │    with crafted input   │  │
                    │  └───────────┬────────────┘  │
                    │              ▼                │
                    │  ┌────────────────────────┐  │
                    │  │ 5. Read ASAN output     │──┼──► CRASH? → Report
                    │  │    Did it crash?        │  │
                    │  └───────────┬────────────┘  │
                    │              │ No             │
                    │              ▼                │
                    │  ┌────────────────────────┐  │
                    │  │ 6. Next hypothesis      │──┼──► Loop back to 2
                    │  └────────────────────────┘  │
                    │                              │
                    └──────────────────────────────┘
```
