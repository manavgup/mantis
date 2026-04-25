# Mantis Data Retention & Destruction Policy

**Document version**: 1.0
**Last updated**: 2026-04-25
**Applicable system**: Mantis Autonomous Vulnerability Discovery Harness
**Policy owner**: Security Operations

---

## 1. Scope

This policy governs the retention, protection, and destruction of all data created, processed, or stored by the Mantis autonomous vulnerability discovery harness. It applies to:

- All data stored in the Postgres findings database
- Audit log files (JSONL)
- Worker container artifacts (ephemeral)
- Configuration and secret material
- Human review reports (markdown)
- Redis queue data

This policy is designed to satisfy requirements from NIST CSF 2.0 (PR.DS, ID.AM), FINRA record retention rules, SOX Section 802, and GDPR/CCPA data minimization principles.

---

## 2. Data Classification

| Data Type | Classification | Storage Location | Encryption | Integrity Mechanism | Retention Period |
|-----------|---------------|-----------------|------------|---------------------|-----------------|
| Audit log entries | Compliance | JSONL file at `{run_dir}/audit.jsonl` | None (plaintext) | SHA-3 hash chain (`harness/audit.py:81-83`) | 7 years minimum |
| Run metadata | Internal | Postgres `runs` table | None (plaintext) | Database constraints | 3 years |
| Job metadata | Internal | Postgres `jobs` table | None (plaintext) | Database constraints, foreign key to `runs` | 3 years |
| Finding metadata (vuln_type, severity, file, line) | Internal | Postgres `findings` table | None (plaintext) | Database constraints, foreign keys | 3 years or 1 year post-disclosure, whichever is later |
| Reproduction commands (PoC) | Restricted | Postgres `reproduction_enc` column | AES-256-GCM (`harness/crypto.py:13-18`) | GCM authentication tag | 3 years or 1 year post-disclosure |
| Candidate patches | Restricted | Postgres `patch_enc` column | AES-256-GCM | GCM authentication tag | 3 years or 1 year post-disclosure |
| ASAN crash output | Restricted | Postgres `asan_output_enc` column | AES-256-GCM | GCM authentication tag | 3 years or 1 year post-disclosure |
| Raw agent output | Sensitive | Postgres `jobs.result_raw` JSONB column | None (plaintext -- gap, see note) | Database constraints | 3 years |
| Worker container artifacts | Ephemeral | tmpfs inside container | None | Destroyed on container exit | Duration of container run only |
| Human review reports | Internal | `{run_dir}/findings/{finding_id}.md` | None (plaintext) | Filesystem permissions | 3 years or 1 year post-disclosure |
| API keys | Secret | Environment variables only | N/A (in-memory) | Never persisted (P4) | Session-scoped |
| Encryption key (FINDINGS_ENC_KEY) | Critical | Environment variable | N/A (in-memory) | Base64-encoded, 32-byte validation (`harness/crypto.py:35-37`) | Rotated per key management policy |
| Redis queue data | Transient | Redis in-memory | None | Spend limit checks (`harness/dispatcher.py:234-246`) | Duration of scan run + 24 hours |
| Configuration (harness.yaml) | Internal | Filesystem | None | Version control (git) | Indefinite (version-controlled) |

**Note on raw agent output**: The `jobs.result_raw` JSONB column may contain ASAN output, vulnerability descriptions, and reproduction commands in plaintext. This is a known gap. It should be encrypted or access-restricted in production (see threat model R7).

---

## 3. Retention Periods

### 3.1 Compliance Records (7-year retention)

**Audit log files** must be retained for a minimum of 7 years to satisfy:
- FINRA Rule 4511: 6-year retention for business records
- SOX Section 802: 7-year retention for audit workpapers
- NIST CSF 2.0 PR.PS-04: Log record availability

The SHA-3 hash chain (`harness/audit.py:93-123`) provides tamper-evident integrity verification throughout the retention period. Audit logs should be archived to immutable storage (S3 with Object Lock, Azure Immutable Blob, or equivalent) within 24 hours of run completion.

### 3.2 Finding Records (3 years or 1 year post-disclosure)

**Finding metadata, encrypted exploit data, and associated job/run records** are retained for 3 years from discovery, or 1 year after public disclosure, whichever is later.

This satisfies:
- Regulatory audit requirements for vulnerability management programs
- Legal hold requirements for ongoing coordinated disclosure
- Evidence preservation for potential litigation

### 3.3 Ephemeral Data (destroyed on container exit)

**Worker container artifacts** exist only for the duration of the container run and are automatically destroyed:
- tmpfs at `/workspace` and `/tmp` cleared on container removal (`harness/dispatcher.py:34`, `--rm` flag)
- Container filesystem is read-only; writable areas are tmpfs only
- No data persists between container runs (P5, `01-constitution.md:32-33`)

### 3.4 Transient Queue Data (run duration + 24 hours)

**Redis queue entries** for job status and spend tracking are retained for the duration of the scan run plus 24 hours for operational review. After that period, Redis keys should be expired or explicitly deleted.

### 3.5 Secret Material (session-scoped)

**API keys and encryption keys** exist only in process memory via environment variables. They are:
- Never written to disk (P4, `01-constitution.md:29`)
- Never included in Docker images
- Never logged in the audit log
- Destroyed when the process exits

---

## 4. Destruction Procedures

### 4.1 Cryptographic Erasure

For data encrypted with AES-256-GCM (reproduction commands, patches, ASAN output in the `findings` table):

**Cryptographic erasure** is the primary destruction method. When the `FINDINGS_ENC_KEY` is destroyed, all data encrypted with that key becomes permanently unreadable.

Procedure:
1. Verify all active legal holds and retention obligations have been satisfied
2. Confirm no pending coordinated disclosures reference the affected findings
3. Revoke and destroy the `FINDINGS_ENC_KEY` from the secrets manager
4. Overwrite the key material in all backup locations
5. Record the key destruction event in the audit log with operator identity
6. Retain the audit log entry recording the destruction (7-year retention)

For individual finding destruction:
1. Execute `DELETE FROM findings WHERE finding_id = $1` to remove encrypted columns
2. Record the deletion in the audit log with justification and operator identity
3. The encrypted data is unrecoverable once the database row is deleted

### 4.2 Audit Log Archival

Audit logs must be archived before destruction of associated findings:

Procedure:
1. Verify hash chain integrity: run `verify_chain()` (`harness/audit.py:93-123`)
2. Copy the audit JSONL file to immutable archival storage
3. Verify the archived copy by re-running hash chain verification on the archive
4. Record the archival event (archive location, hash of final entry, entry count)
5. The original file may be removed from operational storage after archival confirmation

### 4.3 Database Record Destruction

For non-encrypted database records (runs, jobs, finding metadata):

Procedure:
1. Identify all records past their retention period
2. Verify no audit log entries reference the records that have not been archived
3. Execute deletion in dependency order: `findings` -> `jobs` -> `runs`
4. Record the bulk deletion in the audit log (run_ids deleted, count, operator, justification)
5. Run `VACUUM` on affected tables to reclaim storage

### 4.4 Redis Data Destruction

Redis queue data is transient by design:

Procedure:
1. After run completion + 24 hours, expire all `job:{run_id}:*` and `queue:{run_id}` keys
2. Expire `spend:{run_id}` keys
3. No audit log entry required (Redis data is operational, not compliance)

### 4.5 Container Artifact Destruction

Container artifacts are automatically destroyed (P5):

- `--rm` flag on `docker run` ensures container removal on exit (`harness/dispatcher.py:34`)
- tmpfs mounts are kernel-managed and cleared on unmount
- No operator action required

Verification: confirm no stopped containers remain with `docker ps -a --filter name=worker-*`

### 4.6 Human Review Report Destruction

Markdown reports in `{run_dir}/findings/`:

Procedure:
1. Verify the associated finding record has been retained for the required period
2. Securely delete the markdown file (use `shred` on Linux, or equivalent secure delete)
3. Record the deletion in the audit log

---

## 5. Regulatory Considerations

### 5.1 FINRA / SOX

**FINRA Rule 4511** requires broker-dealers to preserve books and records for periods specified in SEA Rules 17a-3 and 17a-4. For Mantis deployed in financial services:

- Audit logs constitute business records of security testing activities and must be retained for 6 years (first 2 years in readily accessible storage)
- The SHA-3 hash chain satisfies the "non-rewriteable, non-erasable" requirement for electronic storage (SEC Rule 17a-4(f))
- Human review sign-offs constitute supervisory records

**SOX Section 802** imposes criminal penalties for knowingly destroying audit workpapers within the retention period:

- All audit log files must be preserved for minimum 7 years
- Destruction must follow documented procedures with approvals
- Audit log archival to immutable storage is recommended within 24 hours of run completion

### 5.2 GDPR / CCPA

Mantis scans open-source software, not personal data. However:

**GDPR Article 5(1)(e)** (storage limitation): Data should be kept only as long as necessary.
- Worker artifacts (tmpfs) satisfy this by being destroyed immediately
- Finding data retained only for stated periods
- Cryptographic erasure provides a GDPR-compliant destruction mechanism

**GDPR Article 17** (right to erasure): If Mantis processes any data that could be linked to an individual (e.g., commit author names in source code):
- Audit logs may reference file paths that include author names
- Gap: no automated PII detection or redaction in audit log payloads
- Mitigation: audit log payloads focus on operational metadata, not source content

**CCPA Section 1798.105**: Similar right to deletion.
- Cryptographic erasure satisfies CCPA deletion requirements for encrypted findings
- Non-encrypted metadata in `runs`/`jobs` tables can be deleted per procedure 4.3

### 5.3 FedRAMP / FISMA

For federal government deployment:

**NIST SP 800-53 AU-11** (audit record retention): Audit records retained per organizational policy (this document specifies 7 years).

**NIST SP 800-53 SI-12** (information management and retention): Data handled in accordance with applicable laws, policies, and regulations (satisfied by this policy).

**NIST SP 800-53 MP-6** (media sanitization): Cryptographic erasure is an approved sanitization method per NIST SP 800-88 Rev. 1 for data encrypted with approved algorithms (AES-256-GCM qualifies).

---

## 6. Key Management

### 6.1 FINDINGS_ENC_KEY Lifecycle

| Phase | Procedure |
|-------|-----------|
| Generation | Generate 32 bytes from CSPRNG (`os.urandom(32)`), base64-encode |
| Storage | Secrets manager (Vault, AWS Secrets Manager, Azure Key Vault) in production; environment variable in dev |
| Distribution | Injected at runtime via environment variable (`harness/crypto.py:30-37`) |
| Rotation | Generate new key, re-encrypt all active findings with new key, destroy old key |
| Destruction | Revoke from secrets manager, overwrite in all backup locations, record in audit log |

### 6.2 Rotation Schedule

| Key Type | Rotation Frequency | Trigger Events |
|----------|-------------------|----------------|
| FINDINGS_ENC_KEY | Annual or on compromise | Personnel change, suspected breach, compliance audit |
| API keys (LLM providers) | Per provider policy | Personnel change, suspected misuse |
| POSTGRES_PASSWORD | Quarterly | Personnel change, suspected breach |
| REDIS_PASSWORD | Quarterly | Personnel change, suspected breach |

---

## 7. Policy Review

This policy must be reviewed:
- Annually at minimum
- When regulatory requirements change
- When the data architecture changes (new data types, new storage locations)
- After any data breach or security incident
- When deploying to a new regulatory jurisdiction

**Approval required from**: Security Operations Lead and Compliance Officer
