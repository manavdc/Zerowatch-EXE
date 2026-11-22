# ZeroWatch OTA Updates: Industry-Standard Architecture & Specification

**Document Version:** 1.0  
**Target Product:** ZeroWatch Enterprise Endpoint Security Platform  
**Scope:** Over-the-Air (OTA) Binary Updates, Cryptographic Supply Chain Security, and Enterprise Distribution  

---

## Executive Summary

In enterprise endpoint security (e.g., CrowdStrike Falcon, SentinelOne, Datadog Agent, Wazuh), agent updates must never be served directly from an engineer's personal repository (such as `github.com/manavdc/...`). 

To meet SOC 2, ISO 27001, FedRAMP, and enterprise procurement requirements, ZeroWatch must adopt the industry-standard four-pillar architecture for Over-the-Air (OTA) updates.

---

## 🏛️ The Four Pillars of Enterprise Agent Distribution

```
┌────────────────────────────────────────────────────────────────────────┐
│                   INDUSTRY STANDARD OTA PIPELINE                      │
└────────────────────────────────────────────────────────────────────────┘

  [ CI / CD Release Pipeline (GitHub Actions / GitLab CI) ]
               │
               ▼
  [ 1. Air-Gapped Code Signing & Manifest Generation ]
  - Authenticode Signing (Windows .exe / .msi)
  - Apple Developer ID Application Signing & Notarization (macOS)
  - Detached Ed25519 Cryptographic Signature on release-manifest.json
               │
               ▼
  [ 2. Enterprise Cloud Storage Bucket (Origin Storage) ]
  - Amazon S3 / Google Cloud Storage / Azure Blob
  - Private bucket, versioning enabled, strict IAM & WORM immutability
               │
               ▼
  [ 3. Global CDN on Dedicated Corporate Domain ]
  - Endpoint: https://updates.deepcytes.io/agent/releases/latest
  - Cloudflare / AWS CloudFront caching with DDoS mitigation & geo-routing
               │
               ▼
  [ 4. Phased Canary Rollout Rings ]
  - Ring 0 (Internal / Dogfood: 5%)
  - Ring 1 (Canary Pilot Customers: 20%)
  - Ring 2 (General Availability Fleet: 100%)
```

---

## 1. Dedicated Corporate Domain via CDN

### Standard
All endpoints query an official, company-owned distribution endpoint:
```
https://updates.deepcytes.io/agent/releases/latest/release-manifest.json
```

### Why This Is Mandatory for Enterprise Clients
1. **Corporate Firewall & Proxy Compatibility:**  
   Most enterprise security policies block direct executable downloads from `github.com/.../releases/download/...` to prevent employees from pulling unauthorized scripts or unvetted open-source tools. Enterprise firewall policies whitelist the vendor's dedicated domain (`*.deepcytes.io`).
2. **High Availability & Low Latency:**  
   Using a global CDN (e.g., Cloudflare Enterprise or AWS CloudFront) ensures edge caching across geographic regions, reducing egress load and eliminating GitHub API rate-limiting restrictions.
3. **Institutional Continuity & Brand Trust:**  
   If an engineer leaves the organization, changes their GitHub handle, or closes their account, customer fleet updates are completely unaffected.

---

## 2. Air-Gapped Cryptographic Signature Verification

### Standard
* **Private Signing Key:**  
  Stored in an enterprise Secret Manager / Hardware Security Module (HSM) (e.g., AWS KMS, HashiCorp Vault, or GitHub Actions Environment Secrets protected by required approvals). The private key is never embedded in binaries or shared across team members.
* **Public Verification Key:**  
  The corresponding public verification key is embedded directly into the compiled agent binary.

### Client-Side Verification Process
When an update is staged on the endpoint, the agent executes three mandatory checks before executing or swapping binaries:

```
[ Download Staged Binary + Manifest ]
                 │
                 ▼
  ┌───────────────────────────────┐
  │ Check 1: Cryptographic Sig   │ ──(Fail)──> Reject & Log Tamper Attempt
  │ Verify Ed25519 signature on   │
  │ release-manifest.json         │
  └───────────────────────────────┘
                 │ (Pass)
                 ▼
  ┌───────────────────────────────┐
  │ Check 2: Checksum Integrity   │ ──(Fail)──> Discard Corrupt Binary
  │ Compute SHA-256 of new binary │
  │ Compare with manifest hash   │
  └───────────────────────────────┘
                 │ (Pass)
                 ▼
  ┌───────────────────────────────┐
  │ Check 3: Anti-Downgrade Check │ ──(Fail)──> Abort Rollback Attack
  │ candidate_version > current   │
  └───────────────────────────────┘
                 │ (Pass)
                 ▼
     [ Safe Atomic File Swap ]
```

1. **Cryptographic Signature Verification:**  
   Validates the Ed25519 signature over the payload of `release-manifest.json` using the embedded public key.
2. **Payload Checksum Integrity:**  
   Calculates the local SHA-256 hash of the downloaded binary and ensures it matches the signed hash in the manifest.
3. **Rollback Prevention (Anti-Downgrade):**  
   Enforces version monotonicity (`new_version > current_version`). An attacker cannot force the agent to downgrade to a previously signed version that contains known vulnerabilities.

---

## 3. Phased Canary Deployment Rings

### Standard
Rather than pushing an update to 100% of customer endpoints simultaneously, deployments are partitioned into phased rollout rings:

| Ring | Audience | Target Share | Soak Time | Health Validation Criteria |
| :---: | :--- | :---: | :---: | :--- |
| **Ring 0** | **Internal Dogfood Fleet** | 5% | 48 hours | Zero unexpected watchdog restarts; CPU < 2%; memory stable. |
| **Ring 1** | **Canary Pilot Customers** | 15–20% | 72 hours | Heartbeat stability $\ge 99.9\%$; zero false-positive spikes; no network saturation. |
| **Ring 2** | **General Availability (GA)** | 100% | Continuous | Automatic circuit-breaker stops rollout if agent error rate exceeds 0.1%. |

---

## 4. Key Rollover & Safe Transition Strategy

To update signing keys without bricking deployed agents:
1. **Dual-Key Bridge Release:**  
   When migrating to a new Ed25519 signing keypair, release a bridge version signed with the *current* private key. The bridge version embeds *both* the current and new public keys.
2. **Transition:**  
   Once the fleet has updated to the bridge version, subsequent releases are signed with the *new* private key.
3. **Rollback Resilience:**  
   Agents retain a backup of the previous running binary (`.bak`). If the replacement agent fails to start within 5 minutes or crashes in an unhandled loop, the watchdog automatically restores the previous working binary.

