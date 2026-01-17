# QERDS / LRE certification requirements (high level)

This document lists the **absolute, certification-relevant requirements** for providing a **Qualified Electronic Registered Delivery Service (QERDS)** under **eIDAS Article 44**, and the **France “LRE” (lettre recommandée électronique)** requirements under the **CPCE**.

It intentionally stays **high level**: it defines *what must be true* to claim qualification/compliance, not *how to implement it*.

## Scope and disclaimers

- **Qualification is granted to a provider and a service**, not to source code. This project aims to implement a platform that can be operated by a provider seeking qualification.
- “Qualified” claims MUST be made only when the provider/service is actually **qualified and supervised** (e.g., listed appropriately in the EU trusted lists).
- Where there is a tension between “state-of-the-art” and “absolute minimum”, this document follows the **normative requirement** (law/implementing regulation/harmonised standards) and avoids over-prescribing.

## Normative sources (non-exhaustive)

These are the primary sources this document is grounded on:

- **Regulation (EU) No 910/2014 (eIDAS)**, Article 44 (electronic registered delivery services).
- **Commission Implementing Regulation (EU) 2025/1944** (rules for applying eIDAS as regards electronic registered delivery services).
- **ETSI EN 319 521** (policy and security requirements for electronic registered delivery services).
- **ETSI EN 319 401** (general policy requirements for trust service providers).
- **ETSI EN 319 522 (relevant parts)** (ERDS evidence and interoperability; see Implementing Regulation 2025/1944, Annex II for the referenced parts, e.g. EN 319 522-4-1/-4-2/-4-3).
- **France CPCE**, notably Articles **R. 53-1 to R. 53-4** and Article **L. 100** (LRE conditions, evidence and recipient information).
- **GDPR** and applicable national privacy/cybersecurity law (applies to operation even when not “qualification-specific”).

Practical links (official sources):

- eIDAS (EUR-Lex): https://eur-lex.europa.eu/eli/reg/2014/910/oj
- Implementing Regulation (EU) 2025/1944 (EUR-Lex): https://eur-lex.europa.eu/eli/reg_impl/2025/1944/oj
- CPCE L.100 (Légifrance): https://www.legifrance.gouv.fr/codes/article_lc/LEGIARTI000031367432
- CPCE R.53-2 (Légifrance): https://www.legifrance.gouv.fr/codes/article_lc/LEGIARTI000031367428
- CPCE R.53-3 (Légifrance): https://www.legifrance.gouv.fr/codes/article_lc/LEGIARTI000031367426

## Glossary (minimal)

- **ERDS**: Electronic registered delivery service (non-qualified).
- **QERDS**: Qualified ERDS (meets eIDAS qualified requirements).
- **LRE**: Lettre recommandée électronique (France), aligned with eIDAS ERDS with extra CPCE constraints.
- **Evidence**: Electronic data that proves a lifecycle event (sending/receiving/refusal/non-claim, etc.).
- **Qualified e-seal / qualified timestamp**: Qualified trust services used to seal evidence and provide time reference, where required.

## Requirements

Each requirement is normative and is assigned an ID for traceability (used in `README.md`).

### A. Provider qualification, governance, and auditability

- **REQ-A01 (Qualification)**: The service MUST be operated by a provider that is qualified/supervised for the relevant trust service(s) and MUST NOT claim “qualified” otherwise.
- **REQ-A02 (Conformity assessment)**: The provider MUST be able to pass the required conformity assessment(s) and audits for QERDS and related trust services (per eIDAS and applicable harmonised standards).
- **REQ-A03 (Policies and CPS)**: The provider MUST maintain documented policies (security, incident, continuity, key management, evidence management) consistent with ETSI EN 319 401/319 521 and make required parts available to relying parties/auditors.
- **REQ-A04 (Traceability matrix)**: The project MUST maintain a traceability mapping from each requirement ID in this document to implementation modules and verification artifacts (tests/audit evidence).

### B. Core eIDAS Article 44 guarantees (service properties)

- **REQ-B01 (Sending/receiving proof)**: The service MUST provide evidence that supports proving the **sending** and the **receiving** of data, including **date and time** of sending and receiving.
- **REQ-B02 (Integrity)**: The service MUST protect transmitted data against **loss, theft, damage, and unauthorised alterations**, and MUST ensure that any change is detectable.
- **REQ-B03 (Identification)**: The service MUST ensure **identification of the sender and the addressee** (at least to the extent required by the applicable standards and national rules for the use case).
- **REQ-B04 (Qualified presumption)**: For “qualified” status, the service MUST meet the qualified conditions enabling the legal presumption under eIDAS Article 44(2) (i.e., meet the requirements laid down for qualified ERDS).
- **REQ-B05 (Sender identity verification methods)**: The provider MUST verify the identity of the sender with a very high level of confidence using methods permitted by the applicable implementing rules/standards (e.g., in-person ID checks, high-assurance eID/EUDI Wallet, qualified certificates, or other assessed methods).

### C. ERDS process and evidence lifecycle (interoperable and complete)

- **REQ-C01 (Complete event coverage)**: Every legally relevant lifecycle event (submission/deposit, acceptance, notification, availability, receipt, refusal, non-claim/expiry, etc.) MUST generate evidence sufficient to reconstruct the full timeline.
- **REQ-C02 (Evidence authenticity)**: Evidence MUST be protected against forgery and MUST be attributable to the service provider (e.g., by electronic seal/signature as required by the standards/regulation).
- **REQ-C03 (Trusted time)**: Evidence MUST carry a trustworthy time reference consistent with qualified requirements (per Implementing Regulation 2025/1944 and ETSI EN 319 521/522).
- **REQ-C04 (Evidence format/interoperability)**: Evidence structures and interfaces MUST follow the ETSI EN 319 522 parts required for QERDS interoperability (per Implementing Regulation 2025/1944, Annex II).
- **REQ-C05 (Immutability)**: Evidence and audit logs MUST be tamper-evident and protected against undetected modification or deletion for the full retention period.

### D. Security controls (baseline for qualified service)

This section intentionally avoids prescribing specific products, but does require outcomes and minimum assurance levels.

- **REQ-D01 (Security management)**: The provider MUST operate an information security management framework consistent with ETSI EN 319 401/319 521 (risk assessment, controls, monitoring, incident handling).
- **REQ-D02 (Least privilege)**: Administrative and operational access MUST be controlled with least privilege, strong authentication, and separation of duties for sensitive operations.
- **REQ-D03 (Cryptographic mechanisms)**: Cryptographic mechanisms MUST follow the “state of the art” as required by Implementing Regulation 2025/1944 and referenced guidance (e.g., ENISA agreed mechanisms).
- **REQ-D04 (Secure key storage)**: Private keys used to protect qualified evidence MUST be generated/stored/used within appropriately certified secure cryptographic devices/modules, as required by Implementing Regulation 2025/1944 (and any successor rules).
- **REQ-D05 (Vulnerability scanning)**: Vulnerability scanning MUST be performed at least **once per quarter**, consistent with Implementing Regulation 2025/1944 and referenced ETSI requirements.
- **REQ-D06 (Penetration testing)**: Penetration testing MUST be performed at least **once per year**, consistent with Implementing Regulation 2025/1944 and referenced ETSI requirements.
- **REQ-D07 (Network filtering)**: Network security controls (e.g., firewalls) MUST be configured to deny all protocols/accesses not required for operation, consistent with Implementing Regulation 2025/1944 and referenced ETSI requirements.
- **REQ-D08 (Logging and monitoring)**: Security-relevant events MUST be logged, protected, monitored, and reviewable for audits and incident response.
- **REQ-D09 (Continuity and recovery)**: The provider MUST implement business continuity, backup, and disaster recovery controls consistent with ETSI EN 319 401/319 521 and the provider’s qualified obligations.

### E. Confidentiality and access control (content protection)

- **REQ-E01 (Confidentiality)**: The service MUST ensure confidentiality of delivered content against unauthorised access (including by operators not authorised for plaintext).
- **REQ-E02 (Access gating)**: Content availability MUST be controlled such that only the identified/authorised recipient can access the content, consistent with the legal model of ERDS/LRE.
- **REQ-E03 (Data minimisation)**: Notifications and public-facing endpoints MUST minimise personal data exposure consistent with GDPR and LRE constraints.

### F. France LRE (CPCE) specific requirements

These apply when the service is used as an LRE under French law (CPCE).

- **REQ-F01 (Recipient information & access)**: The recipient MUST be provided with the information and access required by CPCE (including permanent access to proof of deposit and proof of receipt, and means for authorised third parties to verify with an identifier).
- **REQ-F02 (Notification content rules)**: The initial notification MUST include the legally required information (including the identity of the provider) and MUST comply with CPCE constraints about what can be revealed before acceptance.
- **REQ-F03 (No sender identity pre-acceptance)**: The sender’s identity MUST NOT be disclosed to the recipient before the recipient accepts/refuses the LRE, as required by CPCE.
- **REQ-F04 (15-day acceptance window)**: The recipient MUST be able to accept/refuse the LRE for at least **15 days** from the notification, as required by CPCE.
- **REQ-F05 (Proof of receipt retention)**: Proof of receipt and related legally required evidence MUST be retained and made available for at least the minimum duration required by CPCE (currently at least **one year** for proof of receipt).
- **REQ-F06 (Consumer consent)**: Where the recipient is a consumer, the service MUST enforce and retain evidence of prior consent to receive LRE electronically, as required by CPCE.
- **REQ-F07 (Human-readable proofs)**: The service MUST generate and make available human-readable evidence artifacts (e.g., PDF receipts for deposit, acceptance, refusal, negligence) compliant with the visual/content models required by CPCE/LRE practice.

### G. Truth in claims (compliance guardrail)

- **REQ-G01 (No misleading claims)**: The project documentation and UI/UX MUST NOT represent the system as “qualified” unless the operational provider/service is qualified, audited, and compliant end-to-end.
- **REQ-G02 (Non-qualified mode labeling)**: If the system supports any non-qualified/dev mode (e.g., non-qualified timestamps/seals), it MUST be clearly labeled as non-qualified and MUST prevent presenting resulting evidence as “qualified”.

### H. Provider operational obligations (and the platform features to support them)

This section captures **operational obligations** that are certification-relevant, and the **technical capabilities** the platform MUST provide so the operator can demonstrate compliance (audits, evidence production, incident response).

These requirements are still high level: they describe *outcomes and artifacts* the operator must be able to produce and what the software must enable (not specific vendor products).

- **REQ-H01 (Audit evidence exportability)**: The platform MUST support exporting an “audit pack” sufficient to support conformity assessment and periodic audits (e.g., evidence samples, system configuration snapshots, cryptographic parameters, relevant policy documents, release/SBOM artifacts).
- **REQ-H02 (Evidence retention controls)**: The platform MUST support retention and retrieval controls to meet legally required retention periods for QERDS and CPCE LRE artifacts (including proofs and verification data needed to validate them later).
- **REQ-H03 (Tamper-evident operational logs)**: The platform MUST produce operational/security logs that are tamper-evident and retention-controlled to support auditability and incident investigations.
- **REQ-H04 (Incident response support)**: The platform MUST provide the technical means to detect, triage, and evidence incidents (alerts, log correlation, exportable timelines) consistent with ETSI EN 319 401/319 521 obligations.
- **REQ-H05 (Change management support)**: The platform MUST support controlled change management (traceable deployments/config changes, change attribution, rollback capability, and audit trails) consistent with qualified provider obligations.
- **REQ-H06 (Access administration and reviews)**: The platform MUST support least-privilege access administration (RBAC/ABAC), strong authentication for administrators, and periodic access review artifacts (exportable reports).
- **REQ-H07 (Key lifecycle ceremony evidence)**: Where qualified keys or equivalent sensitive cryptographic assets are used, the platform and surrounding tooling MUST support producing evidence of key lifecycle events (generation, activation, rotation, revocation) and associated approvals, consistent with the applicable rules.
- **REQ-H08 (Business continuity evidence)**: The platform MUST support backup/restore and disaster recovery exercises with verifiable results (e.g., restore test logs, recovery time evidence) suitable for audits.
- **REQ-H09 (Vulnerability management evidence)**: The platform MUST enable producing audit-ready evidence of vulnerability management activities required for the service (scan/pentest reports, remediation tracking, and exceptions), without relying on third-party hosted providers.
- **REQ-H10 (Customer support and disputes evidence)**: The platform MUST support producing dispute-resolution artifacts (item timeline reconstruction, evidence chain verification outputs, and controlled disclosure exports) while respecting confidentiality and data minimisation.
