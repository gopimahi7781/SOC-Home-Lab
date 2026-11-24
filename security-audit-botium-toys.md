# Security Audit — Botium Toys (NIST CSF)

*Internal security audit completed as the capstone portfolio activity of the Google Cybersecurity Professional Certificate. The audit assesses Botium Toys' security posture against the NIST Cybersecurity Framework (CSF) and relevant compliance standards, and recommends improvements.*

---

## 1. Scenario

Botium Toys is a small U.S. toy company with a single physical location and a fast-growing online store that now ships internationally, including to the EU. The IT manager requested an internal security audit to understand the current security posture, identify gaps, and prepare the business for growth and regulatory compliance.

---

## 2. Scope & Goals

**Scope:** The entire security program — assets managed by the IT department, internal processes, existing controls, and applicable compliance obligations.

**Goals:**
- Assess the current security posture.
- Identify gaps in administrative, technical, and physical controls.
- Recommend improvements and prioritise compliance work (PCI DSS, GDPR).

**Framework used:** NIST Cybersecurity Framework (Identify, Protect, Detect, Respond, Recover), plus a controls and compliance checklist.

---

## 3. Current Assets

Assets managed by the IT department that require protection:

- On-premises equipment (office network, servers)
- Employee devices (laptops, desktops, company phones)
- Accounting system (stores customer **payment card** information)
- Company website (e-commerce, accepts online orders)
- Internet access and internal network
- Management of systems/infrastructure hosted in a third-party data centre

---

## 4. Risk Assessment

| Item | Finding |
|------|---------|
| **Risk score** | **8 / 10 (High)** |
| **Why** | Payment and customer data are handled, but key controls (least privilege, encryption, IDS, backups, MFA) are missing. The business also faces PCI DSS and GDPR obligations it does not yet meet. |

The company has a working firewall and dedicated antivirus, but lacks the layered controls expected for a business that stores payment and personal data.

---

## 5. Controls Assessment

"Yes" = control is adequately in place. "No" = control is missing or needs improvement.

### Administrative controls
| Control | In place? | Notes |
|---------|-----------|-------|
| Least Privilege | **No** | All employees have broad access to customer data. |
| Disaster Recovery Plan | **No** | No documented DR/business-continuity plan. |
| Password Policy | **No** | No complexity or rotation requirements enforced. |
| Separation of Duties | **No** | The CEO handles both daily operations and payroll. |

### Technical controls
| Control | In place? | Notes |
|---------|-----------|-------|
| Firewall | **Yes** | Blocks unwanted traffic by policy. |
| Intrusion Detection System (IDS) | **No** | No IDS to detect malicious activity. |
| Encryption | **No** | Data at rest / in transit is not encrypted. |
| Backups | **No** | No regular backups of critical data. |
| Password Management System | **No** | No central password manager. |
| Antivirus | **Yes** | Installed, but should be kept updated. |
| Multi-Factor Authentication (MFA) | **No** | Not enforced for privileged accounts. |

### Physical controls
| Control | In place? | Notes |
|---------|-----------|-------|
| Locks (offices / storefront) | **Yes** | Physical premises are locked. |
| CCTV Surveillance | **No** | No camera coverage. |
| Fire Detection / Suppression | **No** | No fire-detection system. |

---

## 6. Compliance Checklist

| Standard | Applies? | Why |
|----------|----------|-----|
| **PCI DSS** | **Yes** | Botium Toys stores and processes credit-card payments. |
| **GDPR** | **Yes** | It serves customers in the EU and handles their personal data (PII). |
| **SOC 1 / SOC 2** | **Yes** | Relevant for protecting the integrity and privacy of financial and customer data. |

None of these are currently satisfied — closing the control gaps above is required to reach compliance.

---

## 7. Recommendations (Prioritised)

1. **Least privilege & separation of duties** — restrict access to customer and payment data to only the roles that need it.
2. **Encryption** — encrypt payment and personal data at rest and in transit (required for PCI DSS / GDPR).
3. **Deploy an IDS** — add detection for malicious activity (supports NIST "Detect").
4. **Strong authentication** — enforce a password policy, add MFA for privileged accounts, and adopt a password manager.
5. **Backups & Disaster Recovery** — implement regular backups and a documented DR plan (NIST "Recover").
6. **Physical controls** — add CCTV and fire detection.
7. **Compliance** — complete PCI DSS and GDPR requirements as the priority, given payment and EU customer data.

---

## 8. Summary

Botium Toys has a basic perimeter (firewall, antivirus, locks) but is **high risk (8/10)** because it stores payment and personal data without least privilege, encryption, detection, backups, or MFA, and does not yet meet PCI DSS or GDPR. Implementing the recommendations above — starting with access control, encryption, and compliance — would significantly reduce risk and prepare the company for growth.

---

## Skills Demonstrated

- Conducting an internal security audit using the **NIST Cybersecurity Framework**
- Asset inventory and **risk assessment** (risk scoring)
- Evaluating **administrative, technical, and physical controls**
- Mapping obligations to **compliance standards** (PCI DSS, GDPR, SOC)
- Writing prioritised, business-focused security recommendations
