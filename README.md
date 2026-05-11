# Astar-bug-report

Security vulnerability reports and proof-of-concept exploits for Astar Network smart contracts and frontend applications.

> **Disclaimer:** All research in this repository is conducted in accordance with responsible disclosure practices. Vulnerabilities are reported privately to project teams before any public disclosure.

## 📋 Contents

| File | Description |
|---|---|
| `REPORT.md` | Detailed security vulnerability report |
| `POC.html` | Interactive browser-based proof of concept |
| `src/AstarXSS.t.sol` | Foundry simulation of the attack vector |
| `foundry.toml` | Foundry configuration |

---

## 🔴 VULNERABILITY: Stored XSS via `javascript:` Protocol URL

**Severity:** CRITICAL | **CVSS:** 9.0 | **CWE:** CWE-79 (XSS)

### Summary

The DApp Builder registration form in Astar DApp Staking accepts and stores arbitrary `javascript:` protocol URLs as social account links. Because `validator.isURL()` in `Validators.ts` does not restrict allowed protocols, payloads like `javascript:alert(document.domain)` pass validation. When rendered in the public DApp page (`Builders.vue`), the URL is placed directly into an `<a href>` attribute, causing **persistent XSS** on every visitor.

### Affected Files

- `src/components/common/Validators.ts` — `isUrlValid()` with no protocol whitelist
- `src/staking-v3/components/dapp/Builders.vue` — Social URL rendered as `<a :href>`

### Impact

- Session hijacking
- Cryptocurrency wallet drain (`eth_requestAccounts` phishing)
- Credential theft (cookies, localStorage)
- Persistent phishing overlays on Astar platform

### Root Cause

```typescript
// ❌ VULNERABLE — No protocol whitelist
export const isUrlValid = (url: string): boolean =>
  url ? validator.isURL(url) : false;

// ✅ FIXED — Lock down protocols
export const isUrlValid = (url: string): boolean =>
  url ? validator.isURL(url, {
    protocols: ['http', 'https'],
    require_protocol: true,
    require_tld: true,
  }) : false;
```

### View PoC

Open `POC.html` in any browser to interact with the live demonstration.

---

## 🛠️ Foundry PoC

```bash
# Install
forge install

# Run tests
forge test -vvv

# Expected: All tests pass, demonstrating:
#   1. XSS payload passes vulnerable validator
#   2. XSS payload blocked by secure validator
#   3. Benign https:// URLs accepted by both
#   4. data: protocol blocked by secure validator
```

---

## 🗺️ Vulnerability Map

```
DApp Builder Registration Form
    ├── GitHub Account URL      → validator.isURL() ← NO PROTOCOL WHITELIST [XSS ENTRY]
    ├── Twitter Account URL     → validator.isURL() ← NO PROTOCOL WHITELIST [XSS ENTRY]
    └── LinkedIn Account URL    → validator.isURL() ← NO PROTOCOL WHITELIST [XSS ENTRY]
            │
            ▼ Stored on-chain/backend (PERSISTENT)
            │
    Builders.vue (PUBLIC PAGE)
            │
            ├── <a :href="team.githubAccountUrl">     ← RENDERS RAW URL [XSS SINK]
            ├── <a :href="team.twitterAccountUrl">    ← RENDERS RAW URL [XSS SINK]
            └── <a :href="team.linkedInAccountUrl">   ← RENDERS RAW URL [XSS SINK]
                    │
                    ▼ Victim clicks → XSS executes
                    │
                    └── Session hijacked, wallet drained, credentials stolen
```

---

*For authorized security research and responsible disclosure only.*