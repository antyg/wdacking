# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-02-19

### Added

- **Policy Management** (9 functions)
  - `ConvertFrom-WDACBinary` — Convert CI policy binary data to SiPolicy XML via pure-PowerShell pipeline with automatic PKCS#7 unwrapping
  - `Get-WDACPolicy` — Enumerate deployed CI policies with full metadata: PolicyId, BasePolicyId, FriendlyName (extracted from binary Settings), Version, EnforcementMode, PolicyType, RuleOptions (Id + Name pairs), IsDuplicate annotation. Parses PKCS#7 signed and unsigned policies from MultiPolicy, Legacy, and EFI deployment locations
  - `Get-WDACPolicyStatus` — CI enforcement status via WMI + WLDP runtime lockdown bitmask
  - `Get-WDACPolicyFile` — Parse CI policy binary files (format v7+)
  - `Set-WDACPolicy` — Set CI policy binary as active on the system
  - `Remove-WDACPolicy` — Remove deployed CI policy by GUID
  - `Invoke-WDACPolicyRefresh` — CI policy refresh via `NtSetSystemInformation`
  - `Test-WDACEnforcement` — Test WDAC enforcement state via WLDP API
  - `Get-WDACEventLog` — Query CI and AppLocker event logs

- **Trust Token Management** (3 functions)
  - `Get-WDACToken` — Enumerate CI trust tokens via NT API with cache file fallback
  - `Add-WDACToken` — Add CI trust token
  - `Remove-WDACToken` — Remove CI trust token

- **Device Security Telemetry** (7 functions)
  - `Get-WDACDeviceSecurity` — SecureBoot, TPM, VBS, HVCI, DMA Protection
  - `Get-WDACSpeculationMitigation` — Spectre, Meltdown, MDS, L1TF, SpecCtrl enumeration via NT API
  - `Get-WDACFirmwareSecurity` — BIOS/UEFI, Secure Launch via WMI + NT API
  - `Get-WDACDefenderStatus` — Defender real-time status via WMI
  - `Get-WDACExploitProtection` — DEP, ASLR, CFG, CET, IFEO overrides
  - `Get-WDACHypervisorDetail` — CPUID leaf 0x40000000 hypervisor vendor detection
  - `Get-WDACMemoryEncryption` — CPUID-based Intel TME/MKTME and AMD SEV/ES/SNP

- **Security Posture Reporting** (1 function)
  - `Get-WDACSecurityPosture` — Aggregated security posture across all Get-*/Test-* functions
  - Semantic domains: Platform, BootChain, HardwareSecurity, Virtualisation,
    CPUMitigations, ExploitProtection, EndpointProtection, ApplicationControl
  - Tiered authority deduplication (CPUID > NtApi > WMI > Registry > Heuristic)
  - Stubbed verdict system (`NotEvaluated`) per domain for future scoring

- **Binary Parsing Pipeline** (10 private functions)
  - `Unprotect-Pkcs7Policy` — PKCS#7 SignedData unwrapping via `SignedCms` (.NET Framework + .NET Core)
  - `Read-BinaryHeader` — 68-byte CI policy header parser (FormatVersion, PolicyTypeID, PlatformID, OptionFlags, section counts, PolicyVersion)
  - `Read-BinaryString` — Length-prefixed Unicode string reader
  - `Read-BinaryEKU` — EKU entry parser
  - `Read-BinaryFileRule` — FileRule entry parser with rule level detection
  - `Read-BinarySigner` — Signer entry parser with TBS hash extraction
  - `Read-BinaryScenario` — SigningScenario entry parser
  - `Read-BinarySettings` — Settings/PolicyInfo section parser (FriendlyName, Id extraction)
  - `Read-BinaryVBlocks` — V3-V8 versioned block parser (PolicyId, BasePolicyId extraction)
  - `ConvertTo-WDACPolicyObject` — XML-to-output-contract adapter (13-property PSCustomObject)

- **Scripts**
  - *Production*
    - `scripts/Get-EndpointSecurityReport.ps1` — Consolidated endpoint security report
      with console and JSON output, cross-edition normalisation (2-space indent, ISO 8601, no BOM)
    - `scripts/Test-WDACDataIntegrity.ps1` — Cross-source conflict validation for 7 overlapping fields
  - *Diagnostics*
    - `scripts/Test-WDACBinaryParser.ps1` — End-to-end binary parser validation (8 test categories:
      header, rule options, supplemental, FriendlyName, system policies, PKCS#7, edge cases, cross-reference)
    - `scripts/Test-ConvertFromWDACBinary.ps1` — ConvertFrom-WDACBinary function validation
    - `scripts/Invoke-KnownPlaintextAnalysis.ps1` — Known-plaintext binary format analysis tool
    - `scripts/Invoke-KnownPlaintextVariants.ps1` — Binary format variant generation for test coverage

- **Testing**
  - 86 Pester tests across 2 test files
  - `tests/ConvertFrom-WDACBinary.Tests.ps1` — 21 tests (header parsing, section traversal,
    V-block extraction, error handling)
  - `tests/ConvertTo-WDACPolicyObject.Tests.ps1` — 65 tests (output contract, PolicyType
    classification, RuleOptions reverse mapping, FriendlyName, enforcement mode, fallback behaviour)

- **Documentation**
  - `docs/ci-binary-format-reference.md` — Comprehensive CI policy binary format reference
    (header layout, OptionFlags bitmask, PolicyTypeID catalogue, body sections, versioned blocks,
    PKCS#7 detection)

- **Architecture**
  - Hybrid approach: inline C# via `Add-Type` with P/Invoke for telemetry and NT API functions;
    pure-PowerShell pipeline for binary parsing
  - Binary parsing pipeline: `ReadAllBytes -> Unprotect-Pkcs7Policy -> ConvertFrom-WDACBinary -> ConvertTo-WDACPolicyObject`
  - Native CPUID instruction execution via 24-byte x64 machine code
  - Cross-edition compatibility (PS 5.1 / pwsh 7+) with four assembly reference profiles
  - Tiered detection: CPUID > NT API > WMI > Registry > Heuristic fallback
  - Cross-edition JSON output normalisation (consistent 2-space indent, ISO 8601 dates, no BOM)

[1.0.0]: https://github.com/antyg/wdacking/releases/tag/v1.0.0
