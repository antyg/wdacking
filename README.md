# antyg-wdacking

Windows Defender Application Control (WDAC) and Code Integrity policy management PowerShell module. Provides 20 functions for policy lifecycle management, binary policy parsing, CI trust token operations, event log analysis, security posture reporting, and comprehensive device security telemetry.

## Features

### Policy Management

| Function | Description |
|---|---|
| `ConvertFrom-WDACBinary` | Converts CI policy binary data to SiPolicy XML with automatic PKCS#7 unwrapping |
| `Get-WDACPolicy` | Enumerates all deployed CI policies with full metadata (PolicyId, FriendlyName, enforcement, rule options, IsDuplicate) |
| `Get-WDACPolicyStatus` | Queries per-policy lockdown state via WLDP API (`wldp.dll`) |
| `Get-WDACPolicyFile` | Parses CI policy binary files (format version 7+) |
| `Set-WDACPolicy` | Sets a CI policy binary as active on the system |
| `Remove-WDACPolicy` | Removes a deployed CI policy by GUID |
| `Invoke-WDACPolicyRefresh` | Triggers a CI policy refresh via `NtSetSystemInformation` |
| `Test-WDACEnforcement` | Tests whether WDAC enforcement is active via WLDP API |
| `Get-WDACEventLog` | Queries Code Integrity and AppLocker event logs for policy events |

### Trust Token Management

| Function | Description |
|---|---|
| `Get-WDACToken` | Enumerates CI trust tokens (ManagedInstaller, ISG, DynamicCodeTrust) |
| `Add-WDACToken` | Adds a new CI trust token |
| `Remove-WDACToken` | Removes an existing CI trust token |

### Device Security Telemetry

| Function | Description |
|---|---|
| `Get-WDACDeviceSecurity` | Comprehensive device security overview (SecureBoot, TPM, VBS, HVCI, DMA Protection) |
| `Get-WDACSpeculationMitigation` | CPU speculation mitigations via `NtQuerySystemInformation` (Spectre, Meltdown, MDS, L1TF) |
| `Get-WDACFirmwareSecurity` | Firmware and UEFI security configuration (SecureLaunch, BIOS details) |
| `Get-WDACDefenderStatus` | Windows Defender real-time status via WMI (`MSFT_MpComputerStatus`) |
| `Get-WDACExploitProtection` | System-wide exploit mitigations (DEP, ASLR, CFG, CET, IFEO overrides) |
| `Get-WDACHypervisorDetail` | Hypervisor vendor, VBS, and HVCI state via CPUID leaf 0x40000000 |
| `Get-WDACMemoryEncryption` | CPU memory encryption capabilities (Intel TME/MKTME, AMD SEV/ES/SNP) via CPUID |

### Security Posture Reporting

| Function | Description |
|---|---|
| `Get-WDACSecurityPosture` | Aggregated security posture across all 12 Get-\*/Test-\* source functions |

Organises telemetry into semantic domains (Platform, BootChain, HardwareSecurity, Virtualisation, CPUMitigations, ExploitProtection, EndpointProtection, ApplicationControl) with tiered authority deduplication (CPUID > NtApi > WMI > Registry > Heuristic).

## Requirements

- **PowerShell**: 5.1 (Windows PowerShell) or 7+ (pwsh)
- **OS**: Windows 10 / Windows 11 / Windows Server 2016+
- **Privileges**: Administrator elevation required for all functions
- **Architecture**: x64 (required for CPUID-based detection functions)

## Installation

```powershell
# Clone the repository
git clone https://github.com/antyg/wdacking.git

# Import the module
Import-Module ./wdacking/src/antyg-wdacking.psd1

# Verify
Get-Module antyg-wdacking
```

## Quick Start

```powershell
# Import the module
Import-Module antyg-wdacking

# Get a comprehensive device security overview
Get-WDACDeviceSecurity

# List all deployed WDAC policies with full metadata
Get-WDACPolicy

# Parse a CI policy binary file to SiPolicy XML
ConvertFrom-WDACBinary -Path 'C:\Windows\System32\CodeIntegrity\CiPolicies\Active\{GUID}.cip'

# Aggregated security posture across all telemetry sources
Get-WDACSecurityPosture

# Check hypervisor and VBS state
Get-WDACHypervisorDetail

# Query CPU memory encryption capabilities
Get-WDACMemoryEncryption

# View exploit protection configuration
Get-WDACExploitProtection

# Check Windows Defender status
Get-WDACDefenderStatus

# Enumerate CI trust tokens
Get-WDACToken

# Refresh CI policies
Invoke-WDACPolicyRefresh
```

## Architecture

### Hybrid C# and PowerShell

The module uses two complementary approaches:

- **Inline C# via `Add-Type`** — Telemetry and NT API functions use compiled C# classes with P/Invoke declarations for direct access to NT APIs (`NtQuerySystemInformation`, `NtSetSystemInformation`), WLDP API (`wldp.dll`), Win32 API (`kernel32.dll`), and native CPUID instruction execution.

- **Pure-PowerShell binary parsing pipeline** — `ConvertFrom-WDACBinary` and `Get-WDACPolicy` use 10 private PowerShell functions to decompose CI policy binary files into SiPolicy XML. This approach handles PKCS#7 signed policies (via `SignedCms`), extracts FriendlyName from binary Settings sections, and supports all binary format versions (V1-V9).

### Binary Parsing Pipeline

`ConvertFrom-WDACBinary` orchestrates the binary-to-XML conversion through a chain of focused private functions:

```
[byte[]] Raw file bytes
  |
  v
Unprotect-Pkcs7Policy        -- Strip PKCS#7 SignedData envelope (if present)
  |
  v
Read-BinaryHeader             -- Parse 68-byte header (format version, GUIDs,
  |                              OptionFlags bitmask, section counts, version)
  v
Read-BinaryEKU               \
Read-BinaryFileRule            |-- Parse body sections using counts from header
Read-BinarySigner              |   Each reader advances a shared BinaryReader
Read-BinaryScenario           /
  |
  v
Read-BinarySettings           -- Parse Settings section (FriendlyName, PolicyInfo)
  |
  v
Read-BinaryVBlocks            -- Parse V3-V8 versioned blocks (PolicyId, BasePolicyId,
  |                              count-prefixed index arrays)
  v
[XmlDocument] SiPolicy XML    -- Assembled from all parsed sections
```

`Get-WDACPolicy` extends this pipeline by passing the XML through `ConvertTo-WDACPolicyObject`, which transforms the XML into a 13-property output contract with PolicyType classification, RuleOptions reverse mapping, and file metadata.

PKCS#7 detection uses a first-byte check: `0x30` (ASN.1 SEQUENCE tag) indicates a signed policy. The `Unprotect-Pkcs7Policy` function unwraps via `System.Security.Cryptography.Pkcs.SignedCms` on both PS 5.1 (.NET Framework) and pwsh 7+ (.NET Core).

### CPUID Execution Engine

`Get-WDACMemoryEncryption` and `Get-WDACHypervisorDetail` execute the CPUID instruction directly from user mode using dynamically emitted x64 machine code:

```
VirtualAlloc(PAGE_EXECUTE_READWRITE)
  -> Marshal.Copy(24-byte CPUID wrapper)
  -> Marshal.GetDelegateForFunctionPointer
  -> Execute via delegate with GCHandle-pinned output buffer
  -> VirtualFree in finally block
```

The 24-byte x64 machine code follows the Microsoft x64 calling convention:

```asm
push rbx              ; save callee-saved RBX (CPUID clobbers it)
mov  eax, ecx         ; leaf  (1st arg RCX -> EAX)
mov  ecx, edx         ; subleaf (2nd arg RDX -> ECX)
cpuid                 ; execute -- returns EAX, EBX, ECX, EDX
mov  [r8+0],  eax     ; store results at output pointer (3rd arg R8)
mov  [r8+4],  ebx
mov  [r8+8],  ecx
mov  [r8+12], edx
pop  rbx              ; restore RBX
ret
```

CPUID leaves used:

| Leaf | Purpose |
|---|---|
| `0x00000000` | CPU vendor string + max standard leaf |
| `0x00000001` | Feature flags (ECX[31] = hypervisor present) |
| `0x00000007` | Extended features (ECX[13] = Intel TME capability) |
| `0x0000001B` | Intel TME-MK enumeration (algorithms, MKTME key count) |
| `0x40000000` | Hypervisor vendor signature (EBX+ECX+EDX) |
| `0x80000000` | Max extended leaf (AMD) |
| `0x8000001F` | AMD SEV/SEV-ES/SEV-SNP capabilities |

### Cross-Edition Compatibility

The module works on both Windows PowerShell 5.1 (.NET Framework 4.x) and pwsh 7+ (.NET Core / .NET 9.0). Assembly references differ between editions:

- **.NET Framework**: Most assemblies are implicitly available
- **.NET Core**: Requires explicit references (`System.Security.Principal.Windows`, `System.Security.Claims`, `System.Collections`, `System.Management`, `Microsoft.Win32.Registry`, `System.Security.Cryptography.Pkcs`, etc.)

The module loader (`src/antyg-wdacking.psm1`) defines four assembly reference profiles that each function uses via its `-ReferencedAssemblies` parameter:

| Profile | Assemblies | Used By |
|---|---|---|
| `$CIRefBase` | Security, Claims, Collections, RegularExpressions, Cryptography.Pkcs | Functions with elevation checks + binary parsing pipeline |
| `$CIRefWmi` | Base + Management, ComponentModel | Functions using WMI |
| `$CIRefWmiReg` | WMI + Registry | Functions using WMI + Registry |
| `$CIRefEvt` | Base + EventLog | Event log functions |

### Detection Architecture

Functions use a tiered detection strategy, querying the most authoritative source first:

1. **CPUID** (hardware truth) - Definitive capability detection from CPU microcode
2. **NtQuerySystemInformation** (kernel) - OS-level security state from the NT kernel
3. **WMI** (management layer) - Windows Management Instrumentation queries
4. **Registry** (configuration) - System configuration and enablement status
5. **Heuristic fallback** - Best-effort detection from indirect indicators

Enablement status for hardware features (TME, SEV) requires MSR access (ring 0), which is unavailable from user mode. Registry is used as a proxy, with results clearly labelled as `"BIOS-Controlled"` when the activation state cannot be confirmed.

## Function Reference

### ConvertFrom-WDACBinary

Converts CI policy binary data (`.cip` or `.p7b`) to a SiPolicy `[XmlDocument]`. Accepts either raw bytes (`-Data [byte[]]`) or a file path (`-Path [string]`). Automatically detects and unwraps PKCS#7 signed policies. Supports binary format versions 1-9.

### Get-WDACPolicy

Enumerates all deployed CI policies from three locations: MultiPolicy (`CiPolicies\Active\*.cip`), Legacy (`SIPolicy.p7b`), and EFI partition. Returns 13-property objects including FriendlyName (extracted from binary Settings), IsDuplicate annotation (flags policies sharing a PolicyId across locations), and RuleOptions as `@{Id; Name}` pairs. Supports `-Name` (wildcards) and `-PolicyId` (GUID) filters.

### Get-WDACSecurityPosture

Aggregates all 12 Get-\*/Test-\* source functions into a single PSCustomObject organised into semantic domains: Platform identity, SecurityPosture (6 sub-domains), ApplicationControl (enforcement, policies with hierarchy and orphan detection, trust tokens, recent events), and Verdicts (stubbed for future scoring). Overlapping fields are deduplicated using tiered authority.

### Get-WDACDeviceSecurity

Returns a comprehensive security posture assessment including SecureBoot, TPM version, VBS status, HVCI, Credential Guard, DMA Protection, and kernel DMA protection state.

### Get-WDACSpeculationMitigation

Queries `NtQuerySystemInformation` with info classes `0xC9` (SystemSecureSpeculationControlInformation) and `0xC4` for CPU speculation mitigation status including Spectre v1/v2, Meltdown (KVAS), MDS, L1TF, SSBD, and branch prediction barriers.

### Get-WDACExploitProtection

Queries system-wide exploit protection via `kernel32!GetSystemDEPPolicy` for DEP and registry `MitigationOptions` bitmask for ASLR, CFG, CET shadow stacks, and other mitigations. Enumerates per-process IFEO overrides from Image File Execution Options.

### Get-WDACHypervisorDetail

Identifies the hypervisor vendor by executing CPUID leaf `0x40000000` directly, parsing the 12-byte vendor signature (e.g., `"Microsoft Hv"` for Hyper-V). Falls back to `NtQuerySystemInformation(0xC5)` then registry/WMI heuristics. Also reports VBS status, HVCI state, and nested virtualisation configuration.

### Get-WDACMemoryEncryption

Detects hardware memory encryption by executing CPUID leaf 7 (ECX[13] for Intel TME) and leaf `0x8000001F` (EAX bits for AMD SEV/ES/SNP). Reports supported algorithms from CPUID leaf `0x1B` (AES-XTS-128/256) and MKTME key counts. Registry is used only for enablement status since MSR reads require ring 0.

## Scripts

### Production

| Script | Description |
|---|---|
| `Get-EndpointSecurityReport.ps1` | Consolidated endpoint security report with console and JSON output |
| `Test-WDACDataIntegrity.ps1` | Cross-source conflict validation for 7 overlapping telemetry fields |

### Diagnostics

| Script | Description |
|---|---|
| `Test-WDACBinaryParser.ps1` | End-to-end binary parser validation (8 test categories) |
| `Test-ConvertFromWDACBinary.ps1` | ConvertFrom-WDACBinary function validation |
| `Invoke-KnownPlaintextAnalysis.ps1` | Known-plaintext binary format analysis tool |
| `Invoke-KnownPlaintextVariants.ps1` | Binary format variant generation for test coverage |

## Testing

86 Pester tests across 2 test files:

| Test File | Tests | Coverage |
|---|---|---|
| `ConvertFrom-WDACBinary.Tests.ps1` | 21 | Header parsing, section traversal, V-block extraction, error handling |
| `ConvertTo-WDACPolicyObject.Tests.ps1` | 65 | Output contract, PolicyType classification, RuleOptions reverse mapping, FriendlyName, enforcement mode, fallback behaviour |

Run tests:

```powershell
Invoke-Pester ./tests/ -Output Detailed
```

## License

MIT License. See [LICENSE](LICENSE) for details.
