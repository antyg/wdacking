# antyg-wdacking Roadmap

High-level design for planned capabilities beyond the v1.0.0 baseline.

Phase 0 is the baseline-correctness prerequisite: the decoder (`ConvertFrom-WDACBinary`)
must produce an honest and canonical XML representation of the binary before any downstream
phase can build on its output. Phases 1-3 then build on each other: extract intelligence
from what's happening on devices (Phase 1), use that intelligence to generate policy
(Phase 2), then deploy policy at scale via Intune (Phase 3).

```text
Phase 0                       Phase 1                    Phase 2                    Phase 3
Decoder Canonical Alignment > Event Log Intelligence --> Policy XML Generation -->  Graph API Deployment
(read correctly)              (observe)                  (author)                   (deploy)
```

---

## Phase 0 — Decoder Canonical Alignment

**Domain folder:** `src/private/BinaryParsing/` + `src/public/Policy/`

### Intent

Establish honest and canonical representation of WDAC policies via `ConvertFrom-WDACBinary`.
The decoder must surface every field the binary actually carries (the FilePath / FileName /
Hash / PackageFamilyName discriminators; V3-V5 secondary attributes; V7 path data) and emit
idiomatic XML (4-digit uppercase hex IDs, FriendlyName suppression, conditional sentinel
suppression, case preservation). This is the foundation for Phase 1+: Event Intelligence
cannot recommend rules accurately if the decoder mis-represents the existing policy state,
and Phase 2 cannot generate policy XML that round-trips through `ConvertFrom-CIPolicy` if
the read path is broken.

### Status (2026-05-17)

| Priority | Item | Status |
|---|---|---|
| P1 | V7 wire-shape rewrite (per-FR FilePath string) | DONE |
| P1 | FilePath attribute emission | DONE |
| P1 | Conditional FileName / MinimumFileVersion / FriendlyName emission | DONE |
| P2 | 4-digit uppercase hex ID counter | DONE |
| P2 | Case preservation verbatim from binary | DONE (verified) |
| P3 | V3 AppIDs emission (XSD attribute, per cipolicy.xsd line 617) | DONE — implemented as attribute per XSD; handover misframe corrected (was suggested as `<AppIDTags>` child) |
| P3 | FileAttribRef-on-FileRules | DISMISSED — XSD misframe; construct doesn't exist on FileRules per cipolicy.xsd, only on Signers (already emitted) |
| P3 | EKU-FileRule cross-refs | DISMISSED — XSD misframe; construct doesn't exist on FileRules per cipolicy.xsd, only on Signers (already emitted) |
| P3 | `<SupplementalPolicySigners>` section emission (V6 trailing indices) | DONE — net-new finding from V6 probe; emitted for base policies with `SupplementalSignerCount > 0` |
| P4 | KPT corpus round-trip Pester | DONE (FilePath + AppIDs + SupplementalPolicySigners Contexts added) |
| P4 | Real-world policy round-trip | DEFERRED — stretch goal |
| Doc | Format-reference V7 section rewrite | DONE |
| Doc | Fieldset coverage matrix | DONE (16 rows; includes Priority 3 XSD findings) |
| Doc | V6 property rename + base-vs-supplemental size asymmetry | DONE — `IndexCount`→`SupplementalSignerCount`, legacy alias preserved |
| R4 | Unified version-sentinel rule (MFV + MaxFV + PackageVersion) | DONE — single `$versionSentinels` set; `0.0.0.0` and `65535.65535.65535.65535` both suppressed; runtime-semantics rationale for divergence from E8MVT |
| R4 | dfsdscs E8 audit-packet regen (ISM-0843 row folder) | DONE — 10 `.cip.xml` sidecars replaced; ISM-1657/ISM-1870 sibling folders untouched per user scope direction |
| R5 | SigningScenario ID XSD validity fix | DONE — IDs now match XSD pattern `ID_SIGNINGSCENARIO_[A-Z][_A-Z0-9]*` (semantic DRIVERS/USERMODE/V<value> with collision-safe suffixes) |
| R5 | Round-trip empirical proof (FileAttrib + Signer→FileAttrib edges) | DONE — `scripts/Test-RoundTripFileAttrib.ps1` exercises the full compile→decode cycle on `{4FD367C7}` (22,279 rules + 97 cross-references); set + multiset equivalence proven |
| R6 | Schema validation against E8MVT typed model | DONE — `scripts/Test-SchemaAgainstE8MVT.ps1` deserialises workspace XML through `[CodeIntegrity.SiPolicy]`; 5/10 pass cleanly, 5/10 fail due to **E8MVT typed-model defects**, not workspace defects |
| R6 | E8MVT XML round-trip viability test | DONE — `scripts/Test-E8MvtXmlRoundTripViability.ps1` proves E8MVT's own XML output is not round-trip-viable through Microsoft `ConvertFrom-CIPolicy` for policies with `Enabled:Revoked Expired As Unsigned` option OR supplemental policy type. Workspace XML is round-trip-viable for both. |
| R7 | Add KPT variants per OptionType enum value | DONE — `AllOptions-exhaustive` variant (config 13) and `scripts/Test-AllOptionsRoundTrip.ps1` exercise all 24 XSD-canonical options in a single fixture; verifies 23/23 binary-encodable options round-trip cleanly. The 24th (Default Windows Certificate Remapping) is XSD-declared but Microsoft's compiler silently drops it (binary cannot encode); no workspace decoder action required |

### Authoritative reference

Detailed alignment context, per-field emit policy, probe evidence, and fieldset coverage
matrix live in `docs/ci-binary-format-reference.md` § "Canonical Decoder Alignment".

### Dependencies

- Phase 0 outputs (canonical XML) are the input contract for Phase 1's enrichment pipeline
  and Phase 2's policy-builder operations
- E8MVT's `CIPolicyParser.psm1` (Graeber) is the canonical reference for binary read
  semantics; the workspace decoder targets functional equivalence on real-world policies
- Microsoft SiPolicy XSD (`cipolicy.xsd`) is the canonical reference for XML emit shape
  permissibility

---

## Phase 1 — Event Log Intelligence

**Domain folder:** `src/public/EventIntelligence/`

### Intent

Transform raw Code Integrity event log data into actionable policy recommendations. The existing `Get-WDACEventLog` function returns event records — Phase 1 enriches these with file metadata, signer details, and correlation logic to produce structured rule suggestions that feed directly into Phase 2's XML generation.

### Strategy

The intelligence pipeline follows a three-stage model:

```
Collect              Enrich                  Recommend
CI Events ---------> File + Signer --------> Rule Suggestions
(3076/3077/3089)     Metadata Extraction     (Allow/Deny/Signer)
```

**Stage 1 — Collection and Correlation**

- Query CI event logs for audit blocks (3076), enforcement blocks (3077), and signing information (3089) using the existing `Get-WDACEventLog` infrastructure
- Correlate 3089 signing events with their parent 3076/3077 block events via CorrelationId
- Deduplicate repeated blocks for the same file across time windows
- Track block frequency and recency to prioritise high-impact files

**Stage 2 — Metadata Enrichment**

- For each blocked file, extract: file path, file hash (SHA256, SHA1, PE authenticode hash), file version, original filename, product name, internal name
- For signed files, extract: publisher name, issuer, certificate chain, certificate thumbprint, EKU (Enhanced Key Usage)
- Use Authenticode signature validation to distinguish signed vs unsigned, valid vs expired, Microsoft-signed vs third-party
- Enrich with catalog signature lookups where direct Authenticode signatures are absent (e.g., inbox Windows components signed via catalog)

**Stage 3 — Rule Recommendation**

- For each enriched file, recommend the most specific rule type that balishes trust:
  1. **Publisher rule** (preferred) — when a valid publisher certificate chain exists
  2. **FilePublisher rule** — publisher + minimum version constraint
  3. **Hash rule** (fallback) — for unsigned files or when signer information is unavailable
  4. **Path rule** (least preferred) — only when hash is unstable (e.g., files that change frequently)
- Flag files that are Microsoft-signed but blocked (indicates policy misconfiguration)
- Group recommendations by application/publisher for batch rule creation

### Planned Functions

| Function | Description |
|---|---|
| `Get-WDACBlockEvent` | Enriched block events with correlated signing data |
| `Get-WDACFileDetail` | File metadata extraction (hash, version, authenticode) for a given path |
| `Get-WDACSignerDetail` | Certificate chain and publisher information for a signed file |
| `Get-WDACRuleSuggestion` | Rule recommendations from block events or file paths |

### Dependencies

- Extends `Get-WDACEventLog` (v1.0.0) for raw event collection
- C# interop: `System.Security.Cryptography.X509Certificates` for certificate parsing, `System.Security.Cryptography.Pkcs` for authenticode
- File hash computation via `System.Security.Cryptography.SHA256` and PE authenticode hash extraction

---

## Phase 2 — Policy XML Generation

**Domain folder:** `src/public/PolicyBuilder/`

### Intent

Programmatically construct valid WDAC CI policy XML documents from rule definitions, templates, and Phase 1 recommendations. The output is a standards-compliant `SIPolicy` XML that can be converted to binary via `ConvertFrom-CIPolicy` or deployed directly via Phase 3.

### Strategy

Policy construction follows a builder pattern:

```
Template/Base Policy
  + Rule Definitions (allow, deny, signer, hash, path)
  + Policy Options (audit mode, enforce, UMCI, boot)
  + Merge Operations (combine with existing policy)
  = Valid SIPolicy XML
```

**Policy Structure**

CI policy XML follows the `urn:schemas-microsoft-com:sipolicy` schema. Key elements:

- `<SiPolicy>` — root element with PolicyTypeID (base vs supplemental)
- `<Rules>` — policy-level options (Enabled:Audit Mode, Enabled:UMCI, etc.)
- `<EKUs>` — Extended Key Usage OIDs for signer rules
- `<FileRules>` — individual file allow/deny rules (by hash, path, or file attributes)
- `<Signers>` — publisher-based trust rules with certificate references
- `<SigningScenarios>` — kernel-mode (131) and user-mode (12) rule assignments
- `<CiSigners>` — top-level policy signing authorities

**Builder Operations**

1. **New-WDACPolicyDocument** — Create a blank or template-based policy XML
   - Support common templates: AllowMicrosoft, DefaultWindows, AllowAll-Audit
   - Set PolicyTypeID, BasePolicyID, PolicyID (GUIDs)
   - Configure policy options (audit/enforce, UMCI, boot audit on failure)

2. **Add rules from Phase 1 suggestions** — Accept `Get-WDACRuleSuggestion` output directly
   - Convert publisher recommendations to `<Signer>` + `<AllowedSigner>` elements
   - Convert hash recommendations to `<Allow>` elements in `<FileRules>`
   - Convert path recommendations to `<FilePathRule>` elements

3. **Merge operations** — Combine multiple policies or append rules to existing
   - XML-level merge (union of rules from two policy documents)
   - Conflict detection (deny in one policy vs allow in another)
   - Supplemental policy generation (reference a base policy ID)

4. **Validation** — Ensure XML output is schema-compliant before export
   - Required element presence checks
   - GUID format validation for all policy and rule IDs
   - Signing scenario completeness (every file rule assigned to a scenario)

### Planned Functions

| Function | Description |
|---|---|
| `New-WDACPolicyXml` | Create a new CI policy XML from template or blank |
| `Add-WDACPolicyRule` | Add allow/deny/signer/hash/path rules to a policy |
| `Merge-WDACPolicyXml` | Merge two policy XML documents |
| `New-WDACSupplementalPolicy` | Create a supplemental policy referencing a base |
| `Test-WDACPolicyXml` | Validate policy XML against SIPolicy schema |
| `Export-WDACPolicyXml` | Write finalised policy XML to file |

### Dependencies

- Phase 1 output (`Get-WDACRuleSuggestion`) as optional input for rule generation
- `System.Xml` for XML document construction (available in all .NET editions)
- Schema validation against Microsoft's SIPolicy XSD

---

## Phase 3 — Graph API Integration for Intune Deployment

**Domain folder:** `src/public/GraphApi/`

### Intent

Deploy WDAC policies to managed devices at scale via Microsoft Intune using the Microsoft Graph API. Provides full CRUD lifecycle: create configuration policies, assign to device groups, monitor deployment status, and retrieve compliance reporting.

### Strategy

The integration model:

```
Policy XML (Phase 2)
  --> Convert to OMA-URI payload
  --> Create Intune Configuration Policy via Graph
  --> Assign to Device Groups
  --> Monitor Deployment Status
```

**Authentication**

- MSAL-based OAuth2 authentication to Microsoft Graph
- Support for interactive (delegated) and non-interactive (application) auth flows
- Delegated: `DeviceManagementConfiguration.ReadWrite.All` scope
- Application: same permission as app role in Azure AD app registration
- Token caching for session persistence (avoid re-auth per call)
- Shared auth helper in `src/private/` (used by all Graph functions)

**Graph API Endpoints**

WDAC policies in Intune are deployed as custom OMA-URI configuration profiles:

| Operation | Method | Endpoint |
|---|---|---|
| List policies | GET | `/deviceManagement/deviceConfigurations` |
| Create policy | POST | `/deviceManagement/deviceConfigurations` |
| Get policy | GET | `/deviceManagement/deviceConfigurations/{id}` |
| Update policy | PATCH | `/deviceManagement/deviceConfigurations/{id}` |
| Delete policy | DELETE | `/deviceManagement/deviceConfigurations/{id}` |
| Assign to groups | POST | `/deviceManagement/deviceConfigurations/{id}/assign` |
| Get assignments | GET | `/deviceManagement/deviceConfigurations/{id}/assignments` |
| Device status | GET | `/deviceManagement/deviceConfigurations/{id}/deviceStatuses` |

**OMA-URI Payload Structure**

WDAC policies are delivered via the `./Vendor/MSFT/ApplicationControl/Policies/{PolicyGUID}/Policy` OMA-URI. The payload is the Base64-encoded binary CI policy (converted from XML via `ConvertFrom-CIPolicy`).

The configuration profile wraps this as:

```json
{
  "@odata.type": "#microsoft.graph.windows10CustomConfiguration",
  "displayName": "WDAC - <PolicyName>",
  "omaSettings": [{
    "@odata.type": "#microsoft.graph.omaSettingBase64",
    "omaUri": "./Vendor/MSFT/ApplicationControl/Policies/{GUID}/Policy",
    "value": "<base64-encoded-binary-policy>"
  }]
}
```

**Deployment Workflow**

1. Take policy XML (from Phase 2 or manual)
2. Convert to binary via `ConvertFrom-CIPolicy`
3. Base64-encode the binary
4. Create or update Intune configuration profile via Graph
5. Assign to target groups (device groups, not user groups for WDAC)
6. Poll deployment status until target devices report compliance

### Planned Functions

| Function | Description |
|---|---|
| `Connect-WDACGraph` | Authenticate to Microsoft Graph (interactive or app-only) |
| `Disconnect-WDACGraph` | Clear cached token and session |
| `Get-WDACIntunePolicy` | List or retrieve WDAC policies from Intune |
| `New-WDACIntunePolicy` | Create a new WDAC configuration profile from policy XML |
| `Set-WDACIntunePolicy` | Update an existing Intune WDAC policy |
| `Remove-WDACIntunePolicy` | Delete an Intune WDAC policy |
| `Set-WDACIntunePolicyAssignment` | Assign policy to device groups |
| `Get-WDACIntuneDeploymentStatus` | Retrieve per-device deployment and compliance status |

### Dependencies

- Phase 2 output (`Export-WDACPolicyXml`) as input
- `ConvertFrom-CIPolicy` (built-in cmdlet in ConfigCI module) for XML-to-binary conversion
- MSAL.PS or MSAL.NET for OAuth2 token acquisition — shared auth helper in `src/private/`
- `System.Net.Http` for Graph API REST calls (or `Invoke-RestMethod` fallback for PS 5.1)

---

## Cross-Phase Architecture

### Shared Private Helpers (`src/private/`)

| Helper | Used By | Purpose |
|---|---|---|
| Graph authentication | Phase 3 | MSAL token acquisition and caching |
| Certificate utilities | Phase 1, Phase 2 | X.509 certificate parsing, chain building |
| XML builder utilities | Phase 2 | SIPolicy XML element construction helpers |
| Hash computation | Phase 1, Phase 2 | SHA256 + PE authenticode hash extraction |

### Data Flow

```
                    ┌──────────────────┐
                    │   CI Event Logs  │
                    │  (3076/3077/3089)│
                    └────────┬─────────┘
                             │
                    Phase 1: Extract
                             │
                    ┌────────▼─────────┐
                    │ Rule Suggestions │
                    │ (publisher/hash/ │
                    │  path + metadata)│
                    └────────┬─────────┘
                             │
                    Phase 2: Generate
                             │
                    ┌────────▼─────────┐
                    │  SIPolicy XML    │
                    │  (valid schema)  │
                    └────────┬─────────┘
                             │
                    Phase 2: Convert
                             │
                    ┌────────▼─────────┐
                    │  Binary Policy   │
                    │  (.p7b / .cip)   │
                    └────────┬─────────┘
                             │
               ┌─────────────┼─────────────┐
               │             │             │
          Local Deploy   Phase 3:      Export
          (existing)     Intune via     to file
          Deploy-WDAC    Graph API
          Policy
```

### Version Targets

| Phase | Minimum Version | Breaking Changes |
|---|---|---|
| Phase 1 | 1.1.0 | None — additive functions only |
| Phase 2 | 1.2.0 | None — additive functions only |
| Phase 3 | 1.3.0 | None — additive, but introduces MSAL dependency |
