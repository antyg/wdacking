# CI Policy Binary Format Reference

**Version**: 3.0.0 (alignment in progress)
**Date**: 2026-02-18; revised 2026-05-17
**Sources**: WDACTools CIPolicyParser.psm1 (mattifestation, MIT), HotCakeX wiki, Microsoft Learn,
Known-Plaintext Analysis (KPT — `Invoke-KnownPlaintextAnalysis.ps1`, `Invoke-KnownPlaintextVariants.ps1`),
E8MVT `CIPolicyParser.psm1` (real-world Microsoft-compiled policy decode evidence, 2026-05-17)

---

## Canonical Decoder Alignment (active 2026-05-17)

> Active design + implementation tracker for honest and canonical WDAC policy representation by
> `ConvertFrom-WDACBinary`. Round-by-round decisions and per-field fieldset coverage are inscribed
> below. This section is the coordinating artefact for the decoder alignment work; the rest of this
> document remains the binary format reference (with marked corrections pending Round 3+ evidence).

### Status

**Opened**: 2026-05-17
**Origin**: handover at `temp/handover-2026-05-17.md`. A dfsdscs E8 evidence-validation session
uncovered that the workspace decoder emits empty `FileName=""` placeholders where the binary
actually carries `FilePath` values, derives synthetic `FriendlyName` attributes not present in the
binary, and uses a decimal ID-counter format that diverges from E8MVT's 4-digit-hex idiom.

### Purpose

Establish the rule-set coverage and fieldset gap required for an honest and canonical representation
of WDAC policies as decoded by `ConvertFrom-WDACBinary`. The decoder's XML output should be
functionally equivalent to E8MVT's `CIPolicyParser` output on real-world policies for the four
FileRule discriminator classes (`FilePath`, `FileName`, `Hash`, `PackageFamilyName`) plus their
secondary attributes, while remaining XSD-valid where E8MVT's output is not.

### Canonical authority model (Round 1 decision, 2026-05-17)

| Surface | Canonical for | Rationale |
|---|---|---|
| `cipolicy.xsd` (Microsoft SiPolicy schema) | Field permissibility per rule type | Microsoft-authored contract; sole source of truth for "is this attribute/child allowed on this element?" |
| E8MVT `CIPolicyParser.psm1` (Graeber) | Binary read semantics — wire shape per V-block, byte budgets, stream alignment | 10+ years of community use against real Microsoft-compiled policies; battle-tested where the workspace KPT corpus is not |
| Workspace `ConvertFrom-WDACBinary.ps1` | XML emission style — case preservation, attribute conditionality, ID counter format, FriendlyName suppression | Workspace authored; owns the output presentation |

The fieldset coverage matrix (Round 3+) carries an explicit "Authority" column per field so future
maintainers can resolve disagreements without re-litigating the model.

### Round-by-round decisions

#### Round 1 (2026-05-17)

| Axis | Decision |
|---|---|
| Scope | Full alignment — analysis + Priority 1-3 implementation + format-ref correction + ROADMAP restructure |
| V7 wire-shape verification | Author new KPT variant via `Invoke-KnownPlaintextVariants.ps1` containing FilePath-bearing Allow rule; the existing 8-bytes-per-FR observation is likely a coincidence of empty-string encoding (4 length-zero + 0 data + 0 padding + 4 null-terminator = exactly 8 bytes, byte-identical to two zero uint32s) |
| Canonical authority | Layered: XSD permits / E8MVT reads / workspace emits (table above) |

#### Round 2 (2026-05-17)

| Axis | Decision |
|---|---|
| Output structure | Integrate this alignment work INTO this document (`ci-binary-format-reference.md`); no parallel `decoder-canonical-fieldset.md` |
| KPT fixture coverage | Multiple new configs covering FilePath variety — literal, `%OSDRIVE%` macro, wildcard multi-segment, mixed-case, FilePath+Hash mix — added to `$configs` matrix in `Invoke-KnownPlaintextVariants.ps1`; Measure-V7V6 extended to read V7 dual-shape (2×uint32-per-FR vs `Get-BinaryString` per FR) |
| E8 audit-packet co-existence | Defer entirely — this session is module-internal; complete decoder + analysis + format-ref + ROADMAP, then evidence-packet regeneration and `file:line` citation refresh are owned by a follow-on session under the parent E8 workstream |

#### Round 3 (2026-05-17)

| Axis | Decision |
|---|---|
| Implementation sequencing | Probe → fieldset matrix inscription → P1 code → P2 code → P3 code → P4 round-trip Pester → ROADMAP restructure → format-ref V7 section final rewrite (after probe evidence lands). Critical path is the Probe-and-Verify gate; nothing downstream commits until probe evidence is captured. |
| Variants harness update strategy | Additive — preserve existing configs 1-6 (FileName-branch regression); add configs 7-11 (FilePath-literal, `%OSDRIVE%` macro, wildcard multi-segment, mixed-case, FilePath+Hash mix). Extend `New-VariantPolicyXml` with FileRule template selector; extend `Measure-V7V6` with dual-shape V7 parsing; update "V7 Analysis" conclusion logic at lines 396-422 to disambiguate based on byte-budget asymmetry between non-empty-FilePath fixtures and the existing FileName-only corpus. |
| Per-field emit policy | Ratify handover idioms as derived decisions, inscribe in the per-field emit policy summary table below for user review before implementation. Idioms: (a) suppress synthetic FriendlyName entirely, (b) 4-digit uppercase hex ID counter (`'X4'`), (c) suppress FileName when binary value empty, (d) suppress MinimumFileVersion when sentinel `65535.65535.65535.65535`, (e) preserve case verbatim, (f) one-discriminator-per-rule (suppress non-keyed discriminators). Each idiom cited to handover line and authority. |

#### OptionFlags transparency-comment mechanism (2026-05-18) — XSD enforcement, binary-only bits, PKCS#7 envelope discovery

| Axis | Decision / Finding |
|---|---|
| Triggering question | User asked whether XML can compile if it's not XSD-compliant, and how Microsoft's compiler (XSD-locked) and E8MVT (handles binaries carrying bits not in the public XSD) can both be correct. The session resolved both questions empirically. |
| XSD-enforcement empirical evidence (`scripts/Test-XsdValidationBoundaries.ps1`) | Four-variant test compiled by Microsoft's `ConvertFrom-CIPolicy`: (A) baseline — COMPILE OK 404 bytes; (B) XML comment inside `<Rules>` — COMPILE OK 416 bytes (delta fully explained by FileName length difference; comment leaves no trace in the output binary); (C) `OptionType` enum violation — COMPILE FAILED at XML-deserialiser line:col error; (D) unknown attribute on `<Allow>` — COMPILE FAILED at XSD content-model error. **Strict XSD enforcement on writes, complete comment transparency**: XML comments are XML-lexical syntax, not part of the post-schema-validation infoset, so they survive compile without effect. |
| Read/write asymmetry resolution | Public `cipolicy.xsd` is a write-side gate, not a read-side gate. Three distinct surfaces exist in the WDAC ecosystem: (1) public `ConvertFrom-CIPolicy` XML→binary, XSD-bound; (2) Microsoft internal toolchain, richer-schema → binary, ships system policies with bits the public XSD doesn't list; (3) decoders (workspace, E8MVT) read binary→object via direct byte parsing, no schema validation. The internal compiler can write bits the public compiler cannot; decoders can read any bits regardless of public-XSD listing. This resolves the apparent paradox. |
| Transparency-comment mechanism — registry + emission | `ConvertFrom-WDACBinary.ps1` `$bitToOptionName` extended with `__BINARYONLY__:` sentinel prefix. XSD-canonical entries hold the OptionType enum string and emit as `<Rule><Option>$value</Option></Rule>`. Class B entries hold `__BINARYONLY__:<description>` and emit as `<!-- BinaryOnly: bit N (0xHEX) — <description> -->` transparency comments inside `<Rules>`. Rules emission loop now iterates the full 30-bit range (was: registry keys only); bits set in source binary that have no registry entry emit as positional transparency comments — forward-compatibility insurance for any future Microsoft bit addition. Current Class B registry holds a single entry: bit 6 → `Enabled:Windows Lockdown Trial Mode`, sourced from E8MVT's reverse-engineering corpus (Matt Graeber's `CIPolicyParser.psm1`), not present in `cipolicy.xsd` OptionType enumeration. |
| PKCS#7 envelope discovery and earlier-claim retraction | Microsoft-shipped `.cip` files under `C:\Windows\System32\CodeIntegrity\CIPolicies\{Active,Reserved}` are **PKCS#7 SignedData ASN.1 DER envelopes**, NOT raw policy binaries. First bytes: `30 82 ...` (ASN.1 SEQUENCE with multi-byte length) followed by PKCS#7 SignedData OID `06 09 2A 86 48 86 F7 0D 01 07 02`. The workspace decoder already calls `Unprotect-Pkcs7Policy` at `ConvertFrom-WDACBinary.ps1:123` to unwrap before parsing. An early diagnostic probe (since deleted) read byte 0x24 of raw `.cip` files without PKCS#7 unwrap, mistakenly identifying 5 "undocumented bits" (0, 1, 6, 9, 14) as artefacts of misinterpreting ASN.1 envelope bytes as OptionFlags. A corrected probe using `System.Security.Cryptography.Pkcs.SignedCms` to unwrap before reading the inner content at offset 0x24 (also deleted after the empirical question was settled) verified **zero unknown bits observed across 13 Microsoft system policies on the audit machine**; all set bits are within the workspace's 23-bit XSD-canonical map. The transparency-comment mechanism is therefore **forward-compatibility insurance**, not load-bearing for this machine's corpus; bit 6 remains documented from independent E8MVT evidence (would surface in some other system's binaries). |
| Test infrastructure — elevation-gate removal | `tests/ConvertFrom-WDACBinary.Tests.ps1` previously gated round-trip Contexts on `$isElevated` in `BeforeDiscovery` via `-ForEach @()` (the empty-array pattern emits no skipped-test marker, so previously-hidden tests were invisible in reports). Empirically proven over-conservative: four successful non-elevated `ConvertFrom-CIPolicy` invocations in this session establish the cmdlet does not require admin on this machine. Gate removed; test discovery went from 23 (parser unit tests only) to 61 (parser + four round-trip Contexts). The previously hidden round-trip Contexts exposed two real fixture-ID defects: `ID_SS_2` violating XSD `SigningScenarioIDType` pattern `ID_SIGNINGSCENARIO_[A-Z][_A-Z0-9]*`, both fixed by rename to XSD-compliant `ID_SIGNINGSCENARIO_DRIVERS` / `ID_SIGNINGSCENARIO_USERMODE`. Final state: 61 passed, 0 failed, 0 skipped. |
| Test infrastructure — Category 1 vs Category 2 taxonomy | 50-line header comment block added to `tests/ConvertFrom-WDACBinary.Tests.ps1` documenting the test-evidence-weight distinction. **Category 1 (reader-logic regression)**: tests assert on byte arrays authored in the test body; reader logic verified against author's documented format model, but format model NOT independently verified against Microsoft's actual binary output (writer-of-bytes and reader-of-bytes are co-authored against the same mental model, so they cannot disagree). **Category 2 (authoritative format correctness)**: tests author XML, compile via real `ConvertFrom-CIPolicy` (Microsoft as binary authority), decode via workspace `ConvertFrom-WDACBinary`, assert preservation. Only Category 2 has decoder format-correctness signal. All 6 reader Describe blocks renamed with `— reader-logic regression (Category 1, no Microsoft binary)` suffix; round-trip Describe renamed with `— (Category 2, authoritative format correctness via ConvertFrom-CIPolicy)` suffix. Pester output now discloses the category for every test line. |
| Cited code locations | `src/public/Policy/ConvertFrom-WDACBinary.ps1` (registry with sentinel prefix; emission-loop branch iterating 30 bits). `src/private/BinaryParsing/Unprotect-Pkcs7Policy.ps1` (PKCS#7 unwrap path, called at `ConvertFrom-WDACBinary.ps1:123`). `tests/ConvertFrom-WDACBinary.Tests.ps1` (taxonomy header comment block, gate-removed BeforeDiscovery, transparency-comments Context). Verification script (retained): `scripts/Test-XsdValidationBoundaries.ps1` (four-variant XSD-enforcement test — keeps watch on Microsoft compiler's XSD-enforcement behaviour). One-shot diagnostic probes used during this work (since deleted): a PKCS#7-unwrap-vs-raw byte-shape comparison probe, a Microsoft-system-policy OptionFlags audit probe, and a standalone Microsoft re-compile verifier for the transparency-comment mechanism — the empirical findings from each are recorded above; the assertion-shaped subset of the transparency-comment verifier was absorbed into the Pester `OptionFlags transparency comments` Context. |

#### Round 7 (2026-05-17) — Exhaustive OptionType round-trip; Microsoft compiler limitation surfaced

| Axis | Decision / Finding |
|---|---|
| KPT variant per OptionType enum value | **Implemented as single AllOptions-exhaustive variant** (config 13 of `Invoke-KnownPlaintextVariants.ps1`) that emits every XSD-canonical OptionType value in a single source XML. ConvertFrom-CIPolicy compiles the policy successfully without error. Cheaper than 24 separate fixtures; same coverage. |
| OptionType round-trip result | **23 of 24 preserved**, 1 dropped: `Disabled:Default Windows Certificate Remapping`. Workspace decoder emits 0 unexpected options. |
| Empirical bit-position analysis | The compiled binary's OptionFlags value is `0xBFFF2DBC`. After masking off bits 30-31 (compile-time flags), the rule bits are `0x3FFF2DBC` = bits 2, 3, 4, 5, 7, 8, 10, 11, 13, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29 — **exactly the 23 bits the workspace decoder's `bitToOptionName` table knows**. **NO additional bits are set.** |
| Reclassification of Outstanding Research item #4 | The format-ref doc's "bitmask bit unknown — needs research" entry for `Disabled:Default Windows Certificate Remapping` is **RESOLVED**, but not as a workspace decoder gap. Microsoft's ConvertFrom-CIPolicy silently accepts the option in input XML and drops it during compilation. The binary format does not carry the option. The workspace decoder's emit table is complete per the binary's actual contents; the 24th XSD-permitted option is a Microsoft-tooling limitation outside the decoder's scope. |
| Documentation update | Workspace decoder coverage statement: **emits every option the binary actually encodes, plus the 1 binary-only option (Windows Lockdown Trial Mode bit 6) is intentionally excluded from emit per XSD non-presence**. The decoder is XSD-conformant, round-trip-viable, and complete relative to binary encoding capability. |

#### Round 6 (2026-05-17) — Schema validation against E8MVT typed model surfaces two E8MVT defects

| Axis | Decision / Finding |
|---|---|
| Schema validation harness | New `scripts/Test-SchemaAgainstE8MVT.ps1` deserialises workspace XML through E8MVT's `[CodeIntegrity.SiPolicy]` typed model and hooks Unknown* events to surface schema mismatches. Requires PS 5.1 and priming `ConvertTo-CIPolicy` once to trigger E8MVT's lazy Add-Type registration (the typedef block lives inside the function body, not at module scope). |
| E8MVT defect #1 — OptionType enum typo | `CIPolicyParser.psm1` line 214 declares `[XmlEnumAttribute("Enabled: Revoked Expired As Unsigned")]` (with a space after the colon). The XSD canonical form (`cipolicy.xsd` line 128) has no space. **E8MVT's typed deserialiser rejects XSD-canonical XML containing this Option**; conversely, **E8MVT's own XML emit carries the typo'd form**, which **Microsoft's `ConvertFrom-CIPolicy` rejects** via XSD validation. Empirically verified on dfsdscs `{1283AC0F}` and `{4FD367C7}` policies (`Test-E8MvtXmlRoundTripViability.ps1` reports COMPILE FAILED at line/col matching the typo'd option). Workspace decoder emits the XSD-canonical form and round-trips cleanly. |
| E8MVT defect #2 — Missing `PolicyType` attribute | E8MVT's XML output omits the `PolicyType="Base Policy"` / `"Supplemental Policy"` attribute on `<SiPolicy>` root. Microsoft's `ConvertFrom-CIPolicy` defaults to `Base Policy` when absent, then validates `PolicyID == BasePolicyID` for base policies, rejecting supplemental policies that omit the attribute. Empirically verified on dfsdscs `{1939ED82}` (supplemental with `PolicyID ≠ BasePolicyID`): Microsoft errors with "Mismatched policy type BasePolicy". Workspace decoder explicitly emits `PolicyType` derived from V6 `PolicyID == BasePolicyID` comparison; round-trips cleanly. |
| Workspace XML schema-conformance status | The workspace decoder's XML output is **simultaneously** (a) XSD-conformant per `cipolicy.xsd`, (b) round-trip-viable through Microsoft's `ConvertFrom-CIPolicy`, and (c) semantically faithful to the binary input. **E8MVT's XML output satisfies none of these for the affected policy classes.** This reframes the layered canon model: while E8MVT remains canonical for binary READ semantics (10+ years of real-world wire-shape correctness), its XML EMIT surface diverges from the XSD in at least two documented ways. The workspace's direct-XML-construction approach (no typed-model intermediate) avoids the drift class. |
| Implication for future emit-policy drift detection | Add KPT variants that exercise every `OptionType` enum value (currently only `Enabled:Unsigned System Integrity Policy` appears in our regression corpus). A new variant per enum value would catch any future workspace emit-policy regression against the XSD. Filed as Round 7+ backlog. |

#### Round 5 (2026-05-17) — SigningScenario ID XSD validity + round-trip empirical proof

| Axis | Decision |
|---|---|
| SigningScenario ID format | Replace positional `ID_SIGNINGSCENARIO_$($si + 1)` (emits `_1`, `_2`, ... which fail XSD pattern `ID_SIGNINGSCENARIO_[A-Z][_A-Z0-9]*`) with semantic suffixes: 131 → `DRIVERS`, 12 → `USERMODE`, default → `V<value>` (letter-prefix V to satisfy the capital-letter-start constraint). Collision-safe via per-base-id seen-counter (rare case of two scenarios sharing the same value gets `_2`, `_3`, ... suffixes). Defect surfaced empirically when ConvertFrom-CIPolicy rejected the previous IDs during round-trip compilation. |
| Round-trip soundness | Empirically verified via `scripts/Test-RoundTripFileAttrib.ps1` against the dfsdscs `{4FD367C7}` policy: 22,279 rules + 766 Signers + 97 FileAttribRef edges all round-trip successfully through `ConvertFrom-CIPolicy` → `ConvertFrom-WDACBinary`. FileAttrib set-equivalence holds (37 ≡ 37 distinct attribute-tuples preserved). Signer→FileAttrib edge multiset equivalence holds (97 of 97 edges match by resolved-attribute content). Graph-isomorphic equivalence proven — the workspace decoder produces a viable import. Side observation: ConvertFrom-CIPolicy reorders FileAttribs in the binary during recompile (specifically the first two referenced from Signers swap positions); references are correctly rewired by ConvertFrom-CIPolicy so the workspace decoder's positional labels still resolve correctly. |
| FileAttrib fieldset documented | Confirmed FileAttrib uses the same 13-attribute set as Allow/Deny (cipolicy.xsd lines 646-667). The composition loop handles all three rule types uniformly via `$fr.RuleTypeName`. No special-casing needed. |

#### Round 4 (2026-05-17) — Unified version-sentinel rule + dfsdscs regen

| Axis | Decision |
|---|---|
| Version-sentinel unification | Extend dual-sentinel suppression (currently MFV-only) to `MaximumFileVersion` and `PackageVersion`. Single `$versionSentinels = @('0.0.0.0', '65535.65535.65535.65535')` set applied uniformly across all three version attributes in `ConvertFrom-WDACBinary.ps1`. Runtime-semantics rationale: WDAC enforcement must treat `MaxFV=0.0.0.0` as "no upper bound" (otherwise omitted-MaxFV rules would silently match nothing), and `MaxFV=65535...` evaluates as "version ≤ uint16_max" = always true = identical effective semantic. Both reduce to "no constraint"; suppressing both preserves functional-import equivalence while dropping bytes that carry no semantic content. Same argument for `PackageVersion`. Triggered by user observation that 65535 is the type's representational max, and the question of whether binary-writer-generated sentinels are redundant in the source. See § "Unified version-sentinel rule" below. |
| E8 audit-packet regen | Reverse Round 2 deferral — user-authorised regeneration of `.cip.xml` sidecars in the dfsdscs `ISM-0843_workstations` row folder. New `scripts/Convert-WdacEvidenceCip.ps1` decodes the 10 `.cip` binaries and replaces the sidecars in place. Sibling row folders (`ISM-1657`, `ISM-1870`) intentionally NOT touched. Regen completed 2026-05-17; size deltas: rule-heavy policies shrank 11-26% (noise removal), empty-rule policies grew 10-23% (new emissions like SupplementalPolicySigners on `{60FD87F8}`). All 10 decode runs error-free. |
| Divergence from E8MVT on `MaxFV`/`PackageVersion` `65535...` | Workspace deliberately diverges. Layered canon model assigns emit-style authority to the workspace; the "honest representation = drop functionally-redundant bytes" framing aligns with the alignment work's stated purpose more closely than byte-fidelity-to-E8MVT. Auditors performing cross-tool comparison will see workspace omitting `65535...` where E8MVT keeps it; functional equivalence at WDAC runtime enforcement is preserved in both shapes. |

### Hypothesis under empirical test (Round 3 gate)

The existing format-reference assertion at lines 378-400 below ("V7 = 8 bytes per FileRule,
KPT-confirmed") is suspected wrong. Hypothesis: the original KPT analysis used Hash/FileName-only
fixtures, so V7 contained empty FilePath strings indistinguishable from fixed 8-byte metadata.
Probe via new FilePath-bearing fixture is the gate before any V7 parser rewrite.

### Implementation Plan (Round 3, 2026-05-17)

| Step | Activity | Targets | Gate |
|---|---|---|---|
| 1 | Variants harness extension | `scripts/Invoke-KnownPlaintextVariants.ps1` — additive configs 7-11; `New-VariantPolicyXml` template selector; `Measure-V7V6` dual-shape V7 parsing; conclusion logic update at lines 396-422 | Harness runs cleanly on PS 5.1; transcript captures evidence under `temp/kpt-variant-transcript.txt` |
| 2 | Probe run + evidence inscription | Invoke extended harness; capture V7 byte-budget evidence into this document § "V7 Wire-Shape Disambiguation Evidence" (new subsection); resolve hypothesis under test | Evidence shows non-empty FilePath fixtures produce V7 byte budget that matches per-FR `Get-BinaryString` shape exactly, not 8/FR |
| 3 | Fieldset matrix inscription | This document § "Fieldset Coverage Matrix" (new subsection) — per-rule-type, per-field authority-cited matrix | Matrix lands; per-field emit policy summary table populated; user notified at close-out |
| 4 | Priority 1 code | `Read-BinaryVBlocks.ps1:188-209` V7 reader rewrite (per-FR Get-BinaryString + V8 marker); `ConvertFrom-WDACBinary.ps1:254-299` FilePath emission + conditional FileName/MFV/Hash + FriendlyName suppression | KPT corpus (configs 1-11) decodes without exceptions; new fixtures' XML matches the `.xml` sibling for FilePath rules |
| 5 | Priority 2 code | `ConvertFrom-WDACBinary.ps1:163-171` ID format to 4-digit uppercase hex (`'X4'`); case preservation verified via Read-BinaryString output spot-check |  Spot-check fixtures show ID counters as `0340` not `832`; mixed-case FilePath fixture preserves `c:\Windows\*` lowercase drive + `%OSDRIVE%` uppercase macro |
| 6 | Priority 3 code | V3 AppIDs emission (XSD `<AppIDTags>` shape research); FileAttribRef binary source investigation (V6 indices vs scenario-level binding); EKU-FileRule cross-refs | AppIDs surface in decoded XML where binary carries them; FileAttribRef research yields concrete answer (this may surface a Round 4+ single-detail question if the binary source remains ambiguous) |
| 7 | Priority 4 round-trip Pester | `tests/ConvertFrom-WDACBinary.Tests.ps1` — add round-trip test: decoded XML → `ConvertFrom-CIPolicy` (XML→binary) → byte-compare against source `.cip` | Round-trip succeeds for at least the KPT corpus (real-world dfsdscs policies are stretch goal) |
| 8 | ROADMAP restructure | `docs/ROADMAP.md` — add "Phase 0 — Decoder canonical alignment" as upstream of Phase 1 (Event Intelligence) | ROADMAP reflects this work as a baseline-correctness prerequisite, not a Phase 1+ feature |
| 9 | Format-ref V7 section final rewrite | This document § "V7 Block" — rewrite to canonical wire shape; remove the "REVISION PENDING" callout; preserve audit trail by retaining the old shape in a collapsible "Historical (pre-2026-05-17) misreading" note | V7 section reflects probe-verified canonical shape; all Outstanding Research items resolved or moved to a new placeholder |

### Per-Field Emit Policy Summary (Round 3, 2026-05-17)

Ratified handover idioms as derived decisions under the layered canon model. Each row cites the
handover (`temp/handover-2026-05-17.md`) line range and the authority surface that owns the
decision. Workspace emit-style decisions follow E8MVT ecosystem convention where the handover
endorses it; deviation requires explicit override.

| # | Field / Behaviour | Current Workspace | Handover Idiom | E8MVT Behaviour | Decision | Authority |
|---|---|---|---|---|---|---|
| 1 | `FriendlyName` on FileRules (Allow/Deny/FileAttrib) | Synthetic (`"Deny 832"` derived from ID counter) | Suppress entirely — "No FriendlyName when the binary doesn't carry one" | Suppressed | Suppress entirely; binary never carries one (§ Lossy Compilation) | Workspace emit (ecosystem convention) |
| 2 | ID counter format | Decimal (`832`) | 4-digit uppercase hex (`0340`, `036E`, `5673`) | 4-digit uppercase hex | 4-digit uppercase hex via `'X4'` format string | Workspace emit (handover idiom) |
| 3 | `FileName` attribute | Unconditional emit (even when binary value empty → renders as `FileName=""`) | Suppress when binary value empty | Suppressed when empty | Conditional — suppress when binary value is empty string | Workspace emit (handover idiom) |
| 4 | `MinimumFileVersion` attribute | Unconditional emit (even for FilePath rules where MFV is meaningless) | Suppress when binary value is `65535.65535.65535.65535` (any-version sentinel) | Suppressed when sentinel | Conditional — suppress when value ∈ `{0.0.0.0, 65535.65535.65535.65535}` (unified version-sentinel rule, see § "Unified version-sentinel rule" below) | Workspace emit |
| 4a | `MaximumFileVersion` attribute (V3) | Suppress only `0.0.0.0` | (handover silent on `65535...`) | Preserves `65535...` (byte-fidelity) | Conditional — suppress when value ∈ `{0.0.0.0, 65535.65535.65535.65535}` (Round 4 extension, 2026-05-17 — both values reduce to "no upper bound" at WDAC runtime enforcement) | Workspace emit (diverges from E8MVT on `65535...`) |
| 4b | `PackageVersion` attribute (V5) | Suppress only `0.0.0.0` | (handover silent on `65535...`) | Preserves `65535...` (byte-fidelity) | Conditional — suppress when value ∈ `{0.0.0.0, 65535.65535.65535.65535}` (Round 4 extension, 2026-05-17 — same rationale as MaxFV) | Workspace emit (diverges from E8MVT on `65535...`) |
| 5 | `Hash` attribute | Conditional (`if ($null -ne $fr.Hash)`) — correct shape | (handover doesn't comment; current shape matches E8MVT) | Conditional | Keep current conditional shape | Workspace emit (already correct) |
| 6 | Case preservation | Verbatim per `Read-BinaryString` (UTF-16LE pass-through) | "Case is preserved verbatim from the binary" | Verbatim | Verbatim; no `.ToLower()`/`.ToUpper()`/normalisation anywhere in the FilePath/FileName emission path | Workspace emit (handover idiom) |
| 7 | One-discriminator-per-rule | Multi-discriminator (FileName + MFV + Hash + PackageFamilyName co-present even when binary keys on only one) | "Each rule has exactly ONE discriminator: FilePath, FileName, Hash, or PackageFamilyName" | One discriminator each | Suppress non-keyed discriminators (e.g. when binary carries FilePath, suppress FileName/MFV/Hash on that rule) | Workspace emit (handover idiom) |
| 8 | Secondary attributes (`InternalName`, `FileDescription`, `ProductName`, `MaximumFileVersion`, `PackageVersion`) | Conditional — currently emits only when non-empty | (handover doesn't comment; current shape matches E8MVT — secondary attributes only appear when binary carries non-sentinel values) | Conditional | Keep current conditional shape | Workspace emit (already correct) |
| 9 | `FilePath` attribute (new) | Not emitted (V7 data read and discarded) | "Each rule has exactly ONE discriminator: FilePath, FileName, Hash, or PackageFamilyName" — FilePath emission required when V7 carries non-empty string | Emitted from V7 string read | Emit when V7 read yields non-empty string for the FileRule index | Workspace emit (handover Priority 1) |

### V7 Wire-Shape Disambiguation Evidence (probe result, 2026-05-17)

Step 2 of the Implementation Plan complete. Probe under `scripts/Invoke-KnownPlaintextVariants.ps1`
(additive Round 3 extension) ran against 11 configurations (6 FileName-branch + 5 FilePath-branch);
transcript at `temp/kpt-variant-transcript.txt`. All four evidence checks resolved TRUE:

| Check | Result |
|---|---|
| String-shape parse VALID for all configs | TRUE |
| String-shape ENDS-AT-V8 marker for all configs | TRUE |
| FileName-branch V7/FR constant at 8 bytes | TRUE |
| FilePath-branch V7/FR exceeds 8 bytes | TRUE |

**Conclusion**: V7 wire shape is E8MVT-canonical (per-FileRule `Get-BinaryString` followed by
the V8 marker uint32). The earlier workspace KPT analysis's "V7 = 8 bytes per FileRule"
observation was a coincidence of empty-string encoding: empty FilePath strings consume
`4 (length=0) + 0 (data) + 0 (padding) + 4 (null-terminator) = 8 bytes`, byte-identical to two
zero uint32s. The original KPT corpus used FileName-only Allow rules, so V7 only ever contained
empty strings and the two shapes could not be distinguished.

#### Per-template V7 byte-budget evidence

| Template | V7 size(s) | bytes/FR | First decoded FilePath |
|---|---|---|---|
| FileName (configs 1-6) | 8 / 24 / 40 | 8 | `<empty>` |
| FilePath-literal (config 7) | 160 | 80 | `"C:\Program Files\Vendor\TestApp1.exe"` |
| FilePath-OSDRIVE-macro (config 8) | 184 | 92 | `"%OSDRIVE%\Users\*\AppData\Local\Vendor1\*"` |
| FilePath-wildcard-multi (config 9) | 176 | 88 | `"*\Program Files (x86)\Vendor\Plugins\1\*"` |
| FilePath-mixed-case (config 10) | 136 | 68 | `"c:\Windows\System32\Tool1.Exe"` |
| FilePath-Hash-mix (config 11) | 52 | 26 (avg) | FR[0]: `<empty>` (Hash rule); FR[1]: `"D:\Apps\Vendor1\*"` |

#### Direct evidence for Priority 2 (case preservation)

Config 10 input XML: `FilePath="c:\Windows\System32\Tool1.Exe"`. Config 10 V7 string decoded:
`"c:\Windows\System32\Tool1.Exe"`. Lowercase drive letter (`c:`) and mixed-case extension
(`.Exe`) preserved verbatim. The binary's UTF-16LE string encoding is case-preserving; the
workspace's `Read-BinaryString` implementation is therefore correct on case as long as no
downstream normalisation runs.

#### Direct evidence for Priority 1 (per-FR independence)

Config 11 (FilePath-Hash-mix) carries one Hash rule (FR[0]) and one FilePath rule (FR[1]).
The V7 region holds `<empty>` for the Hash rule and `"D:\Apps\Vendor1\*"` for the FilePath
rule. The per-FR `Get-BinaryString` read correctly handles the mixed case — empty strings
take their 8 bytes, non-empty strings take their actual length. The workspace's V7 reader
rewrite must follow this per-FR semantic exactly.

#### Side finding — V6 trailing uint32 is NOT always 0

The probe also exposed a documentation error in the existing § "V6 Block" section. The
trailing uint32 (currently described as "always 0 in all tested configurations") actually
encodes `SupplementalPolicySignerRuleEntryCount` per E8MVT's reading
(`CIPolicyParser.psm1` lines 3214-3227):

| Policy type | Observed trailing | Interpretation |
|---|---|---|
| Base policy (config 4) | 1 | One SupplementalPolicySigner index follows; V6 = 44 bytes |
| Supplemental (configs 1-3, 5-11) | 0 | No SupplementalPolicySigner indices; V6 = 40 bytes |

The workspace's V6 reader at `Read-BinaryVBlocks.ps1:161-186` reads this correctly as
`$indexCount` + index array, but the docstring at lines 171-173 misnames the purpose
("signer/EKU mapping indices"). The actual semantics are: count of supplemental-policy-author
signer indices on base policies. Filed as Round 4+ docstring fix.

### Fieldset Coverage Matrix — FileRule Attributes & Children

The matrix below tracks every FileRule attribute/child surfaced by the binary across V-blocks,
mapped to its read status and post-Priority-1 emit decision. The "Per-Field Emit Policy Summary"
above captures the *decisions*; this matrix captures the *coverage* — where each field comes from
in the binary and where it lands in the XML.

| # | Attribute / Child | Rule Types | Binary Source | Read Status (Workspace) | Emit Status (post-P1) | Notes |
|---|-------------------|------------|---------------|-------------------------|----------------------|-------|
| 1 | `ID` (attribute) | Allow, Deny, FileAttrib | Synthesised positionally (binary doesn't carry XML IDs — see § Lossy Compilation) | N/A | Always emitted | 4-digit uppercase hex per type-specific counter (Round 3 emit decision) |
| 2 | `FriendlyName` (attribute) | Allow, Deny, FileAttrib | NOT in binary (lossy compilation) | N/A | Never emitted | Was synthesised `"$RuleType $Index"` pre-P1; suppressed per Round 3 emit decision |
| 3 | `FileName` (attribute) | Allow, Deny, FileAttrib | File Rule Entry string slot | Read into `$fr.FileName` | Conditional — when non-empty | Pre-P1: unconditional emit (rendered as `FileName=""` for path-keyed rules) |
| 4 | `MinimumFileVersion` (attribute) | Allow, Deny, FileAttrib | File Rule Entry (8 bytes, reversed: Rev/Build/Minor/Major) | Read into `$fr.MinimumFileVersion` | Conditional — when value ∉ `{0.0.0.0, 65535.65535.65535.65535}` (unified version-sentinel rule, Round 4) | Pre-P1: unconditional emit |
| 5 | `MaximumFileVersion` (attribute) | Allow, Deny, FileAttrib | V3 block (8 bytes per FR, reversed) | Read into `$vblocks.V3.FileRuleExtensions[i].MaximumFileVersion` | Conditional — when value ∉ `{0.0.0.0, 65535.65535.65535.65535}` (unified version-sentinel rule, Round 4 — extends from 0.0.0.0-only pre-Round-4) | Pre-P1: unconditional emit |
| 6 | `Hash` (attribute) | Allow, Deny, FileAttrib | File Rule Entry (length-prefixed bytes + padding) | Read into `$fr.Hash` (hex-encoded) | Conditional — when non-null | Already conditional pre-P1 |
| 7 | `InternalName` (attribute) | Allow, Deny, FileAttrib | V4 block (string per FR) | Read into `$vblocks.V4.FileRuleExtensions[i].InternalName` | Conditional — when non-empty | Already conditional pre-P1 |
| 8 | `FileDescription` (attribute) | Allow, Deny, FileAttrib | V4 block (string per FR) | Read into `$vblocks.V4.FileRuleExtensions[i].FileDescription` | Conditional — when non-empty | Already conditional pre-P1 |
| 9 | `ProductName` (attribute) | Allow, Deny, FileAttrib | V4 block (string per FR) | Read into `$vblocks.V4.FileRuleExtensions[i].ProductName` | Conditional — when non-empty | Already conditional pre-P1 |
| 10 | `PackageFamilyName` (attribute) | Allow, Deny, FileAttrib | V5 block (string per FR) | Read into `$vblocks.V5.FileRuleExtensions[i].PackageFamilyName` | Conditional — when non-empty | Already conditional pre-P1 |
| 11 | `PackageVersion` (attribute) | Allow, Deny, FileAttrib | V5 block (8 bytes per FR, reversed) | Read into `$vblocks.V5.FileRuleExtensions[i].PackageVersion` | Conditional — when value ∉ `{0.0.0.0, 65535.65535.65535.65535}` (unified version-sentinel rule, Round 4 — extends from 0.0.0.0-only pre-Round-4) | Pre-Round-4: 0.0.0.0-only suppression |
| 12 | `FilePath` (attribute) | Allow, Deny, FileAttrib | V7 block (per-FR string — probe-verified 2026-05-17) | Read into `$vblocks.V7.FileRuleExtensions[i].FilePath` (post-P1; was misread as `Word0`+`Word1` uint32 pair pre-P1) | Conditional — when non-empty (post-P1) | **PRIORITY 1 GAP — V7 reader rewrite + composition emit are the two changes that close it** |
| 13 | `AppIDs` (**attribute**, per XSD line 617/641/664/688) | Allow, Deny, FileAttrib | V3 block (macro string array per FR) | Read into `$vblocks.V3.FileRuleExtensions[i].AppIDs` (string array) | Conditional — single macro emitted as-is; multiple macros concatenated with no separator (matches XSD `((\$\([a-zA-Z_][a-zA-Z_0-9.]*\))+)` pattern and E8MVT `CIPolicyParser.psm1:3120-3130`) | **Priority 3 #7 — implemented 2026-05-17.** Handover suggested `<AppIDTags>` child elements; XSD shows that was wrong — `AppIDs` is an attribute on FileRule; `<AppIDTags>` is a separate construct on SigningScenario |
| 14 | `<FileAttribRef>` child on FileRules | (none — XSD doesn't permit) | n/a — construct doesn't exist on FileRules | n/a | n/a | **Priority 3 #8 — DISMISSED as XSD misframe.** XSD declares `<FileAttribRef>` only as a child of `<Signer>` (line 857); existing emit at `ConvertFrom-WDACBinary.ps1:358-364` is correct |
| 15 | EKU reference on FileRule | (none — XSD doesn't permit) | n/a — construct doesn't exist on FileRules | n/a | n/a | **Priority 3 #9 — DISMISSED as XSD misframe.** XSD declares `<CertEKU>` only as a child of `<Signer>` (line 853); existing emit at `ConvertFrom-WDACBinary.ps1:315-322` is correct |
| 16 | `<SupplementalPolicySigners>` top-level section | (top-level SiPolicy element; populated for base policies authorising N>=1 supplementals) | V6 block trailing index array | Read into `$vblocks.V6.SupplementalSignerIndices` (post-2026-05-17 rename; legacy `Indices` alias preserved) | Conditional — emitted when V6 `SupplementalSignerCount > 0`, after `<CiSigners>` and before `<HvciOptions>` | **Net-new Priority 3 finding — implemented 2026-05-17.** Surfaced from V6 probe evidence (base=trailing-1, supplemental=trailing-0); the workspace previously read but discarded these indices |

#### Unified version-sentinel rule (Round 4 extension, 2026-05-17)

The three version attributes (`MinimumFileVersion`, `MaximumFileVersion`, `PackageVersion`)
share a unified suppression rule under the workspace's emit-style authority: emit only when
the binary value is **NOT** in the set `{0.0.0.0, 65535.65535.65535.65535}`.

**Runtime-semantics rationale**: WDAC enforcement must interpret `0.0.0.0` specially as
"no constraint" for upper-bound attributes (`MaximumFileVersion`, `PackageVersion`) —
otherwise a rule like `<Deny FileName="x.exe" />` (with `MaxFV` omitted, compiled by
`ConvertFrom-CIPolicy` to `MaxFV=0.0.0.0` in V3) would match only files of literal version
`0.0.0.0`, which would silently render the rule useless. Microsoft would not ship that
footgun; therefore `MaxFV=0.0.0.0` MUST mean "no upper bound" at runtime. And
`MaxFV=65535.65535.65535.65535` evaluates as "version ≤ uint16_max", which is "always
true" — same effective semantic as "no upper bound". Both values reduce to no constraint.

The lower-bound attribute (`MinimumFileVersion`) reaches the same outcome from the opposite
end: `MFV=0.0.0.0` means "version ≥ 0.0.0.0" (always true = no constraint), and
`MFV=65535...` means "version ≥ uint16_max" (almost never true — nonsensical as a real
constraint, used as a sentinel by some authoring tools). Both reduce to no constraint.

By applying one suppression rule across all three attributes, the decoder emits **only
version values that impose a meaningful constraint** (e.g., `MinimumFileVersion="5.812.10240.0"`,
`MaximumFileVersion="5.4.11.1"`). Re-importing the decoded XML produces a binary whose
runtime-enforcement behaviour is identical to the original — functional equivalence is
preserved while bytes that carry no semantic content are dropped.

**Divergence from E8MVT**: E8MVT preserves `65535...` verbatim for `MaxFV` and
`PackageVersion`. The workspace deliberately diverges on these two attributes — the layered
canon model assigns emit-style authority to the workspace, and "honest representation =
drop functionally-redundant bytes" is more aligned with the alignment work's stated
purpose than byte-fidelity-to-E8MVT. Cross-tool comparison will show the workspace omitting
`65535...` where E8MVT keeps it; functional equivalence at WDAC runtime enforcement is
preserved in both shapes.

**Round 4 decision rationale**: surfaced during real-world `{4FD367C7}` policy decode
review (2026-05-17) when the user observed that `65535.65535.65535.65535` is the uint16
max for each version component and asked whether the decoder-as-import-source contract
made the redundant emission meaningful. The runtime-semantics argument confirmed it does
not. Implementation at `ConvertFrom-WDACBinary.ps1` uses a single `$versionSentinels`
set applied uniformly to all three checks.

#### FileRule discriminator classes (Round 3 ratification)

Per the handover's "one discriminator per rule" idiom, each FileRule's binary representation
keys on exactly ONE of: `FilePath`, `FileName`, `Hash`, or `PackageFamilyName`. Secondary
attributes are permitted only in combinations consistent with the primary discriminator:

| Primary discriminator | Permitted secondary attributes | Forbidden secondary attributes (suppressed at emit) |
|---|---|---|
| `FilePath` | (none — paths are path-keyed only) | `MinimumFileVersion`, `MaximumFileVersion`, `Hash`, `InternalName`, `FileDescription`, `ProductName`, `PackageFamilyName`, `PackageVersion` |
| `FileName` | `MinimumFileVersion`, `MaximumFileVersion`, `InternalName`, `FileDescription`, `ProductName` | `Hash`, `PackageFamilyName`, `PackageVersion`, `FilePath` |
| `Hash` | (none — hash is exact) | All version, name, package, path attributes |
| `PackageFamilyName` | `PackageVersion` | All FileName/version/Internal/Description/Product/Hash/FilePath attributes |

**Honest-representation enforcement**: The decoder achieves discriminator-class consistency by
*suppressing empty values* at emit time. When the binary correctly carries exactly one
discriminator (the common case), the conditional-emit logic produces the right shape
automatically. When the binary anomalously carries multiple discriminators (malformed input),
the decoder emits all of them — honesty over fix-up. The decoder does NOT implement explicit
precedence logic to "pick" a discriminator; that would mask binary anomalies.

### Implementation status (2026-05-17)

| Step | Status | Verification |
|---|---|---|
| 1 — Variants harness extension | **DONE** | `scripts/Invoke-KnownPlaintextVariants.ps1` has 11 configs (6 FileName + 5 FilePath) + dual-shape V7 Measure |
| 2 — Probe run + evidence inscription | **DONE** | § "V7 Wire-Shape Disambiguation Evidence" above; transcript at `temp/kpt-variant-transcript.txt` |
| 3 — Fieldset matrix inscription | **DONE** | § "Fieldset Coverage Matrix" above |
| 4 — Priority 1 code | **DONE** | V7 reader rewrite (`Read-BinaryVBlocks.ps1:188-209`); FilePath emission + conditional FileName/MFV + FriendlyName suppression (`ConvertFrom-WDACBinary.ps1`); empirical verification originally via a per-variant Write-Host transcript probe (since deleted 2026-05-18), now via the Pester `FilePath rule round-trip — Priority 1 + 2 emit policy` Context (9 assertions) in `tests/ConvertFrom-WDACBinary.Tests.ps1` |
| 5 — Priority 2 code | **DONE** | 4-digit hex IDs (`ConvertFrom-WDACBinary.ps1:163-171`); case preservation verified via unit test `'reads V7 with case-preserving non-empty FilePath'` |
| 6 — Priority 3 code | **DONE for #7 + SupplementalPolicySigners**; #8 + #9 dismissed as XSD misframes | AppIDs attribute emission (V3 macros → AppIDs="..."); V6-driven SupplementalPolicySigners section emission; XSD-verified rationale for #8/#9 dismissal — see § "Priority 3 XSD findings" below |
| 7 — Priority 4 round-trip Pester | **DONE for KPT corpus**; stretch deferred | Two new round-trip Contexts: FilePath (Priority 1+2 emit) and AppIDs + SupplementalPolicySigners (Priority 3 emit); gated on `ConvertFrom-CIPolicy` + elevation per existing test infrastructure |
| 8 — ROADMAP restructure | **DONE** | `docs/ROADMAP.md` updated to position decoder alignment as Phase 0 prerequisite |
| 9 — Format-ref V7 section final rewrite | **DONE** | § "V7 Block" above rewritten to canonical wire shape; historical misreading preserved as audit trail |

### Priority 3 XSD findings (2026-05-17 — XSD verification gate)

The `cipolicy.xsd` schema at `C:\Windows\schemas\CodeIntegrity\cipolicy.xsd` was inspected
to resolve the three Priority 3 items from the handover. Two are misframes; one is
implemented, plus a net-new emission gap surfaced from the V6 probe evidence.

#### Priority 3 #7 — V3 AppIDs emission: **IMPLEMENTED as XSD attribute**

The handover suggested emitting AppIDs as `<AppIDTags>` child elements. The XSD shows this
was incorrect: AppIDs is declared as an **attribute** on `<Allow>` (line 617), `<Deny>`
(line 641), `<FileAttrib>` (line 664), and `<FileRule>` (line 688), each with
`type="AppIdType"`. `AppIdType` (lines 103-116) is a single-string type permitting either
(a) a non-`$`-starting plain string, or (b) one or more macro references concatenated
(`$(MacroId)`+).

`<AppIDTags>` is a **separate, unrelated construct** declared at line 330 — it has
`<AppIDTag Key=".." Value=".."/>` Key/Value children and is used on `<SigningScenario>`
(line 889) for AppID Tagging Policy, not on FileRule.

The decoder now emits AppIDs at `ConvertFrom-WDACBinary.ps1` per E8MVT's reading semantics
(`CIPolicyParser.psm1:3120-3130`): single macro emitted as-is; multiple macros
concatenated with no separator (matches the XSD's `((\$\([a-zA-Z_][a-zA-Z_0-9.]*\))+)`
pattern). KPT variant 12 (`KPT-Variant-3sig-2fr-supplemental--AppIDs-attribute-.cip`)
exercises this path; the decoded output emits `AppIDs="AppTag1"` etc. verbatim.

#### Priority 3 #8 — FileAttribRef on Allow/Deny FileRules: **DISMISSED — XSD does not permit**

The handover asked for `<FileAttribRef RuleID="..."/>` children on `<Allow>`/`<Deny>`
FileRules. Inspecting the XSD `<Allow>`, `<Deny>`, `<FileAttrib>`, `<FileRule>` element
definitions (lines 599-692), **none of them permit `<FileAttribRef>` children**. The
`<FileAttribRef>` element (line 514) is declared only as a child of `<Signer>` (line 857).

The existing decoder already emits `<FileAttribRef>` correctly on `<Signer>` elements
(`ConvertFrom-WDACBinary.ps1:358-364`), pointing **from Signer to FileRule-of-type-FileAttrib**.
There is no inverse construct. The handover misframed this item — the construct it
described does not exist in the SiPolicy schema.

#### Priority 3 #9 — EKU references on FileRules: **DISMISSED — XSD does not permit**

The handover asked for "FileRule-to-EKU cross-references where the binary expresses them".
Inspecting the XSD FileRule element definitions (lines 599-692), **no EKU attribute or
child element appears**. `<CertEKU>` (line 253) is declared only as a child of `<Signer>`
(line 853).

The existing decoder already emits `<CertEKU>` correctly on Signer elements
(`ConvertFrom-WDACBinary.ps1:315-322`). No FileRule-to-EKU construct exists in the schema.

#### Net-new Priority 3 finding — `<SupplementalPolicySigners>` section emission: **IMPLEMENTED**

The V6 probe evidence surfaced an emission gap: the V6 block carries
`SupplementalPolicySignerRuleEntryCount` (uint32) followed by an index array of signers
authorised to author supplemental policies. Base policies carry N >= 1 of these; supplementals
carry 0. The XSD declares `<SupplementalPolicySigners>` as a valid top-level SiPolicy
element (line 924). The workspace decoder read the indices (under the legacy name
`IndexCount`/`Indices`) but **never emitted** the `<SupplementalPolicySigners>` section —
silently discarding the relationship for any base policy.

Implemented in this session:

- `Read-BinaryVBlocks.ps1` V6 block: renamed `IndexCount`→`SupplementalSignerCount`,
  `Indices`→`SupplementalSignerIndices` with docstring clarifying semantics; legacy alias
  properties preserved for backwards compatibility.
- `ConvertFrom-WDACBinary.ps1`: new `<SupplementalPolicySigners>` emission inserted after
  `<CiSigners>` and before `<HvciOptions>`, gated on `SupplementalSignerCount > 0`.

Verified empirically: the base-policy KPT fixture
(`KPT-Variant-3sig-1fr-base--V6-trailing-test-.cip`) now decodes to include
`<SupplementalPolicySigners><SupplementalPolicySigner SignerId="ID_SIGNER_S_1"/></SupplementalPolicySigners>`,
matching the input XML.

### Open items (Round 4+ backlog)

#### Step 7 stretch deferred

- Round-trip Pester against real-world dfsdscs policies (`{1283AC0F}` 645-rule deny policy,
  `{A7E94259}` 22,279-rule allow-list) in addition to the KPT corpus. The KPT round-trip
  Context (Priority 1+2) covers the canonical emit-policy shapes; real-world policy
  round-trip would catch corpus-level surprises (unusual EKU shapes, Settings provider
  combinations, scenario inheritance) but is not blocking for Priority 1-2 correctness.

#### Round 4+ backlog

- **V6 docstring fix**: rename `$indexCount` to `$supplementalSignerCount` and rewrite the
  docstring at `Read-BinaryVBlocks.ps1:161-186` and § "V6 Block" of this document.
  Capture base-vs-supplemental V6 size asymmetry (40 vs 44 bytes) — base policies show
  V6 = 44 bytes with one trailing SupplementalPolicySigner index; supplementals show
  V6 = 40 bytes with no trailing indices. This is a docstring/naming defect; the actual
  read code is correct (per § "V7 Wire-Shape Disambiguation Evidence / Side finding").

### Cited code locations

| Reference | Path | Lines |
|---|---|---|
| Workspace V7 reader (to be rewritten) | `src/private/BinaryParsing/Read-BinaryVBlocks.ps1` | 188-209 |
| Workspace File Rule reader (4 fields) | `src/private/BinaryParsing/Read-BinaryFileRule.ps1` | 36-80 |
| Workspace V3 AppIDs read-but-discarded | `src/private/BinaryParsing/Read-BinaryVBlocks.ps1` | 61-106 |
| E8MVT V7 reader (canonical reference) | `D:\antyg\Work\dfsdscs\E8\Tools\E8 Maturity Verification Tool Oct 2025\Resources\Scripts\CIPolicyParser.psm1` | 3231-3245 |
| Composition gap (V7 data read and discarded) | `src/public/Policy/ConvertFrom-WDACBinary.ps1` | 254-299 |
| Decimal ID counter | `src/public/Policy/ConvertFrom-WDACBinary.ps1` | 163-171 |
| Unconditional FriendlyName | `src/public/Policy/ConvertFrom-WDACBinary.ps1` | 257 |
| Unconditional FileName / MinimumFileVersion | `src/public/Policy/ConvertFrom-WDACBinary.ps1` | 258-259 |
| Format-reference V7 assertion (incorrect) | `docs/ci-binary-format-reference.md` (this file) | 378-400 |
| Format-reference V7 outstanding research (now resolved) | `docs/ci-binary-format-reference.md` (this file) | 622-628 |
| Variants harness (to be extended) | `scripts/Invoke-KnownPlaintextVariants.ps1` | 68-105 (matrix); 110-193 (XML template); 198-284 (Measure); 396-422 (conclusion) |

### Comparison artefacts (dfsdscs E8 workspace)

| Artefact | Path |
|---|---|
| Workspace decoder output (10 policies × 3 row folders = 30 sidecars) | `D:\antyg\Work\dfsdscs\E8\evidence\application-control\ISM-*\evidence-01-wdac-policy-_<GUID>_-20260515094737.cip.xml` |
| E8MVT decoder output (9 of 10 policies; 60FD87F8 strict-mode crash) | `D:\antyg\Work\dfsdscs\E8\output\WdacDecodeCompare\20260517173637\evidence-01-wdac-policy-_<GUID>_-20260515094737-e8mvt.cip.xml` |
| Per-run manifest | `D:\antyg\Work\dfsdscs\E8\output\WdacDecodeCompare\20260517173637\manifest.json` |
| E8MVT harness (Windows PowerShell 5.1 auto-relaunch) | `D:\antyg\Work\dfsdscs\E8\scripts\Debug\Convert-CipWithE8mvt.ps1` |
| Prime diff candidate (645 Deny rules incl. LOLBin block list) | `{1283AC0F}` policy |
| Stress-test candidates (22,279 Allow rules each, including FilePath) | `{A7E94259}`, `{4FD367C7}` policies |

### Available regression corpus (existing)

| Fixture | Targets |
|---|---|
| `temp/KPT-Variant-1sig-1fr-supplemental--V7-minimum-.cip` + `.xml` | Minimal V7-bearing supplemental policy (1 signer + 1 FileRule); FileName-only — V7 holds empty FilePath strings |
| `temp/KPT-Variant-3sig-3fr-supplemental--V7-FR-test-.cip` + `.xml` | V7 FileRule test variant; FileName-only |
| `temp/KPT-Variant-3sig-5fr-supplemental--V7-FR-test-.cip` + `.xml` | Larger V7 FileRule test variant; FileName-only |
| `temp/KPT-Variant-5sig-1fr-supplemental--V7-signer-test-.cip` + `.xml` | V7 signer-extension variant; FileName-only |
| `temp/KPT-Variant-3sig-1fr-base--V6-trailing-test-.cip` + `.xml` | V6 boundary test; FileName-only |
| `temp/KPT-Comprehensive.cip` + `.xml` | Full-coverage variant; FileName-only |

### New regression corpus (Round 2, pending Round 3+ implementation)

| Fixture | Targets |
|---|---|
| `temp/KPT-Variant-3sig-2fr-supplemental--FilePath-literal-.cip` + `.xml` | Literal absolute FilePath rule (e.g., `C:\Program Files\App\app.exe`) |
| `temp/KPT-Variant-3sig-2fr-supplemental--FilePath-OSDRIVE-macro-.cip` + `.xml` | `%OSDRIVE%`-anchored macro FilePath rule (e.g., `%OSDRIVE%\Users\*\AppData\Local\App\*`) |
| `temp/KPT-Variant-3sig-2fr-supplemental--FilePath-wildcard-multi-.cip` + `.xml` | Multi-segment wildcard FilePath rule (e.g., `*\Program Files (x86)\Vendor\*`) |
| `temp/KPT-Variant-3sig-2fr-supplemental--FilePath-mixed-case-.cip` + `.xml` | Mixed-case FilePath (e.g., `c:\Windows\*` lowercase drive + uppercase macro) — case-preservation regression |
| `temp/KPT-Variant-3sig-2fr-supplemental--FilePath-Hash-mix-.cip` + `.xml` | FilePath + Hash rules in the same FileRules section — confirms V7 stream alignment when not every FileRule carries a FilePath |

---

## Header (0x44 bytes / 68 bytes)

| Offset | Size | Type | Field | Notes |
|--------|------|------|-------|-------|
| 0x00 | 4 | int32 | FormatVersion | Observed value: 8 (ConvertFrom-CIPolicy, Windows 11 26100+) |
| 0x04 | 16 | GUID | BasePolicyID | Legacy: PolicyTypeID (see catalogue). Multi-policy (V6+): BasePolicyID |
| 0x14 | 16 | GUID | PlatformID | Zeroed if unspecified |
| 0x24 | 4 | uint32 | OptionFlags | Bitmask — bit 31 MUST be set. See bitmask section |
| 0x28 | 4 | int32 | EKURuleCount | Number of EKU entries in body section 1 |
| 0x2C | 4 | int32 | FileRuleCount | Number of file rule entries in body section 2 |
| 0x30 | 4 | int32 | SignerRuleCount | Number of signer entries in body section 3 |
| 0x34 | 4 | int32 | SigningScenarioCount | Number of signing scenario entries in body section 6 |
| 0x38 | 2 | uint16 | VersionRevision | Policy version component (read first) |
| 0x3A | 2 | uint16 | VersionBuild | Policy version component |
| 0x3C | 2 | uint16 | VersionMinor | Policy version component |
| 0x3E | 2 | uint16 | VersionMajor | Policy version component (read last) |
| 0x40 | 4 | int32 | HeaderLength | Always 0x00000040 (64 decimal). Body starts at HeaderLength + 4 = 0x44 |

**Version is stored in REVERSE order**: Revision, Build, Minor, Major.
Reconstruct as `Major.Minor.Build.Revision`.

**Header 0x04 dual purpose (KPT-confirmed)**:
- **Legacy format** (FormatVersion < 6): Contains a well-known PolicyTypeID GUID (see catalogue below)
- **Multi-policy format** (FormatVersion ≥ 6): Contains **BasePolicyID**. For base policies, this equals PolicyID. For supplemental policies, this is the parent base policy's GUID. The actual PolicyID is stored in the V6 block.

**Body start calculation**: `bodyStart = HeaderLength + 4 = 0x44`. This is dynamic — read the uint32
at offset 0x40, add 4. This approach supports future header extensions and is more robust than
hardcoding 0x44, particularly for detection and unwrapping of signed binaries.

**Previous incorrect assumptions**: Earlier versions of this document listed 0x44 (UpdatePolicySignerCount)
and 0x48 (CISignerCount) as header fields, making the header 0x4C bytes. KPT analysis proved these
are actually body data — the EKU section begins immediately at offset 0x44. Update and CI signer
counts are stored as count-prefixed arrays within their respective body sections, not in the header.

---

## OptionFlags Bitmask (offset 0x24)

### Structure

```
Bit 31 (0x80000000) — MUST be set (validation flag)
Bit 30 (0x40000000) — Auto-set for supplemental policies by ConvertFrom-CIPolicy
Bits 29-0 (0x3FFFFFFF) — Policy rule options (sparse bitmask)
```

**Extract rule options**: `flags & 0x3FFFFFFF`
**Validate**: `(flags & 0x80000000) == 0x80000000`
**Supplemental detection**: `(flags & 0x40000000) != 0` — bit 30 is auto-injected by
`ConvertFrom-CIPolicy` for supplemental policies. It does NOT appear in the `<Rules>` XML;
it is a compilation-time flag only.

### Sparse Bitmask Mapping

The bitmask is NOT sequential. Bit positions map to specific policy options:

| Bit | Hex Value | XML Rule Option | Enum Name |
|-----|-----------|-----------------|-----------|
| 2 | 0x00000004 | Enabled:UMCI | EnabledUMCI |
| 3 | 0x00000008 | Enabled:Boot Menu Protection | EnabledBootMenuProtection |
| 4 | 0x00000010 | Enabled:Intelligent Security Graph Authorization | EnabledISGAuth |
| 5 | 0x00000020 | Enabled:Invalidate EAs on Reboot | EnabledInvalidateEAsOnReboot |
| 6 | 0x00000040 | Enabled:Windows Lockdown Trial Mode | EnabledWindowsLockdownTrialMode |
| 7 | 0x00000080 | Required:WHQL | RequiredWHQL |
| 8 | 0x00000100 | Enabled:Developer Mode Dynamic Code Trust | EnabledDevModeDynamicCodeTrust |
| 10 | 0x00000400 | Enabled:Allow Supplemental Policies | EnabledAllowSupplementalPolicies |
| 11 | 0x00000800 | Disabled:Runtime FilePath Rule Protection | DisabledRuntimeFilePathRuleProtection |
| 13 | 0x00002000 | Enabled:Revoked Expired As Unsigned | EnabledRevokedExpiredAsUnsigned |
| 16 | 0x00010000 | Enabled:Audit Mode | EnabledAuditMode |
| 17 | 0x00020000 | Disabled:Flight Signing | DisabledFlightSigning |
| 18 | 0x00040000 | Enabled:Inherit Default Policy | EnabledInheritDefaultPolicy |
| 19 | 0x00080000 | Enabled:Unsigned System Integrity Policy | EnabledUnsignedSystemIntegrityPolicy |
| 20 | 0x00100000 | Enabled:Dynamic Code Security | EnabledDynamicCodeSecurity |
| 21 | 0x00200000 | Required:EV Signers | RequiredEVSigners |
| 22 | 0x00400000 | Enabled:Boot Audit On Failure | EnabledBootAuditOnFailure |
| 23 | 0x00800000 | Enabled:Advanced Boot Options Menu | EnabledAdvancedBootOptionsMenu |
| 24 | 0x01000000 | Disabled:Script Enforcement | DisabledScriptEnforcement |
| 25 | 0x02000000 | Required:Enforce Store Applications | RequiredEnforceStoreApplications |
| 26 | 0x04000000 | Enabled:Secure Setting Policy | EnabledSecureSettingPolicy |
| 27 | 0x08000000 | Enabled:Managed Installer | EnabledManagedInstaller |
| 28 | 0x10000000 | Enabled:Update Policy No Reboot | EnabledUpdatePolicyNoReboot |
| 29 | 0x20000000 | Enabled:Conditional Windows Lockdown Policy | EnabledConditionalWindowsLockdownPolicy |

**Unused bits**: 0, 1, 9, 12, 14, 15

**Audit mode check**: `(flags & 0x00010000) != 0` (bit 16)

**XML Rule Option IDs (0-20) do NOT map directly to bit positions.**
The XML `<Option>` element uses sequential IDs 0-20, but the binary bitmask
uses the sparse bit positions above. A translation table is required.

### XML Option ID to Bitmask Bit Translation

| XML ID | XML Name | Bitmask Bit |
|--------|----------|-------------|
| 0 | Enabled:UMCI | 2 |
| 1 | Enabled:Boot Menu Protection | 3 |
| 2 | Required:WHQL | 7 |
| 3 | Enabled:Audit Mode | 16 |
| 4 | Disabled:Flight Signing | 17 |
| 5 | Enabled:Inherit Default Policy | 18 |
| 6 | Enabled:Unsigned System Integrity Policy | 19 |
| 7 | Allowed:Debug Policy Augmented | (not supported) |
| 8 | Required:EV Signers | 21 |
| 9 | Enabled:Advanced Boot Options Menu | 23 |
| 10 | Enabled:Boot Audit On Failure | 22 |
| 11 | Disabled:Script Enforcement | 24 |
| 12 | Required:Enforce Store Applications | 25 |
| 13 | Enabled:Managed Installer | 27 |
| 14 | Enabled:Intelligent Security Graph Authorization | 4 |
| 15 | Enabled:Invalidate EAs on Reboot | 5 |
| 16 | Enabled:Update Policy No Reboot | 28 |
| 17 | Enabled:Allow Supplemental Policies | 10 |
| 18 | Disabled:Runtime FilePath Rule Protection | 11 |
| 19 | Enabled:Dynamic Code Security | 20 |
| 20 | Enabled:Revoked Expired As Unsigned | 13 |

**Note**: The XSD (`cipolicy.xsd`) defines **24** option values, not 21. The 4 additional
options beyond XML IDs 0-20 are already present in the bitmask table above:

- `Enabled:Developer Mode Dynamic Code Trust` → bit 8 (0x00000100)
- `Enabled:Secure Setting Policy` → bit 26 (0x04000000)
- `Enabled:Conditional Windows Lockdown Policy` → bit 29 (0x20000000)
- `Disabled:Default Windows Certificate Remapping` → bitmask bit unknown (needs research)

Additionally, `Enabled:Windows Lockdown Trial Mode` (bit 6, 0x00000040) exists in the binary
bitmask but is **not present in the XSD** — it is a binary-only option with no XML representation.

---

## PolicyTypeID GUID Catalogue

| GUID | Name | Typical Filename |
|------|------|------------------|
| `a244370e-44c9-4c06-b551-f6016e563076` | Enterprise | SiPolicy.p7b |
| `2a5a0136-f09f-498e-99cc-51099011157c` | Windows Revoke | RvkSiPolicy.p7b |
| `976d12c8-cb9f-4730-be52-54600843238e` | SKU | SkuSiPolicy.p7b |
| `5951a96a-e0b5-4d3d-8fb8-3e5b61030784` | Windows Lockdown | WinSiPolicy.p7b |
| `4e61c68c-97f6-430b-9cd7-9b1004706770` | Advanced Threat Protection | ATPSiPolicy.p7b |
| `d2bda982-ccf6-4344-ac5b-0b44427b6816` | Driver | DriverSiPolicy.p7b |

In FormatVersion 6+, the header 0x04 field stores **BasePolicyID** instead of a well-known
PolicyTypeID. Legacy PolicyTypeIDs above are only found in older format binaries.

---

## Body Sections (sequential from offset 0x44)

All sections are variable-length. Offsets must be calculated sequentially
by reading each section in order. There are no pointers or offset tables.

### Section Order (KPT-confirmed)

```
Header:     0x0000 – 0x0044  (68 bytes, fixed)
Section 1:  EKU Rules         (count from header 0x28)
Section 2:  File Rules        (count from header 0x2C)
Section 3:  Signer Rules      (count from header 0x30)
Section 4:  Update Policy Signers  (count-prefixed in body — uint32 count + index array)
Section 5:  CI Signers             (count-prefixed in body — uint32 count + index array)
Section 6:  Signing Scenarios      (count from header 0x34)
Section 7:  HVCI Options      (4 bytes, single uint32)
Section 8:  Secure Settings   (count-prefixed in body + typed entries)
V3 block:   (if FormatVersion >= 3)
V4 block:   (if FormatVersion >= 4)
V5 block:   (if FormatVersion >= 5)
V6 block:   (if FormatVersion >= 6) — PolicyID, BasePolicyID
V7 block:   (if FormatVersion >= 7) — per-FileRule metadata
V8 block:   (if FormatVersion >= 8) — single uint32
V9 sentinel: (if FormatVersion >= 8) — end marker
```

**Critical section order correction**: Previous documentation listed Signing Scenarios
before Update/CI Signers. KPT analysis confirmed the actual order is:
EKU → FileRules → Signers → UpdateSigners → CISigners → Scenarios → HVCI → Settings.

**Count-prefixed sections**: Sections 4 (UpdatePolicySigners) and 5 (CISigners) store their
counts as the first uint32 in the body section itself, followed by an array of signer indices.
Their counts are NOT in the header.

### String Encoding (Binary String Pattern)

```
[4 bytes: UTF-16 byte count (uint32)]
[N bytes: UTF-16LE string data]
[0-3 bytes: zero padding to 4-byte boundary]
[4 bytes: null terminator (0x00000000 — always present)]
```

Padding formula: `paddingBytes = (4 - (length % 4)) & 3`

Total consumed bytes: `4 + length + paddingBytes + 4`

Empty strings: length=0, no data bytes, no padding, null terminator only → 8 bytes total.

### EKU Rule Entry

```
[4 bytes: OID byte length (uint32)]
[N bytes: DER-encoded ASN.1 OID]
[0-3 bytes: padding to 4-byte boundary]
```

### File Rule Entry

```
[4 bytes: RuleType (uint32) — 0=Deny, 1=Allow, 2=FileAttrib]
[String: FileName]
[8 bytes: MinimumFileVersion — Revision(u16), Build(u16), Minor(u16), Major(u16)]
[4 bytes: HashLength (uint32)]
[N bytes: Hash data + padding (if HashLength > 0)]
```

### Signer Rule Entry

```
[4 bytes: CertRootType (uint32) — 0=TBS, 1=Wellknown]
[Variable: CertRoot data (TBS: length-prefixed + padding; Wellknown: 4 bytes)]
[4 bytes: EKU reference count]
[N×4 bytes: EKU index references]
[String: CertIssuer]       (String field 0)
[String: CertPublisher]    (String field 1)
[String: CertOemID]        (String field 2)
[4 bytes: FileAttrib reference count]
[N×4 bytes: FileAttrib index references]
```

**Signer string field order (KPT-confirmed)**: String0=CertIssuer, String1=CertPublisher,
String2=CertOemID. All three are always present (empty strings encoded as 8 bytes each).

### Update Policy Signers (Section 4)

```
[4 bytes: count (uint32)]
[count × 4 bytes: signer index array]
```

Count is stored in the body, not the header.

### CI Signers (Section 5)

```
[4 bytes: count (uint32)]
[count × 4 bytes: signer index array]
```

Count is stored in the body, not the header.

### Signing Scenario Entry

```
[4 bytes: ScenarioValue (uint32 & 0xFF) — 131=Drivers, 12=UserMode]
[4 bytes: InheritedScenario count]
[N×4 bytes: InheritedScenario indices]
[4 bytes: MinimumHashAlgorithm (uint16 from uint32)]
[3 × Signer category (Product, Test, TestSigning), each:]
  [4 bytes: AllowedSigner count]
  [Per signer: index(4) + ExceptDenyRule count(4) + indices(N×4)]
  [4 bytes: DeniedSigner count]
  [Per signer: index(4) + ExceptAllowRule count(4) + indices(N×4)]
  [4 bytes: FileRulesRef count]
  [N×4 bytes: FileRulesRef indices]
```

**FriendlyName is NOT stored**: Scenario FriendlyName is discarded during XML→binary compilation.

### Secure Settings Entry (Section 8)

```
[4 bytes: entry count (uint32)]
Per entry:
  [String: Provider]
  [String: Key]
  [String: ValueName]
  [4 bytes: ValueType (uint32) — 0=Boolean, 1=UInt32, 2=Binary, 3=String]
  [Value data based on type:]
    Boolean: [4 bytes: uint32, 0 or 1]
    UInt32:  [4 bytes: uint32]
    Binary:  [4 bytes: length] [N bytes: data + padding]
    String:  [String: value]
```

---

## Binary Ordering Rules (KPT-confirmed)

The binary compiler does NOT preserve XML element order. The following sorting rules
were confirmed by KPT analysis:

### File Rules — Sorted by RuleType

Binary file rules are grouped by type, not by XML document order:

| Order | RuleType | XML Element |
|-------|----------|-------------|
| 0 | Deny | `<Deny>` |
| 1 | Allow | `<Allow>` |
| 2 | FileAttrib | `<FileAttrib>` |

Within each type group, the relative order from XML is preserved.

### Secure Settings — Sorted Alphabetically by Key

Settings entries are sorted alphabetically by the Key string value.
The Provider and ValueName within each entry are not independently sorted.

### Signers — Compiler-Determined Order

Signer order in binary may differ from XML order. The exact sorting criterion
has not been isolated (may be by CertRoot type, or by first reference order).

### All Other Sections

EKU rules, Signing Scenarios, and V-block per-item data follow the order
implied by header counts and body sequence. No reordering has been observed.

---

## Versioned Blocks (V3–V9)

Each block starts with a 4-byte marker (uint32 equal to the version number),
followed by block-specific data. V-blocks appear sequentially at the tail of
the binary, after all body sections.

### V3 Block (FormatVersion ≥ 3)

Per FileRule entry:
- MaximumFileVersion (8 bytes: Revision, Build, Minor, Major as uint16)
- MacroString count (uint32) + variable strings (AppIDs)

Per Signer entry:
- SignTimeAfter (int64 FileTime, 8 bytes)

### V4 Block (FormatVersion ≥ 4)

Per FileRule entry:
- InternalName (string)
- FileDescription (string)
- ProductName (string)

### V5 Block (FormatVersion ≥ 5)

Per FileRule entry:
- PackageFamilyName (string)
- PackageVersion (8 bytes: Revision, Build, Minor, Major as uint16)

### V6 Block (FormatVersion ≥ 6) — PolicyID and BasePolicyID

```
[4 bytes: marker = 6]
[16 bytes: PolicyID (GUID)]
[16 bytes: BasePolicyID (GUID)]
[4 bytes: trailing uint32 — always 0 in all tested configurations]
```

Total V6 size: **40 bytes** (4 marker + 36 data).

**PolicyID == BasePolicyID** → Base policy
**PolicyID != BasePolicyID** → Supplemental policy

**KPT finding**: The trailing uint32 was observed as 0 across all configurations tested:
base policies, supplemental policies, varying signer counts (1, 3, 5), and varying
FileRule counts (1, 3, 5). Its purpose is unknown — likely reserved/padding.

**Previous incorrect assumption**: Earlier documentation described V6 as containing
a "SupplementalSigner count + index array". KPT analysis proved V6 is a fixed 40-byte
structure with no variable-length components.

### V7 Block (FormatVersion ≥ 7) — Per-FileRule FilePath String

> **Probe-verified shape (2026-05-17)** — see § "Canonical Decoder Alignment / V7 Wire-Shape
> Disambiguation Evidence" for the empirical evidence resolving the prior 8-bytes-per-FR
> misreading. The historical (incorrect) assertion is preserved at the end of this subsection
> as an audit trail.

```text
[4 bytes: marker = 7]
[FileRuleCount × variable: per-FileRule FilePath string]
  Per FileRule:
    [String: FilePath]   — empty string (8 bytes) when rule doesn't key on path;
                           non-empty string (4 + len + padding + 4 bytes) when rule keys on path
```

Total V7 size: **4 + Σ(per-FR string size)**. The V8RuleSupport marker (uint32 = 8) follows
immediately after the last FileRule's FilePath string. The workspace V7 reader is responsible
for advancing the stream by exactly the cumulative per-FR string byte budget; the V8 marker
acts as a stream-alignment validator.

#### Per-FileRule string encoding

The string uses the standard binary-string pattern documented in § "String Encoding":

```text
[4 bytes: UTF-16 byte count (uint32, 0 if empty)]
[N bytes: UTF-16LE string data]
[0-3 bytes: zero padding to 4-byte boundary]
[4 bytes: null terminator (0x00000000 — always present)]
```

Empty FilePath strings (rule keys on FileName/Hash/PackageFamilyName, not on path) consume
exactly 8 bytes: `4 (length=0) + 0 (data) + 0 (padding) + 4 (null-terminator)`. This is
**byte-identical** to two zero uint32s — the source of the historical misreading.

Non-empty FilePath strings consume `4 + N + padding + 4` bytes where N is the UTF-16 byte
count of the path. Examples from probe configs (`temp/kpt-variant-transcript.txt`):

| FilePath input | UTF-16 bytes (N) | Padding | Total V7 entry |
|---|---|---|---|
| `"C:\Program Files\Vendor\TestApp1.exe"` (36 chars) | 72 | 0 | 80 bytes |
| `"%OSDRIVE%\Users\*\AppData\Local\Vendor1\*"` (41 chars) | 82 | 2 | 92 bytes |
| `"*\Program Files (x86)\Vendor\Plugins\1\*"` (40 chars) | 80 | 0 | 88 bytes |
| `"c:\Windows\System32\Tool1.Exe"` (29 chars) | 58 | 2 | 68 bytes |
| `"D:\Apps\Vendor1\*"` (17 chars) | 34 | 2 | 42 bytes |
| `<empty>` | 0 | 0 | 8 bytes (length-zero + null-terminator) |

#### Case preservation

FilePath strings are case-preserved verbatim. Probe config 10 input
`"c:\Windows\System32\Tool1.Exe"` decodes back as `"c:\Windows\System32\Tool1.Exe"` —
lowercase drive letter, mixed-case extension. The decoder must not normalise case anywhere
on the FilePath read path.

#### Workspace reader location

`Read-BinaryVBlocks.ps1:188-209` — currently misreads V7 as two uint32 words per FileRule
(the historical misreading captured below). Per Implementation Plan Step 4, this reader is
rewritten to per-FileRule `Read-BinaryString` followed by a V8 marker validation.

#### Historical misreading (preserved as audit trail)

Until 2026-05-17 this section asserted the following incorrect shape, traceable to a KPT
analysis that used only FileName-bearing Allow rules (no FilePath rules in the corpus,
therefore every V7 string was empty and looked indistinguishable from two zero uint32s):

```text
[4 bytes: marker = 7]
[FileRuleCount × 8 bytes: per-FileRule data]
  Per FileRule:
    [4 bytes: word0 (uint32)]
    [4 bytes: word1 (uint32)]
```

This was wrong. The error went undetected because the workspace's regression corpus (KPT
variants 1-6) used FileName-only Allow rules, so every V7 string in the existing fixtures
was empty. The 8-bytes-per-FR observation was a measurement of the empty-string encoding,
not the canonical wire shape. Round 3 (2026-05-17) added FilePath-bearing fixtures
(KPT variants 7-11) to break the coincidence; the probe under
`scripts/Invoke-KnownPlaintextVariants.ps1` then produced unambiguous evidence — see
§ "Canonical Decoder Alignment / V7 Wire-Shape Disambiguation Evidence" for full results.

### V8 Block (FormatVersion ≥ 8)

```
[4 bytes: marker = 8]
[4 bytes: uint32 value — always 0 in all tested configurations]
```

Total V8 size: **8 bytes**.

### V9 Sentinel (FormatVersion ≥ 8)

```
[4 bytes: marker = 9]
```

Total V9 size: **4 bytes** (marker only, no data).

V9 is the end-of-blocks sentinel. It is always the last 4 bytes of the binary.
For FormatVersion 8 policies, V9 (value 9) is the terminator.

### Backward End-Probing Strategy

For robust parsing, V-blocks can be located by probing from the **end** of the binary:

1. Check last 4 bytes: if uint32 == 9, V9 is present → cursor -= 4
2. Check 8 bytes before cursor: if uint32 == 8, V8 is present → cursor -= 8
3. Scan backward from cursor for V7 marker (uint32 == 7)
4. Scan backward from V7 for V6 marker (uint32 == 6, validate with GUID at +4)

This approach degrades gracefully for older format versions:
- FormatVersion 8+: V3–V9 all present (full set)
- FormatVersion 7: V3–V7 only (no V8/V9 — backward probe finds no V9 at end)
- FormatVersion 6: V3–V6 only (no V7/V8/V9)
- FormatVersion < 6: No V6 — PolicyID/BasePolicyID unavailable from V-blocks

---

## Lossy Compilation

The XML → binary compilation by `ConvertFrom-CIPolicy` is **lossy**. The following
XML attributes are discarded and NOT recoverable from binary:

- **FriendlyName** — on all elements (FileRules, Signers, EKUs, Scenarios)
- **ID** — XML element IDs (ID_ALLOW_A_1, ID_SIGNER_S_1, etc.) are replaced by positional indices
- **Name** — Signer Name attribute is discarded
- **Scenario FriendlyName** — Signing scenario FriendlyNames are discarded

Any FriendlyName shown in XML reconstructions (e.g., from `ConvertFrom-BinPolicy`) is
auto-generated, not recovered from the binary.

---

## PKCS#7 Detection and Stripping

### Detection

```csharp
// .NET approach
var contentType = ContentInfo.GetContentType(policyBytes);
if (contentType.Value == "1.2.840.113549.1.7.2") {
    // This is PKCS#7 SignedData
}
```

OID `1.2.840.113549.1.7.2` = szOID_RSA_signedData

### Unwrapping

```
1. Decode SignedCms from raw bytes
2. Extract ContentInfo.Content
3. If first byte == 0x04 (OCTET STRING tag):
   a. Read length byte
   b. If length < 0x80: single-byte length, data starts at byte 2
   c. If length >= 0x80: multi-byte length
      - sizeCount = length & 0x7F
      - read sizeCount bytes as big-endian length
      - data starts at byte 2 + sizeCount
4. Extract policy bytes from calculated offset
5. Parse extracted bytes as normal CI policy binary
```

### Quick Detection (without .NET crypto)

PKCS#7 files typically start with ASN.1 SEQUENCE tag `0x30` followed by
length encoding. CI policy binaries start with a small integer (1-8) at
offset 0x00. If `data[0] == 0x30`, it's likely PKCS#7.

---

## FormatVersion Values

| FormatVersion | V-Blocks Present | Features Added |
|---------------|------------------|----------------|
| 1-2 | Core only | Header + EKU/File/Signer/Scenario + HVCI + Settings |
| 3 | V3 | + MaxVersion, AppIDs, SignTimeAfter |
| 4 | V3–V4 | + InternalName, FileDescription, ProductName |
| 5 | V3–V5 | + PackageFamilyName, PackageVersion |
| 6 | V3–V6 | + PolicyID, BasePolicyID (multi-policy support) |
| 7 | V3–V7 | + Per-FileRule metadata (8 bytes/FR) |
| 8 | V3–V9 | + V8 block (uint32) + V9 sentinel |

**FormatVersion > 9**: Warn — format may have been updated by Microsoft.
**FormatVersion 420708912 (0x19160030)**: NOT a valid format version.
Likely a PKCS#7 wrapper or non-CI-policy binary.

---

## Data Alignment Rules

All variable-length data is 4-byte aligned:

```
paddingBytes = (4 - (length % 4)) & 3
```

| Length mod 4 | Padding |
|-------------|---------|
| 0 | 0 bytes |
| 1 | 3 bytes |
| 2 | 2 bytes |
| 3 | 1 byte |

---

## KPT Structure Map (reference binary — 1816 bytes)

From the main KPT analysis script (3 EKUs, 3 FileRules, 3 Signers, 2 Scenarios, 4 Settings, supplemental):

```
Section           Start      End        Size     Items
Header            0x0000     0x0044       68     (fixed)
Sec1_EKU          0x0044     0x0074       48     3
Sec2_FileRule     0x0074     0x0114      160     3
Sec3_Signer       0x0114     0x028C      376     3
Sec4_UpdSign      0x028C     0x0298       12     2
Sec5_CISign       0x0298     0x02A0        8     1
Sec6_Scenario     0x02A0     0x0320      128     2
Sec7_HVCI         0x0320     0x0324        4     -
Sec8_Settings     0x0324     0x0570      588     4
V3                0x0570     0x05B0       64     -
V4                0x05B0     0x0670      192     -
V5                0x0670     0x06C8       88     -
V6                0x06C8     0x06F0       40     -
V7                0x06F0     0x070C       28     -
V8                0x070C     0x0714        8     -
V9                0x0714     0x0718        4     -
Total:           1816/1816 bytes (100%)
```

---

## Validation Checklist

1. File size ≥ 68 bytes (0x44 header minimum)
2. FormatVersion at 0x00 is 1–8 (warn if > 8)
3. OptionFlags at 0x24 has bit 31 set (0x80000000)
4. HeaderLength at 0x40 equals 0x40 (64 decimal)
5. Body starts at 0x44 (HeaderLength + 4)
6. If PKCS#7 detected (first byte == 0x30), unwrap before parsing
7. V9 sentinel (if FormatVersion ≥ 8) at last 4 bytes must equal 9
8. V8 marker (if FormatVersion ≥ 8) at 8 bytes before V9 must equal 8

---

## Implementation Decisions (agreed 2026-02-18)

### Architecture

- **Separate public function**: `ConvertFrom-WDACBinary` — takes binary bytes, returns `[System.Xml.XmlDocument]`
- `Get-WDACPolicy` becomes a wrapper that calls `ConvertFrom-WDACBinary` internally, extracts properties
  from the XmlDocument, and enriches with NT API context (WLDP PolicyOptions, etc.)
- The converter is independently usable and testable

### Output Model

- Primary return type: `[System.Xml.XmlDocument]` — XSD-compliant `<SiPolicy>` XML
- Supports XPath queries, `.Save()` to file, and piping to ConfigCI cmdlets
- Synthetic IDs generated following XSD patterns (e.g., `ID_ALLOW_A_1`, `ID_SIGNER_S_1`)
- Synthetic FriendlyNames auto-generated (not recoverable from binary)

### PKCS#7 Unwrapping

- **Included in parser rewrite** (not deferred to Phase F)
- Detection: first byte == 0x30 (ASN.1 SEQUENCE) → PKCS#7
- Unwrapping: .NET `SignedCms` → extract `ContentInfo.Content` → parse inner binary
- Enables parser to handle all real-world system `.cip` files

### Backward Compatibility

- **Clean break** — new output schema designed for full binary structure
- All consumers updated simultaneously: `Get-WDACSecurityPosture`, `Get-EndpointSecurityReport`,
  `Test-WDACBinaryParser`
- No legacy property preservation — fresh schema matching full binary fidelity

### Implementation Phasing

- **Phase F1**: Build `ConvertFrom-WDACBinary` + PKCS#7 unwrapping + Pester unit tests
- **Phase F2**: Rewrite `Get-WDACPolicy` to use converter + update all consumers
- Phase F1 is validated before Phase F2 begins

### Code Organisation

- `ConvertFrom-WDACBinary.ps1` → `src/public/Policy/` (alongside Get-WDACPolicy.ps1)
- Private helper functions in a dedicated folder (e.g., `src/private/BinaryParsing/`):
  - `Read-BinaryHeader`, `Read-BinaryString`, `Read-BinaryEKU`, `Read-BinaryFileRule`
  - `Read-BinarySigner`, `Read-BinaryScenario`, `Read-BinarySettings`, `Read-BinaryVBlocks`
  - `Unprotect-Pkcs7Policy` (PKCS#7 detection + unwrapping)
- Helpers are independently testable and reusable across future functions

### Testing

- **Pester-based unit tests**: `ConvertFrom-WDACBinary.Tests.ps1`
- Describe/It blocks per section (Header, EKU, FileRule, Signer, Scenario, Settings, V-blocks, PKCS#7)
- XML round-trip validation: generate XML → compile → parse → compare XmlDocument against original

---

## Outstanding Research

Items identified during KPT analysis that require further investigation:

1. **V7 word values**: Always 0 in all KPT-generated policies. Real-world policies with
   non-trivial FileRule metadata may have non-zero values. Need to re-run main KPT script
   (which has Hash-based rules) to capture V7 word dump.

   > **⚠ RESOLUTION PENDING (2026-05-17) — see § "Canonical Decoder Alignment".** This research
   > item is now suspected to be a symptom of misreading V7. The "words always 0" observation
   > is consistent with the empty-FilePath-string hypothesis: every variant in the existing KPT
   > corpus carries FileName-only Allow rules, so V7 holds empty FilePath strings encoded as
   > `4 (length=0) + 0 (data) + 0 (padding) + 4 (null-terminator) = 8 bytes` — byte-identical
   > to two zero uint32s. Real-world policies with `FilePath="..."` rules produce non-empty V7
   > strings that the workspace parser cannot decode under its current uint32-pair model.
   > Verification via new FilePath-bearing KPT fixtures (Round 3 gate).

2. **V6 trailing uint32**: Always 0 across all tested configurations. Purpose unknown.

3. **FormatVersion 9**: Observed on Windows 11 26220 (`{784C4414}` Cross Certificates policy).
   Would contain V3–V9 plus potentially a V10 sentinel. Not yet tested.

4. **Disabled:Default Windows Certificate Remapping**: **RESOLVED 2026-05-17** (Round 7). Empirical test via the AllOptions-exhaustive KPT variant proves Microsoft's `ConvertFrom-CIPolicy` accepts this option in input XML but silently drops it during compilation — the resulting binary's OptionFlags has NO bit set that the workspace doesn't already know. The option is XSD-declared but binary-unencodable by current Microsoft tooling. Workspace decoder needs no further action; see § "Round 7" for full empirical evidence.
