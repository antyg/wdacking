#Requires -Modules Pester

# =============================================================================
# Test taxonomy — read this before adding new tests or interpreting results
# =============================================================================
#
# This file contains two distinct categories of tests with different evidentiary
# weight. Conflating them produces false confidence in decoder correctness.
#
# CATEGORY 1 — Reader-logic regression tests
# -------------------------------------------
# Each Describe block named '<Function> — reader-logic regression' exercises an
# individual binary reader (Read-BinaryString, Read-BinaryHeader, Read-BinaryEKU,
# Read-BinaryFileRule, Read-BinaryVBlocks, Unprotect-Pkcs7Policy) against byte
# arrays AUTHORED IN THE TEST BODY as PowerShell literals.
#
#   What these tests prove:
#     - The reader's internal logic (alignment, encoding, padding, bounds checks)
#       is consistent with the author's documented binary-format model.
#     - A refactor that breaks reader logic surfaces as a test failure.
#
#   What these tests do NOT prove:
#     - That the author's format model matches what Microsoft's ConvertFrom-CIPolicy
#       actually produces. The test bytes are co-authored with the reader against
#       the same mental model and so cannot disagree with it.
#     - That a decoded XML is an honest replica of a Microsoft-produced binary.
#
# CATEGORY 2 — Round-trip validation (authoritative format correctness)
# ---------------------------------------------------------------------
# The Describe block 'ConvertFrom-WDACBinary — Round-Trip Validation' contains
# Contexts that author XML inline, compile via Microsoft's ConvertFrom-CIPolicy
# (the binary authority), decode via the workspace's ConvertFrom-WDACBinary, and
# assert that the decoded XML preserves the source's content.
#
#   What these tests prove:
#     - The decoder produces XML that honestly replicates the content of a real
#       Microsoft-compiled binary.
#     - The workspace's binary-format model matches Microsoft's compiler output.
#
# When evaluating "tests pass" reports, the round-trip Contexts are the load-bearing
# evidence for decoder correctness. The reader-logic regression tests are
# supplementary — they catch reader bugs after the format model has been pinned
# down by round-trip evidence.
#
# Historical context (2026-05-17):
#   Before this commit, the round-trip Describe was gated on $isElevated via
#   `-ForEach @()`, which silently dropped its Contexts from non-elevated runs
#   without emitting a skipped-test marker. Reports of "23 tests pass" referred
#   to Category 1 only and did not establish format-correctness coverage. The
#   elevation gate was removed after empirically verifying ConvertFrom-CIPolicy
#   runs without admin (verified via Test-XsdValidationBoundaries.ps1 producing
#   successful COMPILE OK invocations in a non-elevated session, plus the Category 2
#   round-trip Contexts below which exercise ConvertFrom-CIPolicy in every BeforeAll).
# =============================================================================

BeforeAll {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    # Cross-edition Join-Path: PS 5.1 accepts only 2 positional args; pwsh 7+ accepts
    # variadic via -AdditionalChildPath. Nested Join-Path is the cross-edition pattern.
    Import-Module ([System.IO.Path]::GetFullPath([System.IO.Path]::Combine($moduleRoot, 'src', 'antyg-wdacking.psd1'))) -Force
}

Describe 'Read-BinaryString — reader-logic regression (Category 1, no Microsoft binary)' {
    It 'reads an empty string (8 bytes total)' {
        $bytes = [byte[]]@(
            0x00, 0x00, 0x00, 0x00,  # length = 0
            0x00, 0x00, 0x00, 0x00   # null terminator
        )
        $stream = [System.IO.MemoryStream]::new($bytes)
        $reader = [System.IO.BinaryReader]::new($stream)
        try {
            $result = Read-BinaryString -Reader $reader
            $result | Should -BeExactly ''
            $stream.Position | Should -Be 8
        }
        finally {
            $reader.Dispose(); $stream.Dispose()
        }
    }

    It 'reads a 4-byte aligned UTF-16LE string (no padding)' {
        # "AB" = 0x41 0x00 0x42 0x00 = 4 bytes, padding = 0
        $bytes = [byte[]]@(
            0x04, 0x00, 0x00, 0x00,  # length = 4
            0x41, 0x00, 0x42, 0x00,  # "AB" in UTF-16LE
            0x00, 0x00, 0x00, 0x00   # null terminator
        )
        $stream = [System.IO.MemoryStream]::new($bytes)
        $reader = [System.IO.BinaryReader]::new($stream)
        try {
            $result = Read-BinaryString -Reader $reader
            $result | Should -BeExactly 'AB'
            $stream.Position | Should -Be 12
        }
        finally {
            $reader.Dispose(); $stream.Dispose()
        }
    }

    It 'reads a string requiring 2-byte padding' {
        # "A" = 0x41 0x00 = 2 bytes, padding = 2
        $bytes = [byte[]]@(
            0x02, 0x00, 0x00, 0x00,  # length = 2
            0x41, 0x00,              # "A" in UTF-16LE
            0x00, 0x00,              # 2 bytes padding
            0x00, 0x00, 0x00, 0x00   # null terminator
        )
        $stream = [System.IO.MemoryStream]::new($bytes)
        $reader = [System.IO.BinaryReader]::new($stream)
        try {
            $result = Read-BinaryString -Reader $reader
            $result | Should -BeExactly 'A'
            $stream.Position | Should -Be 12
        }
        finally {
            $reader.Dispose(); $stream.Dispose()
        }
    }

    It 'reads consecutive strings correctly' {
        # Two strings back-to-back: "X" then empty
        $bytes = [byte[]]@(
            # String 1: "X" (2 bytes + 2 padding)
            0x02, 0x00, 0x00, 0x00,
            0x58, 0x00,
            0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            # String 2: empty
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        )
        $stream = [System.IO.MemoryStream]::new($bytes)
        $reader = [System.IO.BinaryReader]::new($stream)
        try {
            $s1 = Read-BinaryString -Reader $reader
            $s2 = Read-BinaryString -Reader $reader
            $s1 | Should -BeExactly 'X'
            $s2 | Should -BeExactly ''
            $stream.Position | Should -Be 20
        }
        finally {
            $reader.Dispose(); $stream.Dispose()
        }
    }
}

Describe 'Read-BinaryHeader — reader-logic regression (Category 1, no Microsoft binary)' {
    BeforeAll {
        # Construct a valid 68-byte FormatVersion 8 header
        $script:headerData = [byte[]]::new(68)

        # FormatVersion = 8 at offset 0x00
        [BitConverter]::GetBytes([int]8).CopyTo($script:headerData, 0x00)

        # HeaderGuid at 0x04
        $script:testGuid = [guid]::new('12345678-1234-1234-1234-123456789abc')
        $script:testGuid.ToByteArray().CopyTo($script:headerData, 0x04)

        # PlatformID at 0x14 (zeroed = default)

        # OptionFlags at 0x24: bit 31 (validation) + bit 16 (Audit Mode) + bit 19 (Unsigned)
        # 0x80090000 as decimal avoids PowerShell hex→signed int→uint32 overflow
        [BitConverter]::GetBytes([uint32]2148073472).CopyTo($script:headerData, 0x24)

        # Section counts
        [BitConverter]::GetBytes([int]2).CopyTo($script:headerData, 0x28)   # EKU = 2
        [BitConverter]::GetBytes([int]3).CopyTo($script:headerData, 0x2C)   # FileRule = 3
        [BitConverter]::GetBytes([int]1).CopyTo($script:headerData, 0x30)   # Signer = 1
        [BitConverter]::GetBytes([int]2).CopyTo($script:headerData, 0x34)   # Scenario = 2

        # Version: 10.0.2.0 → Revision=0, Build=2, Minor=0, Major=10
        [BitConverter]::GetBytes([uint16]0).CopyTo($script:headerData, 0x38)
        [BitConverter]::GetBytes([uint16]2).CopyTo($script:headerData, 0x3A)
        [BitConverter]::GetBytes([uint16]0).CopyTo($script:headerData, 0x3C)
        [BitConverter]::GetBytes([uint16]10).CopyTo($script:headerData, 0x3E)

        # HeaderLength = 0x40 at offset 0x40
        [BitConverter]::GetBytes([int]0x40).CopyTo($script:headerData, 0x40)
    }

    It 'parses FormatVersion correctly' {
        $h = Read-BinaryHeader -Data $script:headerData
        $h.FormatVersion | Should -Be 8
    }

    It 'parses HeaderGuid correctly' {
        $h = Read-BinaryHeader -Data $script:headerData
        $h.HeaderGuid | Should -Be $script:testGuid
    }

    It 'parses section counts correctly' {
        $h = Read-BinaryHeader -Data $script:headerData
        $h.EKUCount | Should -Be 2
        $h.FileRuleCount | Should -Be 3
        $h.SignerCount | Should -Be 1
        $h.ScenarioCount | Should -Be 2
    }

    It 'reconstructs version string correctly' {
        $h = Read-BinaryHeader -Data $script:headerData
        $h.Version | Should -Be '10.0.2.0'
        $h.VersionMajor | Should -Be 10
        $h.VersionMinor | Should -Be 0
        $h.VersionBuild | Should -Be 2
        $h.VersionRevision | Should -Be 0
    }

    It 'calculates BodyOffset as HeaderLength + 4 = 0x44' {
        $h = Read-BinaryHeader -Data $script:headerData
        $h.BodyOffset | Should -Be 0x44
    }

    It 'parses OptionFlags correctly' {
        $h = Read-BinaryHeader -Data $script:headerData
        # 0x80090000 = 2148073472 unsigned; use decimal to avoid PowerShell signed hex interpretation
        $h.OptionFlags | Should -Be 2148073472
    }

    It 'throws for data shorter than 68 bytes' {
        { Read-BinaryHeader -Data ([byte[]]::new(60)) } | Should -Throw '*minimum 68*'
    }

    It 'throws for invalid FormatVersion (> 100)' {
        $bad = [byte[]]::new(68)
        [BitConverter]::GetBytes([int]200).CopyTo($bad, 0x00)
        [BitConverter]::GetBytes([int]0x40).CopyTo($bad, 0x40)
        { Read-BinaryHeader -Data $bad } | Should -Throw '*Invalid FormatVersion*'
    }
}

Describe 'Unprotect-Pkcs7Policy — reader-logic regression (Category 1, no Microsoft binary)' {
    It 'passes through non-PKCS#7 data unchanged' {
        $data = [byte[]]@(0x08, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04)
        $result = Unprotect-Pkcs7Policy -Data $data
        $result.Length | Should -Be 8
        $result[0] | Should -Be 0x08
    }

    It 'passes through data with first byte < 0x30' {
        $data = [byte[]]@(0x07, 0x00, 0x00, 0x00)
        $result = Unprotect-Pkcs7Policy -Data $data
        $result[0] | Should -Be 0x07
    }

    It 'passes through very short data unchanged' {
        $data = [byte[]]@(0x01, 0x02)
        $result = Unprotect-Pkcs7Policy -Data $data
        $result.Length | Should -Be 2
        $result[0] | Should -Be 0x01
        $result[1] | Should -Be 0x02
    }
}

Describe 'Read-BinaryEKU — reader-logic regression (Category 1, no Microsoft binary)' {
    It 'reads zero EKUs without error' {
        $stream = [System.IO.MemoryStream]::new([byte[]]@(0xFF))  # dummy byte
        $reader = [System.IO.BinaryReader]::new($stream)
        try {
            $result = Read-BinaryEKU -Reader $reader -Count 0
            $result.Count | Should -Be 0
        }
        finally {
            $reader.Dispose(); $stream.Dispose()
        }
    }

    It 'reads a single EKU with 3-byte OID (1-byte padding)' {
        # OID: 0x06 0x08 0x2B = 3 bytes, padding = 1
        $bytes = [byte[]]@(
            0x03, 0x00, 0x00, 0x00,  # length = 3
            0x06, 0x08, 0x2B,        # OID bytes
            0x00                     # 1 byte padding
        )
        $stream = [System.IO.MemoryStream]::new($bytes)
        $reader = [System.IO.BinaryReader]::new($stream)
        try {
            $result = Read-BinaryEKU -Reader $reader -Count 1
            $result.Count | Should -Be 1
            $result[0].Value | Should -Be '06082B'
            $result[0].Index | Should -Be 0
        }
        finally {
            $reader.Dispose(); $stream.Dispose()
        }
    }
}

Describe 'Read-BinaryFileRule — reader-logic regression (Category 1, no Microsoft binary)' {
    It 'reads a single Allow rule with empty hash' {
        # Build: RuleType=1(Allow) + FileName="T" + MinVersion(8 bytes) + HashLength=0
        $ms = [System.IO.MemoryStream]::new()
        $w = [System.IO.BinaryWriter]::new($ms)
        try {
            $w.Write([int]1)                           # RuleType = Allow
            $w.Write([uint32]2)                        # FileName length = 2 bytes
            $w.Write([byte[]]@(0x54, 0x00))            # "T" in UTF-16LE
            $w.Write([byte[]]@(0x00, 0x00))            # 2 bytes padding
            $w.Write([int]0)                           # FileName null terminator
            $w.Write([uint16]0); $w.Write([uint16]0)   # MinVersion: Rev=0, Build=0
            $w.Write([uint16]0); $w.Write([uint16]1)   # MinVersion: Minor=0, Major=1
            $w.Write([uint32]0)                        # HashLength = 0
            $w.Flush()

            $ms.Position = 0
            $reader = [System.IO.BinaryReader]::new($ms)
            $result = Read-BinaryFileRule -Reader $reader -Count 1
            $result.Count | Should -Be 1
            $result[0].RuleTypeName | Should -Be 'Allow'
            $result[0].FileName | Should -Be 'T'
            $result[0].MinimumFileVersion | Should -Be '1.0.0.0'
            $result[0].Hash | Should -BeNullOrEmpty
        }
        finally {
            $w.Dispose(); $ms.Dispose()
        }
    }
}

Describe 'Read-BinaryVBlocks — reader-logic regression (Category 1, no Microsoft binary)' {
    BeforeAll {
        $script:testPolicyGuid = [guid]::new('60FD87F8-4593-44A0-91B0-2E0DA022F248')
    }

    It 'parses V6 block with non-zero index array and reaches V7/V8/V9' {
        # Construct a synthetic V-block stream: FormatVersion 8, 0 FileRules, 0 Signers
        # V6 has 5-entry index array — the exact scenario that caused V7 marker mismatch
        $ms = [System.IO.MemoryStream]::new()
        $w = [System.IO.BinaryWriter]::new($ms)
        try {
            # V3 marker (no per-FileRule or per-Signer data when counts = 0)
            $w.Write([uint32]3)
            # V4 marker
            $w.Write([uint32]4)
            # V5 marker
            $w.Write([uint32]5)
            # V6: marker + PolicyID + BasePolicyID + count(5) + 5 indices
            $w.Write([uint32]6)
            $w.Write($script:testPolicyGuid.ToByteArray())   # PolicyID
            $w.Write($script:testPolicyGuid.ToByteArray())   # BasePolicyID (same = base)
            $w.Write([uint32]5)                               # index count
            $w.Write([uint32]0)
            $w.Write([uint32]1)
            $w.Write([uint32]2)
            $w.Write([uint32]4)
            $w.Write([uint32]3)                               # deliberately out-of-order
            # V7 marker (no per-FileRule data)
            $w.Write([uint32]7)
            # V8: marker + value
            $w.Write([uint32]8)
            $w.Write([uint32]42)
            # V9 sentinel
            $w.Write([uint32]9)
            $w.Flush()

            $ms.Position = 0
            $reader = [System.IO.BinaryReader]::new($ms)
            $result = Read-BinaryVBlocks -Reader $reader -FormatVersion 8 -FileRuleCount 0 -SignerCount 0

            # V6 block parsed correctly
            $result.V6 | Should -Not -BeNullOrEmpty
            $result.V6.PolicyID | Should -Be $script:testPolicyGuid
            $result.V6.BasePolicyID | Should -Be $script:testPolicyGuid
            $result.V6.IndexCount | Should -Be 5
            $result.V6.Indices.Count | Should -Be 5
            $result.V6.Indices[3] | Should -Be 4
            $result.V6.Indices[4] | Should -Be 3

            # V7/V8/V9 all reached (would throw on marker mismatch if V6 didn't consume indices)
            $result.V7 | Should -Not -BeNullOrEmpty
            $result.V8 | Should -Not -BeNullOrEmpty
            $result.V8.Value | Should -Be 42
            $result.V9Present | Should -BeTrue
        }
        finally {
            $w.Dispose(); $ms.Dispose()
        }
    }

    It 'parses V6 block with zero-count index array (simple policy)' {
        $ms = [System.IO.MemoryStream]::new()
        $w = [System.IO.BinaryWriter]::new($ms)
        try {
            $w.Write([uint32]3)   # V3
            $w.Write([uint32]4)   # V4
            $w.Write([uint32]5)   # V5
            # V6: marker + PolicyID + BasePolicyID + count(0)
            $w.Write([uint32]6)
            $w.Write($script:testPolicyGuid.ToByteArray())
            $w.Write($script:testPolicyGuid.ToByteArray())
            $w.Write([uint32]0)   # zero indices
            $w.Write([uint32]7)   # V7
            $w.Write([uint32]8)   # V8
            $w.Write([uint32]0)   # V8 value
            $w.Write([uint32]9)   # V9
            $w.Flush()

            $ms.Position = 0
            $reader = [System.IO.BinaryReader]::new($ms)
            $result = Read-BinaryVBlocks -Reader $reader -FormatVersion 8 -FileRuleCount 0 -SignerCount 0

            $result.V6.IndexCount | Should -Be 0
            $result.V6.Indices.Count | Should -Be 0
            $result.V7 | Should -Not -BeNullOrEmpty
            $result.V9Present | Should -BeTrue
        }
        finally {
            $w.Dispose(); $ms.Dispose()
        }
    }

    It 'reads V7 per-FileRule FilePath strings (empty and non-empty mix)' {
        # Probe-verified wire shape (2026-05-17): V7 = per-FR Read-BinaryString.
        # Empty strings consume 8 bytes; non-empty consume 4+len+padding+4.
        # This test does not depend on ConvertFrom-CIPolicy or elevation.
        $ms = [System.IO.MemoryStream]::new()
        $w = [System.IO.BinaryWriter]::new($ms)
        try {
            # V3: marker + 2 FRs (each: 8 MaxFV + 4 MacroCount=0) + 0 signers
            $w.Write([uint32]3)
            for ($i = 0; $i -lt 2; $i++) {
                $w.Write([uint16]0); $w.Write([uint16]0); $w.Write([uint16]0); $w.Write([uint16]0)
                $w.Write([uint32]0)
            }

            # V4: marker + 2 FRs × 3 empty strings (24 bytes per FR)
            $w.Write([uint32]4)
            for ($i = 0; $i -lt 6; $i++) {
                $w.Write([uint32]0); $w.Write([uint32]0)
            }

            # V5: marker + 2 FRs (each: empty PackageFamilyName + 8 PackageVer)
            $w.Write([uint32]5)
            for ($i = 0; $i -lt 2; $i++) {
                $w.Write([uint32]0); $w.Write([uint32]0)
                $w.Write([uint16]0); $w.Write([uint16]0); $w.Write([uint16]0); $w.Write([uint16]0)
            }

            # V6: marker + PolicyID + BasePolicyID + IndexCount=0
            $w.Write([uint32]6)
            $w.Write($script:testPolicyGuid.ToByteArray())
            $w.Write($script:testPolicyGuid.ToByteArray())
            $w.Write([uint32]0)

            # V7: marker + 2 per-FR FilePath strings
            $w.Write([uint32]7)
            # FR 0: empty FilePath (length=0 + null-terminator = 8 bytes)
            $w.Write([uint32]0); $w.Write([uint32]0)
            # FR 1: FilePath = "TestPath.exe" (12 chars × 2 = 24 bytes UTF-16, padding=0)
            $expectedPath = 'TestPath.exe'
            $pathBytes = [System.Text.Encoding]::Unicode.GetBytes($expectedPath)
            $w.Write([uint32]$pathBytes.Length)
            $w.Write($pathBytes)
            $w.Write([uint32]0)

            # V8 marker + value
            $w.Write([uint32]8)
            $w.Write([uint32]42)

            # V9 sentinel
            $w.Write([uint32]9)

            $w.Flush()
            $ms.Position = 0
            $reader = [System.IO.BinaryReader]::new($ms)
            $result = Read-BinaryVBlocks -Reader $reader -FormatVersion 8 -FileRuleCount 2 -SignerCount 0

            # V7 reads the per-FR FilePath strings
            $result.V7 | Should -Not -BeNullOrEmpty
            $result.V7.FileRuleExtensions.Count | Should -Be 2
            $result.V7.FileRuleExtensions[0].FilePath | Should -BeExactly ''
            $result.V7.FileRuleExtensions[1].FilePath | Should -BeExactly $expectedPath

            # Stream alignment proof: V8 marker correctly reached after V7 strings
            $result.V8 | Should -Not -BeNullOrEmpty
            $result.V8.Value | Should -Be 42
            $result.V9Present | Should -BeTrue
        }
        finally {
            $w.Dispose(); $ms.Dispose()
        }
    }

    It 'reads V7 with case-preserving non-empty FilePath (regression for Priority 2 case preservation)' {
        # Verifies Read-BinaryString returns UTF-16LE strings verbatim without case normalisation.
        $ms = [System.IO.MemoryStream]::new()
        $w = [System.IO.BinaryWriter]::new($ms)
        try {
            $w.Write([uint32]3)
            $w.Write([uint16]0); $w.Write([uint16]0); $w.Write([uint16]0); $w.Write([uint16]0)
            $w.Write([uint32]0)
            $w.Write([uint32]4)
            for ($i = 0; $i -lt 3; $i++) { $w.Write([uint32]0); $w.Write([uint32]0) }
            $w.Write([uint32]5)
            $w.Write([uint32]0); $w.Write([uint32]0)
            $w.Write([uint16]0); $w.Write([uint16]0); $w.Write([uint16]0); $w.Write([uint16]0)
            $w.Write([uint32]6)
            $w.Write($script:testPolicyGuid.ToByteArray())
            $w.Write($script:testPolicyGuid.ToByteArray())
            $w.Write([uint32]0)
            $w.Write([uint32]7)
            $expectedMixedCase = 'c:\Windows\System32\Probe.Exe'
            $bytes = [System.Text.Encoding]::Unicode.GetBytes($expectedMixedCase)
            $padding = (4 - ($bytes.Length % 4)) -band 3
            $w.Write([uint32]$bytes.Length)
            $w.Write($bytes)
            if ($padding -gt 0) { $w.Write([byte[]]::new($padding)) }
            $w.Write([uint32]0)
            $w.Write([uint32]8); $w.Write([uint32]0)
            $w.Write([uint32]9)
            $w.Flush()
            $ms.Position = 0
            $reader = [System.IO.BinaryReader]::new($ms)
            $result = Read-BinaryVBlocks -Reader $reader -FormatVersion 8 -FileRuleCount 1 -SignerCount 0

            # Case preservation: lowercase drive 'c:' and mixed-case extension '.Exe' kept verbatim
            $result.V7.FileRuleExtensions[0].FilePath | Should -BeExactly $expectedMixedCase
        }
        finally {
            $w.Dispose(); $ms.Dispose()
        }
    }

    It 'stops at V6 for FormatVersion 6 (no V7/V8/V9)' {
        $ms = [System.IO.MemoryStream]::new()
        $w = [System.IO.BinaryWriter]::new($ms)
        try {
            $w.Write([uint32]3)   # V3
            $w.Write([uint32]4)   # V4
            $w.Write([uint32]5)   # V5
            $w.Write([uint32]6)   # V6
            $w.Write($script:testPolicyGuid.ToByteArray())
            $w.Write($script:testPolicyGuid.ToByteArray())
            $w.Write([uint32]0)   # zero indices
            $w.Flush()

            $ms.Position = 0
            $reader = [System.IO.BinaryReader]::new($ms)
            $result = Read-BinaryVBlocks -Reader $reader -FormatVersion 6 -FileRuleCount 0 -SignerCount 0

            $result.V6 | Should -Not -BeNullOrEmpty
            $result.V7 | Should -BeNullOrEmpty
            $result.V8 | Should -BeNullOrEmpty
            $result.V9Present | Should -BeFalse
        }
        finally {
            $w.Dispose(); $ms.Dispose()
        }
    }
}

Describe 'ConvertFrom-WDACBinary — Round-Trip Validation (Category 2, authoritative format correctness via ConvertFrom-CIPolicy)' {
    BeforeDiscovery {
        # ConvertFrom-CIPolicy is shipped via the ConfigCI module on Windows client/server SKUs.
        # The cmdlet does not require Administrator — proven empirically 2026-05-17 by four
        # successful non-elevated COMPILE OK invocations from Test-XsdValidationBoundaries.ps1
        # (the A and B variants compiled cleanly in this same non-elevated session, confirming
        # the cmdlet does not require admin). The previous elevation gate was over-
        # conservative and silently dropped these round-trip Contexts from non-admin runs
        # (the -ForEach @() pattern does not emit a skipped-test marker), masking the
        # absence of format-correctness signal in "tests pass" reports.
        $hasCmd = $null -ne (Get-Command -Name ConvertFrom-CIPolicy -ErrorAction SilentlyContinue)
        $script:roundTripCases = if ($hasCmd) {
            @(@{ _enabled = $true })
        } else {
            @()
        }
    }

    Context 'Pipeline produces correct XML' -ForEach $script:roundTripCases {
        BeforeAll {
            $script:roundTripXml = $null
            $script:originalPolicyId = $null

        # Setup temp directory (cross-edition Join-Path: nested form for PS 5.1 compat)
        $testDir = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'temp', 'pester-roundtrip'))
        if (-not (Test-Path $testDir)) {
            New-Item -ItemType Directory -Path $testDir -Force | Out-Null
        }

        # Generate test policy XML with known distinctive values
        $script:originalPolicyId = [guid]::NewGuid()
        $basePolicyId = $script:originalPolicyId  # same = base policy

        $testXml = @"
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Base Policy">
  <VersionEx>10.0.5.0</VersionEx>
  <PlatformID>{00000000-0000-0000-0000-000000000000}</PlatformID>
  <PolicyID>{$($script:originalPolicyId)}</PolicyID>
  <BasePolicyID>{$basePolicyId}</BasePolicyID>
  <Rules>
    <Rule><Option>Enabled:Audit Mode</Option></Rule>
    <Rule><Option>Enabled:Unsigned System Integrity Policy</Option></Rule>
    <Rule><Option>Enabled:Allow Supplemental Policies</Option></Rule>
  </Rules>
  <EKUs>
    <EKU ID="ID_EKU_E_1" Value="010A2B0601040182370A0305" FriendlyName="Code Signing" />
  </EKUs>
  <FileRules>
    <Allow ID="ID_ALLOW_A_1" FriendlyName="AllowTest" FileName="TestAllow.dll" MinimumFileVersion="0.0.0.0" />
    <Deny ID="ID_DENY_D_1" FriendlyName="DenyTest" FileName="TestDeny.exe" MinimumFileVersion="0.0.0.0" />
  </FileRules>
  <Signers>
    <Signer ID="ID_SIGNER_S_1" Name="TestSigner">
      <CertRoot Type="Wellknown" Value="03" />
      <CertPublisher Value="TestPublisher" />
    </Signer>
  </Signers>
  <SigningScenarios>
    <SigningScenario ID="ID_SIGNINGSCENARIO_DRIVERS_1" Value="131" FriendlyName="Drivers">
      <ProductSigners>
        <AllowedSigners>
          <AllowedSigner SignerId="ID_SIGNER_S_1" />
        </AllowedSigners>
      </ProductSigners>
    </SigningScenario>
    <SigningScenario ID="ID_SIGNINGSCENARIO_USERMODE_1" Value="12" FriendlyName="User Mode">
      <ProductSigners>
        <AllowedSigners>
          <AllowedSigner SignerId="ID_SIGNER_S_1" />
        </AllowedSigners>
        <FileRulesRef>
          <FileRuleRef RuleID="ID_ALLOW_A_1" />
        </FileRulesRef>
      </ProductSigners>
    </SigningScenario>
  </SigningScenarios>
  <UpdatePolicySigners>
    <UpdatePolicySigner SignerId="ID_SIGNER_S_1" />
  </UpdatePolicySigners>
  <CiSigners>
    <CiSigner SignerId="ID_SIGNER_S_1" />
  </CiSigners>
  <HvciOptions>0</HvciOptions>
  <Settings>
    <Setting Provider="PolicyInfo" Key="Information" ValueName="Name">
      <Value><String>Pester Round-Trip Test</String></Value>
    </Setting>
  </Settings>
</SiPolicy>
"@

        $xmlPath = Join-Path $testDir 'roundtrip-input.xml'
        $cipPath = Join-Path $testDir 'roundtrip-output.cip'
        Set-Content -Path $xmlPath -Value $testXml -Encoding UTF8

        ConvertFrom-CIPolicy -XmlFilePath $xmlPath -BinaryFilePath $cipPath -ErrorAction Stop
        $script:roundTripXml = ConvertFrom-WDACBinary -Path $cipPath -ErrorAction Stop
    }

    It 'produces a valid XmlDocument' {
        $script:roundTripXml | Should -BeOfType [System.Xml.XmlDocument]
    }

    It 'has SiPolicy root element with correct namespace' {
        $script:roundTripXml.DocumentElement.LocalName | Should -Be 'SiPolicy'
        $script:roundTripXml.DocumentElement.NamespaceURI | Should -Be 'urn:schemas-microsoft-com:sipolicy'
    }

    It 'sets PolicyType attribute to Base Policy' {
        $script:roundTripXml.DocumentElement.GetAttribute('PolicyType') | Should -Be 'Base Policy'
    }

    It 'preserves VersionEx as 10.0.5.0' {
        $nsm = [System.Xml.XmlNamespaceManager]::new($script:roundTripXml.NameTable)
        $nsm.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')
        $node = $script:roundTripXml.SelectSingleNode('//ns:VersionEx', $nsm)
        $node.InnerText | Should -Be '10.0.5.0'
    }

    It 'preserves PolicyID GUID' {
        $nsm = [System.Xml.XmlNamespaceManager]::new($script:roundTripXml.NameTable)
        $nsm.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')
        $node = $script:roundTripXml.SelectSingleNode('//ns:PolicyID', $nsm)
        $node | Should -Not -BeNullOrEmpty
        $parsed = [guid]::new($node.InnerText.Trim('{}'))
        $parsed | Should -Be $script:originalPolicyId
    }

    It 'preserves BasePolicyID GUID (equal to PolicyID for base policy)' {
        $nsm = [System.Xml.XmlNamespaceManager]::new($script:roundTripXml.NameTable)
        $nsm.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')
        $node = $script:roundTripXml.SelectSingleNode('//ns:BasePolicyID', $nsm)
        $node | Should -Not -BeNullOrEmpty
        $parsed = [guid]::new($node.InnerText.Trim('{}'))
        $parsed | Should -Be $script:originalPolicyId
    }

    It 'contains expected Rule Options' {
        $nsm = [System.Xml.XmlNamespaceManager]::new($script:roundTripXml.NameTable)
        $nsm.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')
        $options = @($script:roundTripXml.SelectNodes('//ns:Rules/ns:Rule/ns:Option', $nsm) |
            ForEach-Object { $_.InnerText })
        $options | Should -Contain 'Enabled:Audit Mode'
        $options | Should -Contain 'Enabled:Unsigned System Integrity Policy'
        $options | Should -Contain 'Enabled:Allow Supplemental Policies'
    }

    It 'preserves EKU count and value' {
        $nsm = [System.Xml.XmlNamespaceManager]::new($script:roundTripXml.NameTable)
        $nsm.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')
        $nodes = $script:roundTripXml.SelectNodes('//ns:EKUs/ns:EKU', $nsm)
        $nodes.Count | Should -Be 1
        $nodes[0].GetAttribute('Value') | Should -Be '010A2B0601040182370A0305'
    }

    It 'preserves FileRule count: 1 Allow + 1 Deny' {
        $nsm = [System.Xml.XmlNamespaceManager]::new($script:roundTripXml.NameTable)
        $nsm.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')
        $allows = $script:roundTripXml.SelectNodes('//ns:FileRules/ns:Allow', $nsm)
        $denies = $script:roundTripXml.SelectNodes('//ns:FileRules/ns:Deny', $nsm)
        $allows.Count | Should -Be 1
        $denies.Count | Should -Be 1
    }

    It 'preserves FileRule FileNames' {
        $nsm = [System.Xml.XmlNamespaceManager]::new($script:roundTripXml.NameTable)
        $nsm.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')
        $fileNames = @(
            $script:roundTripXml.SelectNodes('//ns:FileRules/*', $nsm) |
            ForEach-Object { $_.GetAttribute('FileName') }
        )
        $fileNames | Should -Contain 'TestAllow.dll'
        $fileNames | Should -Contain 'TestDeny.exe'
    }

    It 'preserves Signer count (1)' {
        $nsm = [System.Xml.XmlNamespaceManager]::new($script:roundTripXml.NameTable)
        $nsm.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')
        $nodes = $script:roundTripXml.SelectNodes('//ns:Signers/ns:Signer', $nsm)
        $nodes.Count | Should -Be 1
    }

    It 'preserves Signer CertRoot type and value' {
        $nsm = [System.Xml.XmlNamespaceManager]::new($script:roundTripXml.NameTable)
        $nsm.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')
        $certRoot = $script:roundTripXml.SelectSingleNode('//ns:Signers/ns:Signer/ns:CertRoot', $nsm)
        $certRoot.GetAttribute('Type') | Should -Be 'Wellknown'
        $certRoot.GetAttribute('Value') | Should -Be '03'
    }

    It 'preserves CertPublisher value' {
        $nsm = [System.Xml.XmlNamespaceManager]::new($script:roundTripXml.NameTable)
        $nsm.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')
        $certPub = $script:roundTripXml.SelectSingleNode('//ns:Signers/ns:Signer/ns:CertPublisher', $nsm)
        $certPub.GetAttribute('Value') | Should -Be 'TestPublisher'
    }

    It 'preserves SigningScenario count (2) and values (131, 12)' {
        $nsm = [System.Xml.XmlNamespaceManager]::new($script:roundTripXml.NameTable)
        $nsm.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')
        $nodes = $script:roundTripXml.SelectNodes('//ns:SigningScenarios/ns:SigningScenario', $nsm)
        $nodes.Count | Should -Be 2
        $values = @($nodes | ForEach-Object { $_.GetAttribute('Value') })
        $values | Should -Contain '131'
        $values | Should -Contain '12'
    }

    It 'preserves UpdatePolicySigner references' {
        $nsm = [System.Xml.XmlNamespaceManager]::new($script:roundTripXml.NameTable)
        $nsm.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')
        $nodes = $script:roundTripXml.SelectNodes('//ns:UpdatePolicySigners/ns:UpdatePolicySigner', $nsm)
        $nodes.Count | Should -Be 1
        $nodes[0].GetAttribute('SignerId') | Should -Match '^ID_SIGNER_S_\d+$'
    }

    It 'preserves CiSigner references' {
        $nsm = [System.Xml.XmlNamespaceManager]::new($script:roundTripXml.NameTable)
        $nsm.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')
        $nodes = $script:roundTripXml.SelectNodes('//ns:CiSigners/ns:CiSigner', $nsm)
        $nodes.Count | Should -Be 1
        $nodes[0].GetAttribute('SignerId') | Should -Match '^ID_SIGNER_S_\d+$'
    }

    It 'preserves HvciOptions value' {
        $nsm = [System.Xml.XmlNamespaceManager]::new($script:roundTripXml.NameTable)
        $nsm.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')
        $node = $script:roundTripXml.SelectSingleNode('//ns:HvciOptions', $nsm)
        $node.InnerText | Should -Be '0'
    }

    It 'preserves Settings entries with correct provider and key' {
        $nsm = [System.Xml.XmlNamespaceManager]::new($script:roundTripXml.NameTable)
        $nsm.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')
        $nodes = $script:roundTripXml.SelectNodes('//ns:Settings/ns:Setting', $nsm)
        $nodes.Count | Should -BeGreaterOrEqual 1

        $infoSetting = $nodes | Where-Object {
            $_.GetAttribute('Provider') -eq 'PolicyInfo' -and
            $_.GetAttribute('Key') -eq 'Information' -and
            $_.GetAttribute('ValueName') -eq 'Name'
        }
        $infoSetting | Should -Not -BeNullOrEmpty
    }

    It 'preserves Settings string value' {
        $nsm = [System.Xml.XmlNamespaceManager]::new($script:roundTripXml.NameTable)
        $nsm.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')
        $strNode = $script:roundTripXml.SelectSingleNode(
            '//ns:Settings/ns:Setting[@ValueName="Name"]/ns:Value/ns:String', $nsm)
        $strNode.InnerText | Should -Be 'Pester Round-Trip Test'
    }

    }

    AfterAll {
        $testDir = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'temp', 'pester-roundtrip'))
        if (Test-Path $testDir) {
            Remove-Item -Path $testDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Context 'FilePath rule round-trip — Priority 1 + 2 emit policy' -ForEach $script:roundTripCases {
        BeforeAll {
            # Test inputs — independent expected values, hardcoded from test design (not derived
            # from the SUT). Per tests/CLAUDE.md § Independent Expected Values.
            $script:fpPolicyId = [guid]::NewGuid()
            $script:fpInputs = @{
                FilePathLiteral = 'C:\Program Files\Vendor\PriorityOne.exe'
                FilePathMacro   = '%OSDRIVE%\Users\*\AppData\Local\App\*'
                FilePathCase    = 'c:\Windows\System32\probe.Exe'
                FileNameOnly    = 'TestFileName.dll'
                FileNameVersion = '2.5.0.0'
            }

            $testDir = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'temp', 'pester-roundtrip-fp'))
            if (-not (Test-Path $testDir)) {
                New-Item -ItemType Directory -Path $testDir -Force | Out-Null
            }

            $testXml = @"
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Base Policy">
  <VersionEx>1.0.0.0</VersionEx>
  <PlatformID>{00000000-0000-0000-0000-000000000000}</PlatformID>
  <PolicyID>{$($script:fpPolicyId)}</PolicyID>
  <BasePolicyID>{$($script:fpPolicyId)}</BasePolicyID>
  <Rules>
    <Rule><Option>Enabled:Unsigned System Integrity Policy</Option></Rule>
  </Rules>
  <EKUs>
    <EKU ID="ID_EKU_E_1" Value="010A2B0601040182370A0306" />
  </EKUs>
  <FileRules>
    <Allow ID="ID_ALLOW_A_1" FriendlyName="literal" FilePath="$($script:fpInputs.FilePathLiteral)" />
    <Allow ID="ID_ALLOW_A_2" FriendlyName="macro"   FilePath="$($script:fpInputs.FilePathMacro)" />
    <Allow ID="ID_ALLOW_A_3" FriendlyName="case"    FilePath="$($script:fpInputs.FilePathCase)" />
    <Deny  ID="ID_DENY_D_1"  FriendlyName="named"   FileName="$($script:fpInputs.FileNameOnly)" MinimumFileVersion="$($script:fpInputs.FileNameVersion)" />
  </FileRules>
  <Signers>
    <Signer ID="ID_SIGNER_S_1" Name="TestSigner">
      <CertRoot Type="Wellknown" Value="03" />
    </Signer>
  </Signers>
  <SigningScenarios>
    <SigningScenario ID="ID_SIGNINGSCENARIO_DRIVERS" Value="131" FriendlyName="Drivers">
      <ProductSigners />
    </SigningScenario>
    <SigningScenario ID="ID_SIGNINGSCENARIO_USERMODE" Value="12" FriendlyName="User">
      <ProductSigners>
        <FileRulesRef>
          <FileRuleRef RuleID="ID_ALLOW_A_1" />
          <FileRuleRef RuleID="ID_ALLOW_A_2" />
          <FileRuleRef RuleID="ID_ALLOW_A_3" />
          <FileRuleRef RuleID="ID_DENY_D_1" />
        </FileRulesRef>
      </ProductSigners>
    </SigningScenario>
  </SigningScenarios>
  <HvciOptions>0</HvciOptions>
</SiPolicy>
"@
            $xmlPath = Join-Path $testDir 'fp-input.xml'
            $cipPath = Join-Path $testDir 'fp-output.cip'
            Set-Content -Path $xmlPath -Value $testXml -Encoding UTF8

            ConvertFrom-CIPolicy -XmlFilePath $xmlPath -BinaryFilePath $cipPath -ErrorAction Stop
            $script:fpRoundTripXml = ConvertFrom-WDACBinary -Path $cipPath -ErrorAction Stop
            $script:fpNs = [System.Xml.XmlNamespaceManager]::new($script:fpRoundTripXml.NameTable)
            $script:fpNs.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')
        }

        It 'emits 3 Allow rules and 1 Deny rule from the FilePath+FileName mixed input' {
            $allows = $script:fpRoundTripXml.SelectNodes('//ns:FileRules/ns:Allow', $script:fpNs)
            $denies = $script:fpRoundTripXml.SelectNodes('//ns:FileRules/ns:Deny', $script:fpNs)
            $allows.Count | Should -Be 3
            $denies.Count | Should -Be 1
        }

        It 'emits FilePath attribute on each Allow rule matching the input verbatim' {
            $allows = $script:fpRoundTripXml.SelectNodes('//ns:FileRules/ns:Allow', $script:fpNs)
            $filePaths = @($allows | ForEach-Object { $_.GetAttribute('FilePath') })
            $filePaths | Should -Contain $script:fpInputs.FilePathLiteral
            $filePaths | Should -Contain $script:fpInputs.FilePathMacro
            $filePaths | Should -Contain $script:fpInputs.FilePathCase
        }

        It 'preserves case verbatim on FilePath (lowercase drive, mixed-case extension)' {
            $allows = $script:fpRoundTripXml.SelectNodes('//ns:FileRules/ns:Allow', $script:fpNs)
            $mixed = @($allows | Where-Object { $_.GetAttribute('FilePath') -clike 'c:\Windows*' })
            $mixed.Count | Should -Be 1
            $mixed[0].GetAttribute('FilePath') | Should -BeExactly $script:fpInputs.FilePathCase
        }

        It 'suppresses FriendlyName attribute on every FileRule (Round 3 emit policy)' {
            $rules = $script:fpRoundTripXml.SelectNodes('//ns:FileRules/*', $script:fpNs)
            foreach ($rule in $rules) {
                $rule.HasAttribute('FriendlyName') |
                    Should -BeFalse -Because 'FriendlyName must be suppressed entirely on FileRules (binary does not carry one)'
            }
        }

        It 'suppresses FileName attribute on FilePath rules (one-discriminator idiom)' {
            $allows = $script:fpRoundTripXml.SelectNodes('//ns:FileRules/ns:Allow', $script:fpNs)
            foreach ($rule in $allows) {
                $rule.HasAttribute('FileName') |
                    Should -BeFalse -Because 'FilePath rules must not carry FileName per one-discriminator-per-rule'
            }
        }

        It 'suppresses MinimumFileVersion attribute on FilePath rules (0.0.0.0 sentinel)' {
            $allows = $script:fpRoundTripXml.SelectNodes('//ns:FileRules/ns:Allow', $script:fpNs)
            foreach ($rule in $allows) {
                $rule.HasAttribute('MinimumFileVersion') |
                    Should -BeFalse -Because 'FilePath rules with no input MFV should suppress the 0.0.0.0 sentinel emitted by ConvertFrom-CIPolicy'
            }
        }

        It 'emits FileName and non-sentinel MinimumFileVersion on the Deny rule' {
            $denies = $script:fpRoundTripXml.SelectNodes('//ns:FileRules/ns:Deny', $script:fpNs)
            $deny = $denies[0]
            $deny.GetAttribute('FileName') | Should -Be $script:fpInputs.FileNameOnly
            $deny.GetAttribute('MinimumFileVersion') | Should -Be $script:fpInputs.FileNameVersion
        }

        It 'suppresses FilePath attribute on the FileName Deny rule' {
            $denies = $script:fpRoundTripXml.SelectNodes('//ns:FileRules/ns:Deny', $script:fpNs)
            $denies[0].HasAttribute('FilePath') | Should -BeFalse
        }

        It 'emits FileRule IDs in 4-digit uppercase hex format (ID_DENY_D_XXXX, ID_ALLOW_A_XXXX)' {
            $rules = $script:fpRoundTripXml.SelectNodes('//ns:FileRules/*', $script:fpNs)
            foreach ($rule in $rules) {
                $rule.GetAttribute('ID') |
                    Should -Match '^ID_(DENY_D|ALLOW_A|FILEATTRIB_F)_[0-9A-F]{4}$'
            }
        }

        AfterAll {
            $testDir = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'temp', 'pester-roundtrip-fp'))
            if (Test-Path $testDir) {
                Remove-Item -Path $testDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Context 'AppIDs attribute + SupplementalPolicySigners round-trip — Priority 3 emit policy' -ForEach $script:roundTripCases {
        BeforeAll {
            # Independent expected values: hardcoded inputs that the SUT must reproduce verbatim.
            # AppIDs is a FileRule attribute per cipolicy.xsd (AppIdType); SupplementalPolicySigners
            # is a top-level SiPolicy element populated from the V6 SupplementalSigner index array
            # (only present on base policies per WDAC semantics).
            $script:p3PolicyId = [guid]::NewGuid()
            $script:p3Inputs = @{
                AppTag1   = 'AlphaTag'
                AppTag2   = 'BetaTag'
                FileName1 = 'AlphaApp.exe'
                FileName2 = 'BetaApp.exe'
            }

            $testDir = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'temp', 'pester-roundtrip-p3'))
            if (-not (Test-Path $testDir)) {
                New-Item -ItemType Directory -Path $testDir -Force | Out-Null
            }

            $testXml = @"
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Base Policy">
  <VersionEx>1.0.0.0</VersionEx>
  <PlatformID>{00000000-0000-0000-0000-000000000000}</PlatformID>
  <PolicyID>{$($script:p3PolicyId)}</PolicyID>
  <BasePolicyID>{$($script:p3PolicyId)}</BasePolicyID>
  <Rules>
    <Rule><Option>Enabled:Unsigned System Integrity Policy</Option></Rule>
  </Rules>
  <EKUs>
    <EKU ID="ID_EKU_E_1" Value="010A2B0601040182370A0306" />
  </EKUs>
  <FileRules>
    <Allow ID="ID_ALLOW_A_1" FileName="$($script:p3Inputs.FileName1)" AppIDs="$($script:p3Inputs.AppTag1)" />
    <Allow ID="ID_ALLOW_A_2" FileName="$($script:p3Inputs.FileName2)" AppIDs="$($script:p3Inputs.AppTag2)" />
  </FileRules>
  <Signers>
    <Signer ID="ID_SIGNER_S_1" Name="P3TestSigner">
      <CertRoot Type="Wellknown" Value="03" />
    </Signer>
  </Signers>
  <SigningScenarios>
    <SigningScenario ID="ID_SIGNINGSCENARIO_DRIVERS" Value="131" FriendlyName="Drivers">
      <ProductSigners />
    </SigningScenario>
    <SigningScenario ID="ID_SIGNINGSCENARIO_USERMODE" Value="12" FriendlyName="User">
      <ProductSigners>
        <FileRulesRef>
          <FileRuleRef RuleID="ID_ALLOW_A_1" />
          <FileRuleRef RuleID="ID_ALLOW_A_2" />
        </FileRulesRef>
      </ProductSigners>
    </SigningScenario>
  </SigningScenarios>
  <SupplementalPolicySigners>
    <SupplementalPolicySigner SignerId="ID_SIGNER_S_1" />
  </SupplementalPolicySigners>
  <HvciOptions>0</HvciOptions>
</SiPolicy>
"@
            $xmlPath = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($testDir, 'p3-input.xml'))
            $cipPath = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($testDir, 'p3-output.cip'))
            Set-Content -Path $xmlPath -Value $testXml -Encoding UTF8

            ConvertFrom-CIPolicy -XmlFilePath $xmlPath -BinaryFilePath $cipPath -ErrorAction Stop
            $script:p3RoundTripXml = ConvertFrom-WDACBinary -Path $cipPath -ErrorAction Stop
            $script:p3Ns = [System.Xml.XmlNamespaceManager]::new($script:p3RoundTripXml.NameTable)
            $script:p3Ns.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')
        }

        It 'emits AppIDs attribute on each Allow rule matching input verbatim' {
            $allows = $script:p3RoundTripXml.SelectNodes('//ns:FileRules/ns:Allow', $script:p3Ns)
            $appIds = @($allows | ForEach-Object { $_.GetAttribute('AppIDs') })
            $appIds | Should -Contain $script:p3Inputs.AppTag1
            $appIds | Should -Contain $script:p3Inputs.AppTag2
        }

        It 'emits AppIDs as attribute, NOT as <AppIDTags> child element (XSD AppIdType)' {
            $allows = $script:p3RoundTripXml.SelectNodes('//ns:FileRules/ns:Allow', $script:p3Ns)
            foreach ($rule in $allows) {
                $rule.HasAttribute('AppIDs') |
                    Should -BeTrue -Because 'AppIDs is an attribute on the FileRule element per cipolicy.xsd line 617'
                $appIdTags = $rule.SelectSingleNode('ns:AppIDTags', $script:p3Ns)
                $appIdTags |
                    Should -BeNullOrEmpty -Because 'AppIDTags is a separate construct used on SigningScenario, not FileRule'
            }
        }

        It 'emits SupplementalPolicySigners section with one SupplementalPolicySigner' {
            $sps = $script:p3RoundTripXml.SelectSingleNode('//ns:SupplementalPolicySigners', $script:p3Ns)
            $sps |
                Should -Not -BeNullOrEmpty -Because 'Base policies with V6 SupplementalSignerCount > 0 must emit SupplementalPolicySigners section'
            $children = $sps.SelectNodes('ns:SupplementalPolicySigner', $script:p3Ns)
            $children.Count | Should -Be 1
            $children[0].GetAttribute('SignerId') | Should -Match '^ID_SIGNER_S_\d+$'
        }

        It 'omits FileName attribute when binary does not carry one (FilePath/Hash rules unaffected here)' {
            # This Allow ruleset uses FileName+AppIDs so FileName SHOULD be emitted.
            $allows = $script:p3RoundTripXml.SelectNodes('//ns:FileRules/ns:Allow', $script:p3Ns)
            $fileNames = @($allows | ForEach-Object { $_.GetAttribute('FileName') })
            $fileNames | Should -Contain $script:p3Inputs.FileName1
            $fileNames | Should -Contain $script:p3Inputs.FileName2
        }

        AfterAll {
            $testDir = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'temp', 'pester-roundtrip-p3'))
            if (Test-Path $testDir) {
                Remove-Item -Path $testDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Context 'OptionFlags transparency comments — binary-only and unregistered bits' -ForEach $script:roundTripCases {
        BeforeAll {
            $script:r8TestDir = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'temp', 'pester-roundtrip-r8'))
            if (-not (Test-Path $script:r8TestDir)) {
                New-Item -ItemType Directory -Path $script:r8TestDir -Force | Out-Null
            }
            $script:r8PolicyId = [guid]::NewGuid()
            $r8Xml = @"
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Base Policy">
  <VersionEx>1.0.0.0</VersionEx>
  <PlatformID>{00000000-0000-0000-0000-000000000000}</PlatformID>
  <PolicyID>{$($script:r8PolicyId)}</PolicyID>
  <BasePolicyID>{$($script:r8PolicyId)}</BasePolicyID>
  <Rules>
    <Rule><Option>Enabled:Unsigned System Integrity Policy</Option></Rule>
    <Rule><Option>Enabled:UMCI</Option></Rule>
  </Rules>
  <EKUs />
  <FileRules>
    <Allow ID="ID_ALLOW_A_1" FileName="r8.dll" />
  </FileRules>
  <Signers>
    <Signer ID="ID_SIGNER_S_1" Name="R8Signer">
      <CertRoot Type="Wellknown" Value="03" />
    </Signer>
  </Signers>
  <SigningScenarios>
    <SigningScenario ID="ID_SIGNINGSCENARIO_DRIVERS" Value="131" FriendlyName="Drivers">
      <ProductSigners />
    </SigningScenario>
    <SigningScenario ID="ID_SIGNINGSCENARIO_USERMODE" Value="12" FriendlyName="User">
      <ProductSigners>
        <AllowedSigners>
          <AllowedSigner SignerId="ID_SIGNER_S_1" />
        </AllowedSigners>
      </ProductSigners>
    </SigningScenario>
  </SigningScenarios>
  <HvciOptions>0</HvciOptions>
</SiPolicy>
"@
            $script:r8XmlPath = [System.IO.Path]::Combine($script:r8TestDir, 'r8-source.xml')
            $script:r8CipPath = [System.IO.Path]::Combine($script:r8TestDir, 'r8-source.cip')
            [System.IO.File]::WriteAllText($script:r8XmlPath, $r8Xml, [System.Text.UTF8Encoding]::new($true))
            ConvertFrom-CIPolicy -XmlFilePath $script:r8XmlPath -BinaryFilePath $script:r8CipPath | Out-Null

            $script:r8Bytes = [System.IO.File]::ReadAllBytes($script:r8CipPath)
            $script:r8OriginalFlags = [BitConverter]::ToUInt32($script:r8Bytes, 0x24)

            # Patch OptionFlags: keep all existing bits, additionally set bit 6 (binary-only)
            # and bit 12 (unregistered in workspace map). Bits 30-31 are preserved via the
            # original flags' high portion.
            $script:r8PatchedFlags = $script:r8OriginalFlags -bor 0x40 -bor 0x1000
            $patchedBytes = [BitConverter]::GetBytes($script:r8PatchedFlags)
            [Array]::Copy($patchedBytes, 0, $script:r8Bytes, 0x24, 4)

            $script:r8DecodedXml = ConvertFrom-WDACBinary -Data $script:r8Bytes
            $script:r8Ns = [System.Xml.XmlNamespaceManager]::new($script:r8DecodedXml.NameTable)
            $script:r8Ns.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')
            $script:r8RulesNode = $script:r8DecodedXml.SelectSingleNode('//ns:Rules', $script:r8Ns)
        }

        It 'emits the XSD-canonical UMCI option as a <Rule><Option> element' {
            $options = @($script:r8RulesNode.SelectNodes('ns:Rule/ns:Option', $script:r8Ns) |
                ForEach-Object { $_.InnerText })
            $options | Should -Contain 'Enabled:UMCI'
        }

        It 'emits the XSD-canonical Unsigned System Integrity Policy option as a <Rule><Option> element' {
            $options = @($script:r8RulesNode.SelectNodes('ns:Rule/ns:Option', $script:r8Ns) |
                ForEach-Object { $_.InnerText })
            $options | Should -Contain 'Enabled:Unsigned System Integrity Policy'
        }

        It 'emits a transparency comment naming Windows Lockdown Trial Mode for binary-only bit 6' {
            $comments = @($script:r8RulesNode.ChildNodes |
                Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Comment })
            $bit6Comment = $comments | Where-Object { $_.Value -match 'bit 6 ' }
            $bit6Comment | Should -Not -BeNullOrEmpty
            $bit6Comment.Value | Should -Match 'Windows Lockdown Trial Mode'
            $bit6Comment.Value | Should -Match '0x00000040'
        }

        It 'emits a transparency comment marking bit 12 as unregistered' {
            $comments = @($script:r8RulesNode.ChildNodes |
                Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Comment })
            $bit12Comment = $comments | Where-Object { $_.Value -match 'bit 12 ' }
            $bit12Comment | Should -Not -BeNullOrEmpty
            $bit12Comment.Value | Should -Match 'unregistered'
            $bit12Comment.Value | Should -Match '0x00001000'
        }

        It 'does not emit Option elements for binary-only or unregistered bits' {
            $options = @($script:r8RulesNode.SelectNodes('ns:Rule/ns:Option', $script:r8Ns) |
                ForEach-Object { $_.InnerText })
            $options | Should -Not -Contain 'Enabled:Windows Lockdown Trial Mode'
            $options | ForEach-Object { $_ | Should -Not -Match 'bit 6|bit 12|undocumented|unregistered' }
        }

        It 'preserves Microsoft re-compile compatibility when transparency comments are present' {
            $reCompilePath = [System.IO.Path]::Combine($script:r8TestDir, 'r8-recompile-source.xml')
            $reCompileCip = [System.IO.Path]::Combine($script:r8TestDir, 'r8-recompile.cip')
            $xmlSettings = [System.Xml.XmlWriterSettings]::new()
            $xmlSettings.Indent = $true
            $xmlSettings.IndentChars = '    '
            $xmlSettings.Encoding = [System.Text.UTF8Encoding]::new($true)
            $writer = [System.Xml.XmlWriter]::Create($reCompilePath, $xmlSettings)
            try { $script:r8DecodedXml.Save($writer) } finally { $writer.Close() }

            { ConvertFrom-CIPolicy -XmlFilePath $reCompilePath -BinaryFilePath $reCompileCip -ErrorAction Stop | Out-Null } |
                Should -Not -Throw
            (Get-Item $reCompileCip).Length | Should -BeGreaterThan 0
        }

        AfterAll {
            if (Test-Path $script:r8TestDir) {
                Remove-Item -Path $script:r8TestDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}
