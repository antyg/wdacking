#Requires -Modules Pester

BeforeAll {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $moduleRoot 'src' 'antyg-wdacking.psd1') -Force

    # Create a temp file so [System.IO.FileInfo] works in the adapter
    $script:tempDir = Join-Path ([System.IO.Path]::GetTempPath()) 'WDACPolicyObjectTests'
    if (-not (Test-Path $script:tempDir)) { New-Item -ItemType Directory -Path $script:tempDir -Force | Out-Null }

    # Helper: build an XmlDocument from a string
    function New-TestXml {
        param([string]$XmlString)
        $doc = [System.Xml.XmlDocument]::new()
        $doc.LoadXml($XmlString)
        return $doc
    }

    # Helper: create a temp file with known size
    function New-TestPolicyFile {
        param([string]$FileName, [int]$Size = 248)
        $path = Join-Path $script:tempDir $FileName
        $bytes = [byte[]]::new($Size)
        [System.IO.File]::WriteAllBytes($path, $bytes)
        return $path
    }
}

AfterAll {
    if (Test-Path $script:tempDir) {
        Remove-Item $script:tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# =========================================================================
# V6+ Base Policy — PolicyID, BasePolicyID, FriendlyName, Audit mode
# =========================================================================
Describe 'ConvertTo-WDACPolicyObject' {

    Context 'V6+ base policy with FriendlyName and Audit mode' {
        BeforeAll {
            $script:v6File = New-TestPolicyFile -FileName '{a1b2c3d4-e5f6-7890-abcd-ef1234567890}.cip' -Size 248
            $script:v6Xml = New-TestXml @'
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy PolicyType="Base Policy" xmlns="urn:schemas-microsoft-com:sipolicy">
  <VersionEx>10.0.5.0</VersionEx>
  <PlatformID>{00000000-0000-0000-0000-000000000000}</PlatformID>
  <PolicyID>{a1b2c3d4-e5f6-7890-abcd-ef1234567890}</PolicyID>
  <BasePolicyID>{a1b2c3d4-e5f6-7890-abcd-ef1234567890}</BasePolicyID>
  <Rules>
    <Rule><Option>Enabled:Audit Mode</Option></Rule>
    <Rule><Option>Enabled:Unsigned System Integrity Policy</Option></Rule>
  </Rules>
  <EKUs />
  <FileRules />
  <Signers />
  <SigningScenarios />
  <UpdatePolicySigners />
  <CiSigners />
  <HvciOptions>0</HvciOptions>
  <Settings>
    <Setting Provider="PolicyInfo" Key="Information" ValueName="Name">
      <Value><String>Test Base Policy</String></Value>
    </Setting>
  </Settings>
</SiPolicy>
'@
            $script:v6Result = ConvertTo-WDACPolicyObject -Xml $script:v6Xml -FormatVersion 8 -FilePath $script:v6File -Location 'MultiPolicy'
        }

        It 'extracts PolicyId from <PolicyID> element' {
            $script:v6Result.PolicyId | Should -Be 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
        }

        It 'extracts BasePolicyId from <BasePolicyID> element' {
            $script:v6Result.BasePolicyId | Should -Be 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
        }

        It 'extracts FriendlyName from Settings' {
            $script:v6Result.FriendlyName | Should -Be 'Test Base Policy'
        }

        It 'extracts Version from <VersionEx>' {
            $script:v6Result.Version | Should -Be '10.0.5.0'
        }

        It 'identifies as non-supplemental when PolicyId equals BasePolicyId' {
            $script:v6Result.IsSupplemental | Should -BeFalse
        }

        It 'detects Audit enforcement mode from Rule Options' {
            $script:v6Result.EnforcementMode | Should -Be 'Audit'
        }

        It 'passes through FormatVersion from parameter' {
            $script:v6Result.FormatVersion | Should -Be 8
        }

        It 'extracts PolicyType from SiPolicy attribute' {
            $script:v6Result.PolicyType | Should -Be 'Base Policy'
        }

        It 'reverse-maps RuleOptions names to correct IDs' {
            $script:v6Result.RuleOptions | Should -HaveCount 2
            $auditOption = $script:v6Result.RuleOptions | Where-Object { $_.Name -eq 'Enabled:Audit Mode' }
            $auditOption.Id | Should -Be 3
            $unsignedOption = $script:v6Result.RuleOptions | Where-Object { $_.Name -eq 'Enabled:Unsigned System Integrity Policy' }
            $unsignedOption.Id | Should -Be 6
        }

        It 'sets Location from parameter' {
            $script:v6Result.Location | Should -Be 'MultiPolicy'
        }

        It 'populates FileSize from the file on disk' {
            $script:v6Result.FileSize | Should -Be 248
        }

        It 'populates LastModified as a DateTime' {
            $script:v6Result.LastModified | Should -BeOfType [datetime]
            $script:v6Result.LastModified | Should -BeGreaterThan ([datetime]'2026-01-01')
        }
    }

    # =========================================================================
    # V6+ Supplemental Policy — PolicyId != BasePolicyId, Enforced mode
    # =========================================================================
    Context 'V6+ supplemental policy in Enforced mode' {
        BeforeAll {
            $script:suppFile = New-TestPolicyFile -FileName '{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}.cip' -Size 300
            $script:suppXml = New-TestXml @'
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy PolicyType="Supplemental Policy" xmlns="urn:schemas-microsoft-com:sipolicy">
  <VersionEx>2.1.0.0</VersionEx>
  <PlatformID>{00000000-0000-0000-0000-000000000000}</PlatformID>
  <PolicyID>{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}</PolicyID>
  <BasePolicyID>{11111111-2222-3333-4444-555555555555}</BasePolicyID>
  <Rules>
    <Rule><Option>Enabled:Unsigned System Integrity Policy</Option></Rule>
  </Rules>
  <EKUs />
  <FileRules />
  <Signers />
  <SigningScenarios />
  <UpdatePolicySigners />
  <CiSigners />
  <HvciOptions>0</HvciOptions>
</SiPolicy>
'@
            $script:suppResult = ConvertTo-WDACPolicyObject -Xml $script:suppXml -FormatVersion 8 -FilePath $script:suppFile -Location 'MultiPolicy'
        }

        It 'identifies as supplemental when PolicyId differs from BasePolicyId' {
            $script:suppResult.IsSupplemental | Should -BeTrue
        }

        It 'extracts the supplemental PolicyId' {
            $script:suppResult.PolicyId | Should -Be 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        }

        It 'extracts the base policy BasePolicyId' {
            $script:suppResult.BasePolicyId | Should -Be '11111111-2222-3333-4444-555555555555'
        }

        It 'detects Enforced mode when Audit Mode option is absent' {
            $script:suppResult.EnforcementMode | Should -Be 'Enforced'
        }

        It 'extracts PolicyType as Supplemental Policy' {
            $script:suppResult.PolicyType | Should -Be 'Supplemental Policy'
        }

        It 'returns empty FriendlyName when Settings are absent' {
            $script:suppResult.FriendlyName | Should -BeExactly ''
        }
    }

    # =========================================================================
    # Legacy format — PolicyTypeID GUID classification
    # =========================================================================
    Context 'Legacy format with known Enterprise GUID' {
        BeforeAll {
            $script:legacyFile = New-TestPolicyFile -FileName 'SIPolicy.p7b' -Size 512
            $script:legacyXml = New-TestXml @'
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
  <VersionEx>6.3.0.0</VersionEx>
  <PolicyTypeID>{a244370e-44c9-4c06-b551-f6016e563076}</PolicyTypeID>
  <PlatformID>{00000000-0000-0000-0000-000000000000}</PlatformID>
  <Rules>
    <Rule><Option>Enabled:Audit Mode</Option></Rule>
  </Rules>
  <EKUs />
  <FileRules />
  <Signers />
  <SigningScenarios />
  <UpdatePolicySigners />
  <CiSigners />
  <HvciOptions>0</HvciOptions>
</SiPolicy>
'@
            $script:legacyResult = ConvertTo-WDACPolicyObject -Xml $script:legacyXml -FormatVersion 3 -FilePath $script:legacyFile -Location 'Legacy'
        }

        It 'uses PolicyTypeID GUID as PolicyId' {
            $script:legacyResult.PolicyId | Should -Be 'a244370e-44c9-4c06-b551-f6016e563076'
        }

        It 'uses PolicyTypeID GUID as BasePolicyId' {
            $script:legacyResult.BasePolicyId | Should -Be 'a244370e-44c9-4c06-b551-f6016e563076'
        }

        It 'classifies known Enterprise GUID to Enterprise PolicyType' {
            $script:legacyResult.PolicyType | Should -Be 'Enterprise'
        }

        It 'identifies as non-supplemental for legacy single-policy' {
            $script:legacyResult.IsSupplemental | Should -BeFalse
        }

        It 'passes through FormatVersion 3' {
            $script:legacyResult.FormatVersion | Should -Be 3
        }

        It 'sets Location to Legacy' {
            $script:legacyResult.Location | Should -Be 'Legacy'
        }
    }

    # =========================================================================
    # Legacy format — all 6 known GUID classifications
    # =========================================================================
    Context 'Legacy format classifies all 6 known PolicyTypeID GUIDs' {
        BeforeAll {
            $script:guidTestFile = New-TestPolicyFile -FileName 'guid-test.cip' -Size 100

            $script:knownGuids = @(
                @{ Guid = 'a244370e-44c9-4c06-b551-f6016e563076'; Expected = 'Enterprise' }
                @{ Guid = '2a5a0136-f09f-498e-99cc-51099011157c'; Expected = 'Revoke' }
                @{ Guid = '976d12c8-cb9f-4730-be52-54600843238e'; Expected = 'SKU' }
                @{ Guid = '5951a96a-e0b5-4d3d-8fb8-3e5b61030784'; Expected = 'WindowsLockdown' }
                @{ Guid = '4e61c68c-97f6-430b-9cd7-9b1004706770'; Expected = 'ATP' }
                @{ Guid = 'd2bda982-ccf6-4344-ac5b-0b44427b6816'; Expected = 'Driver' }
            )
        }

        It 'classifies <Guid> as <Expected>' -ForEach @(
            @{ Guid = 'a244370e-44c9-4c06-b551-f6016e563076'; Expected = 'Enterprise' }
            @{ Guid = '2a5a0136-f09f-498e-99cc-51099011157c'; Expected = 'Revoke' }
            @{ Guid = '976d12c8-cb9f-4730-be52-54600843238e'; Expected = 'SKU' }
            @{ Guid = '5951a96a-e0b5-4d3d-8fb8-3e5b61030784'; Expected = 'WindowsLockdown' }
            @{ Guid = '4e61c68c-97f6-430b-9cd7-9b1004706770'; Expected = 'ATP' }
            @{ Guid = 'd2bda982-ccf6-4344-ac5b-0b44427b6816'; Expected = 'Driver' }
        ) {
            $xml = New-TestXml @"
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
  <VersionEx>1.0.0.0</VersionEx>
  <PolicyTypeID>{$Guid}</PolicyTypeID>
  <PlatformID>{00000000-0000-0000-0000-000000000000}</PlatformID>
  <Rules /><EKUs /><FileRules /><Signers /><SigningScenarios />
  <UpdatePolicySigners /><CiSigners /><HvciOptions>0</HvciOptions>
</SiPolicy>
"@
            $result = ConvertTo-WDACPolicyObject -Xml $xml -FormatVersion 3 -FilePath $script:guidTestFile -Location 'Legacy'
            $result.PolicyType | Should -Be $Expected
        }
    }

    # =========================================================================
    # Legacy format — unknown GUID returns GUID string
    # =========================================================================
    Context 'Legacy format with unknown PolicyTypeID GUID' {
        BeforeAll {
            $script:unknownFile = New-TestPolicyFile -FileName 'unknown-type.cip' -Size 100
            $script:unknownXml = New-TestXml @'
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
  <VersionEx>1.0.0.0</VersionEx>
  <PolicyTypeID>{deadbeef-cafe-babe-face-123456789abc}</PolicyTypeID>
  <PlatformID>{00000000-0000-0000-0000-000000000000}</PlatformID>
  <Rules /><EKUs /><FileRules /><Signers /><SigningScenarios />
  <UpdatePolicySigners /><CiSigners /><HvciOptions>0</HvciOptions>
</SiPolicy>
'@
            $script:unknownResult = ConvertTo-WDACPolicyObject -Xml $script:unknownXml -FormatVersion 3 -FilePath $script:unknownFile -Location 'MultiPolicy'
        }

        It 'returns the unknown GUID wrapped in braces as PolicyType' {
            $script:unknownResult.PolicyType | Should -Be '{deadbeef-cafe-babe-face-123456789abc}'
        }
    }

    # =========================================================================
    # Fallback: PolicyId from filename when XML has no ID elements
    # =========================================================================
    Context 'Fallback to filename GUID when XML has no PolicyID or PolicyTypeID' {
        BeforeAll {
            $script:fallbackFile = New-TestPolicyFile -FileName '{CAFEBABE-1234-5678-9ABC-DEF012345678}.cip' -Size 100
            $script:fallbackXml = New-TestXml @'
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
  <VersionEx>1.0.0.0</VersionEx>
  <PlatformID>{00000000-0000-0000-0000-000000000000}</PlatformID>
  <Rules /><EKUs /><FileRules /><Signers /><SigningScenarios />
  <UpdatePolicySigners /><CiSigners /><HvciOptions>0</HvciOptions>
</SiPolicy>
'@
            $script:fallbackResult = ConvertTo-WDACPolicyObject -Xml $script:fallbackXml -FormatVersion 5 -FilePath $script:fallbackFile -Location 'EFI' -WarningAction SilentlyContinue
        }

        It 'extracts PolicyId from filename GUID' {
            $script:fallbackResult.PolicyId | Should -Be 'cafebabe-1234-5678-9abc-def012345678'
        }

        It 'leaves BasePolicyId empty' {
            $script:fallbackResult.BasePolicyId | Should -BeExactly ''
        }

        It 'sets PolicyType to Unknown when no classification source exists' {
            $script:fallbackResult.PolicyType | Should -Be 'Unknown'
        }

        It 'sets Location to EFI' {
            $script:fallbackResult.Location | Should -Be 'EFI'
        }
    }

    # =========================================================================
    # Fallback: non-GUID filename
    # =========================================================================
    Context 'Fallback to raw filename when filename is not a GUID' {
        BeforeAll {
            $script:rawNameFile = New-TestPolicyFile -FileName 'SIPolicy.p7b' -Size 100
            $script:rawNameXml = New-TestXml @'
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
  <VersionEx>1.0.0.0</VersionEx>
  <PlatformID>{00000000-0000-0000-0000-000000000000}</PlatformID>
  <Rules /><EKUs /><FileRules /><Signers /><SigningScenarios />
  <UpdatePolicySigners /><CiSigners /><HvciOptions>0</HvciOptions>
</SiPolicy>
'@
            $script:rawNameResult = ConvertTo-WDACPolicyObject -Xml $script:rawNameXml -FormatVersion 3 -FilePath $script:rawNameFile -Location 'Legacy' -WarningAction SilentlyContinue
        }

        It 'uses the raw filename as PolicyId' {
            $script:rawNameResult.PolicyId | Should -Be 'SIPolicy'
        }
    }

    # =========================================================================
    # RuleOptions: all 21 known option names mapped to correct IDs
    # =========================================================================
    Context 'RuleOptions reverse-maps all 21 known option names' {
        BeforeAll {
            $script:allOptsFile = New-TestPolicyFile -FileName 'all-options.cip' -Size 100
            $script:allOptsXml = New-TestXml @'
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy PolicyType="Base Policy" xmlns="urn:schemas-microsoft-com:sipolicy">
  <VersionEx>10.0.0.0</VersionEx>
  <PlatformID>{00000000-0000-0000-0000-000000000000}</PlatformID>
  <PolicyID>{00000000-0000-0000-0000-000000000001}</PolicyID>
  <BasePolicyID>{00000000-0000-0000-0000-000000000001}</BasePolicyID>
  <Rules>
    <Rule><Option>Enabled:UMCI</Option></Rule>
    <Rule><Option>Enabled:Boot Menu Protection</Option></Rule>
    <Rule><Option>Required:WHQL</Option></Rule>
    <Rule><Option>Enabled:Audit Mode</Option></Rule>
    <Rule><Option>Disabled:Flight Signing</Option></Rule>
    <Rule><Option>Enabled:Inherit Default Policy</Option></Rule>
    <Rule><Option>Enabled:Unsigned System Integrity Policy</Option></Rule>
    <Rule><Option>Enabled:Dynamic Code Security</Option></Rule>
    <Rule><Option>Required:EV Signers</Option></Rule>
    <Rule><Option>Enabled:Boot Audit On Failure</Option></Rule>
    <Rule><Option>Enabled:Advanced Boot Options Menu</Option></Rule>
    <Rule><Option>Disabled:Script Enforcement</Option></Rule>
    <Rule><Option>Required:Enforce Store Applications</Option></Rule>
    <Rule><Option>Enabled:Managed Installer</Option></Rule>
    <Rule><Option>Enabled:Update Policy No Reboot</Option></Rule>
    <Rule><Option>Enabled:Allow Supplemental Policies</Option></Rule>
    <Rule><Option>Disabled:Runtime FilePath Rule Protection</Option></Rule>
    <Rule><Option>Enabled:Revoked Expired As Unsigned</Option></Rule>
    <Rule><Option>Enabled:Intelligent Security Graph Authorization</Option></Rule>
    <Rule><Option>Enabled:Invalidate EAs on Reboot</Option></Rule>
    <Rule><Option>Enabled:Developer Mode Dynamic Code Trust</Option></Rule>
  </Rules>
  <EKUs /><FileRules /><Signers /><SigningScenarios />
  <UpdatePolicySigners /><CiSigners /><HvciOptions>0</HvciOptions>
</SiPolicy>
'@
            $script:allOptsResult = ConvertTo-WDACPolicyObject -Xml $script:allOptsXml -FormatVersion 8 -FilePath $script:allOptsFile -Location 'MultiPolicy'
        }

        It 'returns 21 rule options' {
            $script:allOptsResult.RuleOptions | Should -HaveCount 21
        }

        It 'maps Enabled:UMCI to ID 0' {
            ($script:allOptsResult.RuleOptions | Where-Object Name -eq 'Enabled:UMCI').Id | Should -Be 0
        }

        It 'maps Enabled:Boot Menu Protection to ID 1' {
            ($script:allOptsResult.RuleOptions | Where-Object Name -eq 'Enabled:Boot Menu Protection').Id | Should -Be 1
        }

        It 'maps Required:WHQL to ID 2' {
            ($script:allOptsResult.RuleOptions | Where-Object Name -eq 'Required:WHQL').Id | Should -Be 2
        }

        It 'maps Enabled:Audit Mode to ID 3' {
            ($script:allOptsResult.RuleOptions | Where-Object Name -eq 'Enabled:Audit Mode').Id | Should -Be 3
        }

        It 'maps Enabled:Allow Supplemental Policies to ID 15' {
            ($script:allOptsResult.RuleOptions | Where-Object Name -eq 'Enabled:Allow Supplemental Policies').Id | Should -Be 15
        }

        It 'maps Enabled:Developer Mode Dynamic Code Trust to ID 20' {
            ($script:allOptsResult.RuleOptions | Where-Object Name -eq 'Enabled:Developer Mode Dynamic Code Trust').Id | Should -Be 20
        }
    }

    # =========================================================================
    # Unknown rule option name gets ID 999
    # =========================================================================
    Context 'Unknown rule option name receives fallback ID' {
        BeforeAll {
            $script:unkOptFile = New-TestPolicyFile -FileName 'unk-option.cip' -Size 100
            $script:unkOptXml = New-TestXml @'
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy PolicyType="Base Policy" xmlns="urn:schemas-microsoft-com:sipolicy">
  <VersionEx>1.0.0.0</VersionEx>
  <PlatformID>{00000000-0000-0000-0000-000000000000}</PlatformID>
  <PolicyID>{00000000-0000-0000-0000-000000000001}</PolicyID>
  <BasePolicyID>{00000000-0000-0000-0000-000000000001}</BasePolicyID>
  <Rules>
    <Rule><Option>Enabled:Some Future Option</Option></Rule>
  </Rules>
  <EKUs /><FileRules /><Signers /><SigningScenarios />
  <UpdatePolicySigners /><CiSigners /><HvciOptions>0</HvciOptions>
</SiPolicy>
'@
            $script:unkOptResult = ConvertTo-WDACPolicyObject -Xml $script:unkOptXml -FormatVersion 8 -FilePath $script:unkOptFile -Location 'MultiPolicy'
        }

        It 'assigns ID 999 to unknown option names' {
            $script:unkOptResult.RuleOptions | Should -HaveCount 1
            $script:unkOptResult.RuleOptions[0].Id | Should -Be 999
            $script:unkOptResult.RuleOptions[0].Name | Should -Be 'Enabled:Some Future Option'
        }
    }

    # =========================================================================
    # Minimal XML — missing optional elements default gracefully
    # =========================================================================
    Context 'Minimal XML with missing VersionEx and empty Rules' {
        BeforeAll {
            $script:minFile = New-TestPolicyFile -FileName '{11111111-1111-1111-1111-111111111111}.cip' -Size 64
            $script:minXml = New-TestXml @'
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy PolicyType="Base Policy" xmlns="urn:schemas-microsoft-com:sipolicy">
  <PlatformID>{00000000-0000-0000-0000-000000000000}</PlatformID>
  <PolicyID>{11111111-1111-1111-1111-111111111111}</PolicyID>
  <BasePolicyID>{11111111-1111-1111-1111-111111111111}</BasePolicyID>
  <Rules />
  <EKUs /><FileRules /><Signers /><SigningScenarios />
  <UpdatePolicySigners /><CiSigners /><HvciOptions>0</HvciOptions>
</SiPolicy>
'@
            $script:minResult = ConvertTo-WDACPolicyObject -Xml $script:minXml -FormatVersion 7 -FilePath $script:minFile -Location 'MultiPolicy' -WarningAction SilentlyContinue
        }

        It 'reports Version as Unknown when VersionEx is absent' {
            $script:minResult.Version | Should -Be 'Unknown'
        }

        It 'returns empty RuleOptions array when Rules element is empty' {
            $script:minResult.RuleOptions | Should -HaveCount 0
        }

        It 'defaults EnforcementMode to Enforced when Rules element is present but empty' {
            # <Rules /> is present — this is a genuine "no rule options" state, not a parse failure
            $script:minResult.EnforcementMode | Should -Be 'Enforced'
        }

        It 'defaults FriendlyName to empty string when no Settings exist' {
            $script:minResult.FriendlyName | Should -BeExactly ''
        }
    }

    # =========================================================================
    # Degraded parse — Rules element entirely absent
    # =========================================================================
    Context 'Degraded parse — Rules element absent from XML' {
        BeforeAll {
            $script:noRulesFile = New-TestPolicyFile -FileName '{33333333-3333-3333-3333-333333333333}.cip' -Size 64
            $script:noRulesXml = New-TestXml @'
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy PolicyType="Base Policy" xmlns="urn:schemas-microsoft-com:sipolicy">
  <VersionEx>1.0.0.0</VersionEx>
  <PlatformID>{00000000-0000-0000-0000-000000000000}</PlatformID>
  <PolicyID>{33333333-3333-3333-3333-333333333333}</PolicyID>
  <BasePolicyID>{33333333-3333-3333-3333-333333333333}</BasePolicyID>
  <EKUs /><FileRules /><Signers /><SigningScenarios />
  <UpdatePolicySigners /><CiSigners /><HvciOptions>0</HvciOptions>
</SiPolicy>
'@
            $script:noRulesResult = ConvertTo-WDACPolicyObject -Xml $script:noRulesXml -FormatVersion 7 -FilePath $script:noRulesFile -Location 'MultiPolicy' -WarningAction SilentlyContinue
        }

        It 'reports EnforcementMode as Unknown when Rules element is absent' {
            $script:noRulesResult.EnforcementMode | Should -Be 'Unknown'
        }

        It 'returns empty RuleOptions array when Rules element is absent' {
            $script:noRulesResult.RuleOptions | Should -HaveCount 0
        }

        It 'still extracts PolicyId correctly despite degraded parse' {
            $script:noRulesResult.PolicyId | Should -Be '33333333-3333-3333-3333-333333333333'
        }
    }

    # =========================================================================
    # Output contract: all 13 properties present with correct types
    # =========================================================================
    Context 'Output contract — 13 properties with correct types' {
        BeforeAll {
            $script:contractFile = New-TestPolicyFile -FileName '{22222222-2222-2222-2222-222222222222}.cip' -Size 200
            $script:contractXml = New-TestXml @'
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy PolicyType="Base Policy" xmlns="urn:schemas-microsoft-com:sipolicy">
  <VersionEx>5.0.0.0</VersionEx>
  <PlatformID>{00000000-0000-0000-0000-000000000000}</PlatformID>
  <PolicyID>{22222222-2222-2222-2222-222222222222}</PolicyID>
  <BasePolicyID>{22222222-2222-2222-2222-222222222222}</BasePolicyID>
  <Rules>
    <Rule><Option>Enabled:UMCI</Option></Rule>
  </Rules>
  <EKUs /><FileRules /><Signers /><SigningScenarios />
  <UpdatePolicySigners /><CiSigners /><HvciOptions>0</HvciOptions>
</SiPolicy>
'@
            $script:contractResult = ConvertTo-WDACPolicyObject -Xml $script:contractXml -FormatVersion 8 -FilePath $script:contractFile -Location 'MultiPolicy'
            $script:contractProps = $script:contractResult.PSObject.Properties
        }

        It 'returns exactly 13 properties' {
            $script:contractProps | Should -HaveCount 13
        }

        It 'has PolicyId as [string]' {
            $script:contractResult.PolicyId | Should -BeOfType [string]
            $script:contractResult.PolicyId | Should -Be '22222222-2222-2222-2222-222222222222'
        }

        It 'has BasePolicyId as [string]' {
            $script:contractResult.BasePolicyId | Should -BeOfType [string]
            $script:contractResult.BasePolicyId | Should -Be '22222222-2222-2222-2222-222222222222'
        }

        It 'has FriendlyName as [string]' {
            $script:contractResult.FriendlyName | Should -BeOfType [string]
        }

        It 'has Version as [string]' {
            $script:contractResult.Version | Should -BeOfType [string]
            $script:contractResult.Version | Should -Be '5.0.0.0'
        }

        It 'has IsSupplemental as [bool]' {
            $script:contractResult.IsSupplemental | Should -BeOfType [bool]
        }

        It 'has EnforcementMode as [string]' {
            $script:contractResult.EnforcementMode | Should -BeOfType [string]
            $script:contractResult.EnforcementMode | Should -Be 'Enforced'
        }

        It 'has FormatVersion as [uint32]' {
            $script:contractResult.FormatVersion | Should -BeOfType [uint32]
            $script:contractResult.FormatVersion | Should -Be 8
        }

        It 'has PolicyType as [string]' {
            $script:contractResult.PolicyType | Should -BeOfType [string]
            $script:contractResult.PolicyType | Should -Be 'Base Policy'
        }

        It 'has RuleOptions as array' {
            $script:contractResult.RuleOptions | Should -HaveCount 1
            $script:contractResult.RuleOptions[0].Id | Should -Be 0
            $script:contractResult.RuleOptions[0].Name | Should -Be 'Enabled:UMCI'
        }

        It 'has FilePath as [string]' {
            $script:contractResult.FilePath | Should -BeOfType [string]
            $script:contractResult.FilePath | Should -BeLike '*22222222-2222-2222-2222-222222222222*'
        }

        It 'has Location as [string]' {
            $script:contractResult.Location | Should -BeOfType [string]
            $script:contractResult.Location | Should -Be 'MultiPolicy'
        }

        It 'has FileSize as [long]' {
            $script:contractResult.FileSize | Should -BeOfType [long]
            $script:contractResult.FileSize | Should -Be 200
        }

        It 'has LastModified as [datetime]' {
            $script:contractResult.LastModified | Should -BeOfType [datetime]
        }
    }
}
