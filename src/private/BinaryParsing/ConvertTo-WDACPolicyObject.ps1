function ConvertTo-WDACPolicyObject {
    <#
    .SYNOPSIS
        Converts a SiPolicy XmlDocument to the Get-WDACPolicy output contract.

    .DESCRIPTION
        Adapter function that transforms the XmlDocument returned by ConvertFrom-WDACBinary
        into the 13-property PSCustomObject expected by Get-WDACPolicy consumers.

        Extracts PolicyId, BasePolicyId, FriendlyName (from Settings), Version, enforcement
        mode, rule options with reverse-mapped IDs, and PolicyType classification.

    .PARAMETER Xml
        SiPolicy XmlDocument from ConvertFrom-WDACBinary.

    .PARAMETER FormatVersion
        Binary format version (from first 4 bytes of raw binary data).

    .PARAMETER FilePath
        Full path to the source .cip or .p7b file.

    .PARAMETER Location
        Deployment location: 'MultiPolicy', 'Legacy', or 'EFI'.

    .OUTPUTS
        PSCustomObject matching Get-WDACPolicy output contract.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [System.Xml.XmlDocument]$Xml,

        [Parameter(Mandatory)]
        [uint32]$FormatVersion,

        [Parameter(Mandatory)]
        [string]$FilePath,

        [Parameter(Mandatory)]
        [ValidateSet('MultiPolicy', 'Legacy', 'EFI')]
        [string]$Location
    )

    # -----------------------------------------------------------------------
    # Lookup tables
    # -----------------------------------------------------------------------

    # PolicyType classification: known PolicyTypeID GUIDs → human-readable names
    # Source: WDACPolicyReader.ClassifyPolicyType() in original C# implementation
    $knownPolicyTypes = @{
        'a244370e-44c9-4c06-b551-f6016e563076' = 'Enterprise'
        '2a5a0136-f09f-498e-99cc-51099011157c' = 'Revoke'
        '976d12c8-cb9f-4730-be52-54600843238e' = 'SKU'
        '5951a96a-e0b5-4d3d-8fb8-3e5b61030784' = 'WindowsLockdown'
        '4e61c68c-97f6-430b-9cd7-9b1004706770' = 'ATP'
        'd2bda982-ccf6-4344-ac5b-0b44427b6816' = 'Driver'
    }

    # Rule Option name → XML Rule Option ID (0-20)
    # Source: WDACPolicyReader.GetRuleOptionName() dictionary in original C# implementation
    $optionNameToId = @{
        'Enabled:UMCI'                                     = [uint32]0
        'Enabled:Boot Menu Protection'                     = [uint32]1
        'Required:WHQL'                                    = [uint32]2
        'Enabled:Audit Mode'                               = [uint32]3
        'Disabled:Flight Signing'                          = [uint32]4
        'Enabled:Inherit Default Policy'                   = [uint32]5
        'Enabled:Unsigned System Integrity Policy'         = [uint32]6
        'Enabled:Dynamic Code Security'                    = [uint32]7
        'Required:EV Signers'                              = [uint32]8
        'Enabled:Boot Audit On Failure'                    = [uint32]9
        'Enabled:Advanced Boot Options Menu'               = [uint32]10
        'Disabled:Script Enforcement'                      = [uint32]11
        'Required:Enforce Store Applications'              = [uint32]12
        'Enabled:Managed Installer'                        = [uint32]13
        'Enabled:Update Policy No Reboot'                  = [uint32]14
        'Enabled:Allow Supplemental Policies'              = [uint32]15
        'Disabled:Runtime FilePath Rule Protection'        = [uint32]16
        'Enabled:Revoked Expired As Unsigned'              = [uint32]17
        'Enabled:Intelligent Security Graph Authorization' = [uint32]18
        'Enabled:Invalidate EAs on Reboot'                 = [uint32]19
        'Enabled:Developer Mode Dynamic Code Trust'        = [uint32]20
    }

    # -----------------------------------------------------------------------
    # XML namespace manager
    # -----------------------------------------------------------------------
    $nsm = [System.Xml.XmlNamespaceManager]::new($Xml.NameTable)
    $nsm.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')

    # -----------------------------------------------------------------------
    # Extract PolicyId and BasePolicyId
    # -----------------------------------------------------------------------
    $policyIdNode = $Xml.SelectSingleNode('//ns:PolicyID', $nsm)
    $basePolicyIdNode = $Xml.SelectSingleNode('//ns:BasePolicyID', $nsm)
    $policyTypeIdNode = $Xml.SelectSingleNode('//ns:PolicyTypeID', $nsm)

    $policyId = ''
    $basePolicyId = ''

    if ($null -ne $policyIdNode -and -not [string]::IsNullOrWhiteSpace($policyIdNode.InnerText)) {
        # V6+ multi-policy format
        $policyId = $policyIdNode.InnerText.Trim('{}').ToLowerInvariant()
        if ($null -ne $basePolicyIdNode -and -not [string]::IsNullOrWhiteSpace($basePolicyIdNode.InnerText)) {
            $basePolicyId = $basePolicyIdNode.InnerText.Trim('{}').ToLowerInvariant()
        }
    }
    elseif ($null -ne $policyTypeIdNode -and -not [string]::IsNullOrWhiteSpace($policyTypeIdNode.InnerText)) {
        # Legacy format — PolicyTypeID serves as both
        $typeGuid = $policyTypeIdNode.InnerText.Trim('{}').ToLowerInvariant()
        $policyId = $typeGuid
        $basePolicyId = $typeGuid
    }

    # Fallback: extract GUID from filename (e.g., {GUID}.cip)
    # This indicates a degraded parse — the binary did not produce identity elements.
    if ([string]::IsNullOrWhiteSpace($policyId)) {
        $fileName = [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
        $parseResult = [guid]::Empty
        if ([guid]::TryParse($fileName.Trim('{', '}'), [ref]$parseResult)) {
            $policyId = $parseResult.ToString()
        }
        else {
            $policyId = $fileName
        }
        Write-Warning "PolicyId for '$FilePath' derived from filename — binary did not contain PolicyID or PolicyTypeID elements."
    }

    # -----------------------------------------------------------------------
    # PolicyType classification
    # -----------------------------------------------------------------------
    $policyType = 'Unknown'
    $policyTypeAttr = $Xml.DocumentElement.GetAttribute('PolicyType')

    if ($null -ne $policyTypeIdNode -and -not [string]::IsNullOrWhiteSpace($policyTypeIdNode.InnerText)) {
        # Legacy format: classify from known GUID table
        $typeGuid = $policyTypeIdNode.InnerText.Trim('{}').ToLowerInvariant()
        if ($knownPolicyTypes.ContainsKey($typeGuid)) {
            $policyType = $knownPolicyTypes[$typeGuid]
        }
        else {
            $policyType = "{$typeGuid}"
        }
    }
    elseif (-not [string]::IsNullOrWhiteSpace($policyTypeAttr)) {
        # V6+ format: use PolicyType attribute directly
        $policyType = $policyTypeAttr
    }

    # -----------------------------------------------------------------------
    # Version
    # -----------------------------------------------------------------------
    $versionNode = $Xml.SelectSingleNode('//ns:VersionEx', $nsm)
    $version = if ($null -ne $versionNode -and -not [string]::IsNullOrWhiteSpace($versionNode.InnerText)) {
        $versionNode.InnerText
    }
    else {
        Write-Warning "Version for '$FilePath' could not be extracted — VersionEx element missing from parsed XML."
        'Unknown'
    }

    # -----------------------------------------------------------------------
    # FriendlyName from Settings (NEW — was always empty in C# parser)
    # -----------------------------------------------------------------------
    $friendlyName = ''
    $nameSettingNode = $Xml.SelectSingleNode(
        '//ns:Settings/ns:Setting[@Provider="PolicyInfo" and @Key="Information" and @ValueName="Name"]/ns:Value/ns:String',
        $nsm
    )
    if ($null -ne $nameSettingNode -and -not [string]::IsNullOrWhiteSpace($nameSettingNode.InnerText)) {
        $friendlyName = $nameSettingNode.InnerText
    }

    # -----------------------------------------------------------------------
    # IsSupplemental
    # -----------------------------------------------------------------------
    $isSupplemental = $false
    if (-not [string]::IsNullOrWhiteSpace($policyId) -and -not [string]::IsNullOrWhiteSpace($basePolicyId)) {
        $isSupplemental = $policyId -ne $basePolicyId
    }

    # -----------------------------------------------------------------------
    # EnforcementMode from Rule Options
    # -----------------------------------------------------------------------
    $rulesNode = $Xml.SelectSingleNode('//ns:Rules', $nsm)
    $optionNodes = $Xml.SelectNodes('//ns:Rules/ns:Rule/ns:Option', $nsm)
    $optionNames = @($optionNodes | ForEach-Object { $_.InnerText })

    $enforcementMode = if ($null -eq $rulesNode) {
        Write-Warning "EnforcementMode for '$FilePath' is unknown — Rules element missing from parsed XML."
        'Unknown'
    }
    elseif ($optionNames -contains 'Enabled:Audit Mode') {
        'Audit'
    }
    else {
        'Enforced'
    }

    # -----------------------------------------------------------------------
    # RuleOptions: reverse-map names → Id + Name PSCustomObjects
    # -----------------------------------------------------------------------
    $ruleOptions = @($optionNames | ForEach-Object {
        $name = $_
        $id = if ($optionNameToId.ContainsKey($name)) { $optionNameToId[$name] } else { [uint32]999 }
        [PSCustomObject]@{
            Id   = $id
            Name = $name
        }
    })

    # -----------------------------------------------------------------------
    # File metadata
    # -----------------------------------------------------------------------
    $fileInfo = [System.IO.FileInfo]::new($FilePath)

    # -----------------------------------------------------------------------
    # Build output object (13 properties — matches Get-WDACPolicy contract)
    # -----------------------------------------------------------------------
    [PSCustomObject]@{
        PolicyId        = [string]$policyId
        BasePolicyId    = [string]$basePolicyId
        FriendlyName    = [string]$friendlyName
        Version         = [string]$version
        IsSupplemental  = [bool]$isSupplemental
        EnforcementMode = [string]$enforcementMode
        FormatVersion   = [uint32]$FormatVersion
        PolicyType      = [string]$policyType
        RuleOptions     = $ruleOptions
        FilePath        = [string]$fileInfo.FullName
        Location        = [string]$Location
        FileSize        = [long]$fileInfo.Length
        LastModified    = [datetime]$fileInfo.LastWriteTime
    }
}
