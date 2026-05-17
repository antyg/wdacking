@{
    # Module metadata
    RootModule        = 'antyg-wdacking.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b3f7a2c1-9d4e-4f8b-a6c5-1e2d3f4a5b6c'
    Author            = 'antyg'
    CompanyName       = 'antyg'
    Description       = 'Windows Defender Application Control (WDAC) and Code Integrity policy management. Provides functions for policy lifecycle (query, deploy, remove, refresh, enforcement test), CI trust token management, event log analysis, and comprehensive device security telemetry (speculation mitigations, firmware, Defender status, exploit protection, hypervisor details, memory encryption).'
    Copyright         = '(c) 2026 antyg. All rights reserved.'

    # Requirements
    PowerShellVersion = '5.1'
    CLRVersion        = '4.0'

    # Exported members
    FunctionsToExport = '*'
    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @()

    # Private data
    PrivateData = @{
        PSData = @{
            Tags       = @('WDAC', 'CodeIntegrity', 'DeviceGuard', 'Security', 'Windows')
            ProjectUri = 'https://github.com/antyg/wdacking'
            LicenseUri = 'https://github.com/antyg/wdacking/blob/main/LICENSE'
        }
    }
}
