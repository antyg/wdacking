# antyg-wdacking.psm1
# Windows Defender Application Control (WDAC) / Code Integrity Policy Management Module

# Assembly reference profiles for Add-Type cross-edition compatibility
# PS 5.1 (Desktop / .NET Framework): most assemblies implicitly available
# pwsh 7+ (Core / .NET): requires explicit assembly references
$CIRefBase   = @('System.Security')
$CIRefWmi    = @('System.Management')
$CIRefWmiReg = @('System.Management')
$CIRefEvt    = @('System.Core')
if ($PSVersionTable.PSEdition -eq 'Core') {
    # Core common: WindowsIdentity requires System.Security.Claims (ClaimsIdentity base class)
    #              List<T> and generic collections require System.Collections
    #              System.Security.Cryptography.Pkcs: SignedCms for PKCS#7 unwrapping
    $CIRefBase   = @('System.Security.Principal.Windows', 'System.Security.Claims', 'System.Collections', 'System.Text.RegularExpressions', 'System.Security.Cryptography.Pkcs')
    $CIRefWmi    = @('System.Security.Principal.Windows', 'System.Security.Claims', 'System.Collections', 'System.Text.RegularExpressions', 'System.Management', 'System.ComponentModel.Primitives')
    $CIRefWmiReg = @('System.Security.Principal.Windows', 'System.Security.Claims', 'System.Collections', 'System.Text.RegularExpressions', 'System.Management', 'System.ComponentModel.Primitives', 'Microsoft.Win32.Registry')
    $CIRefEvt    = @('System.Security.Principal.Windows', 'System.Security.Claims', 'System.Collections', 'System.Diagnostics.EventLog', 'System.Text.RegularExpressions')
}

# Dot-source private helpers first (internal, not exported)
$privatePath = Join-Path $PSScriptRoot 'private'
if (Test-Path $privatePath) {
    Get-ChildItem -Path $privatePath -Filter '*.ps1' -Recurse | ForEach-Object { . $_.FullName }
}

# Dot-source public functions (exported via FunctionsToExport in .psd1)
$publicPath = Join-Path $PSScriptRoot 'public'
if (Test-Path $publicPath) {
    Get-ChildItem -Path $publicPath -Filter '*.ps1' -Recurse | ForEach-Object { . $_.FullName }
}
