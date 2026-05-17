function Get-WDACDefenderStatus {
    <#
    .SYNOPSIS
        Queries Windows Defender / antimalware status via WMI.

    .DESCRIPTION
        Retrieves comprehensive Windows Defender status information by querying the MSFT_MpComputerStatus
        WMI class in the root\Microsoft\Windows\Defender namespace. Returns detailed information about
        antimalware service state, protection features, signature versions, and scan status.

        If Windows Defender is not present (e.g., third-party antimalware is installed), the function
        returns a status object with DefenderPresent=false and sensible defaults for all other properties.

    .OUTPUTS
        PSCustomObject with properties:
            - DefenderPresent                   [bool]
            - AMRunningMode                     [string]
            - AMServiceEnabled                  [bool]
            - AntivirusEnabled                  [bool]
            - AntispywareEnabled                [bool]
            - RealTimeProtectionEnabled         [bool]
            - BehaviorMonitorEnabled            [bool]
            - IoavProtectionEnabled             [bool]
            - NISEnabled                        [bool]
            - OnAccessProtectionEnabled         [bool]
            - TamperProtectionSource            [string]
            - AntivirusSignatureVersion         [string]
            - AntivirusSignatureLastUpdated     [datetime]
            - AntispywareSignatureLastUpdated   [datetime]
            - QuickScanAge                      [uint32]
            - FullScanAge                       [uint32]
            - ComputerState                     [uint32]
            - DefenderProductStatus             [uint32]

    .EXAMPLE
        Get-WDACDefenderStatus
        Returns the current Windows Defender status.

    .EXAMPLE
        $status = Get-WDACDefenderStatus
        if ($status.DefenderPresent -and -not $status.RealTimeProtectionEnabled) {
            Write-Warning "Real-time protection is disabled"
        }

    .EXAMPLE
        (Get-WDACDefenderStatus).AntivirusSignatureLastUpdated
        Returns the last time antivirus signatures were updated.

    .NOTES
        Requires: Administrator elevation
        Platform: Windows only
    #>
    [CmdletBinding()]
    param()

    if (-not ([System.Management.Automation.PSTypeName]'WDACDefenderStatusReader').Type) {
        Add-Type -TypeDefinition @'
using System;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;

public static class WDACDefenderStatusReader
{
    public static void EnsureElevated()
    {
        using (var identity = WindowsIdentity.GetCurrent())
        {
            var principal = new WindowsPrincipal(identity);
            if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
                throw new UnauthorizedAccessException(
                    "This operation requires Administrator elevation. Run PowerShell as Administrator.");
        }
    }

    public static object[] Query()
    {
        EnsureElevated();

        bool defenderPresent = true;
        string amRunningMode = string.Empty;
        bool amServiceEnabled = false;
        bool antivirusEnabled = false;
        bool antispywareEnabled = false;
        bool realTimeProtectionEnabled = false;
        bool behaviorMonitorEnabled = false;
        bool ioavProtectionEnabled = false;
        bool nisEnabled = false;
        bool onAccessProtectionEnabled = false;
        string tamperProtectionSource = string.Empty;
        string antivirusSignatureVersion = string.Empty;
        DateTime antivirusSignatureLastUpdated = DateTime.MinValue;
        DateTime antispywareSignatureLastUpdated = DateTime.MinValue;
        uint quickScanAge = 0;
        uint fullScanAge = 0;
        uint computerState = 0;
        uint defenderProductStatus = 0;

        try
        {
            using (var searcher = new ManagementObjectSearcher(
                "root\\Microsoft\\Windows\\Defender",
                "SELECT * FROM MSFT_MpComputerStatus"))
            {
                foreach (ManagementObject obj in searcher.Get())
                {
                    // AMRunningMode
                    var amMode = obj["AMRunningMode"];
                    if (amMode != null)
                        amRunningMode = amMode.ToString();

                    // AMServiceEnabled
                    var amSvc = obj["AMServiceEnabled"];
                    if (amSvc != null)
                        amServiceEnabled = Convert.ToBoolean(amSvc);

                    // AntivirusEnabled
                    var av = obj["AntivirusEnabled"];
                    if (av != null)
                        antivirusEnabled = Convert.ToBoolean(av);

                    // AntispywareEnabled
                    var as_ = obj["AntispywareEnabled"];
                    if (as_ != null)
                        antispywareEnabled = Convert.ToBoolean(as_);

                    // RealTimeProtectionEnabled
                    var rtp = obj["RealTimeProtectionEnabled"];
                    if (rtp != null)
                        realTimeProtectionEnabled = Convert.ToBoolean(rtp);

                    // BehaviorMonitorEnabled
                    var bm = obj["BehaviorMonitorEnabled"];
                    if (bm != null)
                        behaviorMonitorEnabled = Convert.ToBoolean(bm);

                    // IoavProtectionEnabled
                    var ioav = obj["IoavProtectionEnabled"];
                    if (ioav != null)
                        ioavProtectionEnabled = Convert.ToBoolean(ioav);

                    // NISEnabled
                    var nis = obj["NISEnabled"];
                    if (nis != null)
                        nisEnabled = Convert.ToBoolean(nis);

                    // OnAccessProtectionEnabled
                    var oap = obj["OnAccessProtectionEnabled"];
                    if (oap != null)
                        onAccessProtectionEnabled = Convert.ToBoolean(oap);

                    // TamperProtectionSource
                    var tps = obj["TamperProtectionSource"];
                    if (tps != null)
                        tamperProtectionSource = tps.ToString();

                    // AntivirusSignatureVersion
                    var avVer = obj["AntivirusSignatureVersion"];
                    if (avVer != null)
                        antivirusSignatureVersion = avVer.ToString();

                    // AntivirusSignatureLastUpdated
                    var avLastUpd = obj["AntivirusSignatureLastUpdated"];
                    if (avLastUpd != null)
                    {
                        try
                        {
                            antivirusSignatureLastUpdated = ManagementDateTimeConverter.ToDateTime(avLastUpd.ToString());
                        }
                        catch
                        {
                            antivirusSignatureLastUpdated = DateTime.MinValue;
                        }
                    }

                    // AntispywareSignatureLastUpdated
                    var asLastUpd = obj["AntispywareSignatureLastUpdated"];
                    if (asLastUpd != null)
                    {
                        try
                        {
                            antispywareSignatureLastUpdated = ManagementDateTimeConverter.ToDateTime(asLastUpd.ToString());
                        }
                        catch
                        {
                            antispywareSignatureLastUpdated = DateTime.MinValue;
                        }
                    }

                    // QuickScanAge
                    var qsa = obj["QuickScanAge"];
                    if (qsa != null)
                        quickScanAge = Convert.ToUInt32(qsa);

                    // FullScanAge
                    var fsa = obj["FullScanAge"];
                    if (fsa != null)
                        fullScanAge = Convert.ToUInt32(fsa);

                    // ComputerState
                    var cs = obj["ComputerState"];
                    if (cs != null)
                        computerState = Convert.ToUInt32(cs);

                    // ProductStatus (may vary by Windows version)
                    var ps = obj["ProductStatus"];
                    if (ps != null)
                        defenderProductStatus = Convert.ToUInt32(ps);

                    break; // Only one instance expected
                }
            }
        }
        catch (ManagementException)
        {
            // WMI namespace doesn't exist — likely third-party AV
            defenderPresent = false;
        }
        catch (UnauthorizedAccessException)
        {
            throw;
        }
        catch (Exception)
        {
            // Other failures — treat as Defender not present
            defenderPresent = false;
        }

        // Return as object array
        return new object[] {
            defenderPresent,
            amRunningMode,
            amServiceEnabled,
            antivirusEnabled,
            antispywareEnabled,
            realTimeProtectionEnabled,
            behaviorMonitorEnabled,
            ioavProtectionEnabled,
            nisEnabled,
            onAccessProtectionEnabled,
            tamperProtectionSource,
            antivirusSignatureVersion,
            antivirusSignatureLastUpdated,
            antispywareSignatureLastUpdated,
            quickScanAge,
            fullScanAge,
            computerState,
            defenderProductStatus
        };
    }
}
'@ -ReferencedAssemblies $CIRefWmi
    }

    Write-Verbose 'Querying Windows Defender status...'

    $result = [WDACDefenderStatusReader]::Query()

    [PSCustomObject]@{
        DefenderPresent                 = [bool]$result[0]
        AMRunningMode                   = [string]$result[1]
        AMServiceEnabled                = [bool]$result[2]
        AntivirusEnabled                = [bool]$result[3]
        AntispywareEnabled              = [bool]$result[4]
        RealTimeProtectionEnabled       = [bool]$result[5]
        BehaviorMonitorEnabled          = [bool]$result[6]
        IoavProtectionEnabled           = [bool]$result[7]
        NISEnabled                      = [bool]$result[8]
        OnAccessProtectionEnabled       = [bool]$result[9]
        TamperProtectionSource          = [string]$result[10]
        AntivirusSignatureVersion       = [string]$result[11]
        AntivirusSignatureLastUpdated   = [datetime]$result[12]
        AntispywareSignatureLastUpdated = [datetime]$result[13]
        QuickScanAge                    = [uint32]$result[14]
        FullScanAge                     = [uint32]$result[15]
        ComputerState                   = [uint32]$result[16]
        DefenderProductStatus           = [uint32]$result[17]
    }
}
