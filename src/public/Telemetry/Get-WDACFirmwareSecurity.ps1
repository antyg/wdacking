function Get-WDACFirmwareSecurity {
    <#
    .SYNOPSIS
        Queries firmware and boot security state using WMI, Registry, and NT API.

    .DESCRIPTION
        Retrieves comprehensive firmware security information by combining data from:
        - WMI Win32_BIOS (BIOS vendor, version, release date, SMBIOS version, serial number)
        - Registry HKLM\HARDWARE\DESCRIPTION\System\BIOS (system manufacturer, product name)
        - NT API GetFirmwareType (firmware type: BIOS vs UEFI)
        - WMI Win32_DeviceGuard (Secure Launch/DRTM support)

        Uses C# interop for WMI queries, registry access, and native API calls with elevation
        validation. Returns a consolidated security state object suitable for audit and compliance
        reporting.

    .OUTPUTS
        PSCustomObject with properties:
            - BIOSVendor            [string]  BIOS vendor name
            - BIOSVersion           [string]  BIOS version string
            - BIOSReleaseDate       [string]  BIOS release date
            - SMBIOSVersion         [string]  SMBIOS version (formatted as "Major.Minor")
            - SystemManufacturer    [string]  System manufacturer name
            - SystemProductName     [string]  System product/model name
            - FirmwareType          [string]  "UEFI", "BIOS", or "Unknown"
            - UEFIMode              [bool]    True if running in UEFI mode
            - SecureLaunchSupported [bool]    True if Secure Launch (DRTM) is supported
            - SerialNumber          [string]  BIOS serial number
            - QuerySuccess          [bool]    Whether all queries completed successfully

    .EXAMPLE
        Get-WDACFirmwareSecurity
        Retrieves firmware security information for the current system.

    .EXAMPLE
        $firmwareInfo = Get-WDACFirmwareSecurity
        if ($firmwareInfo.UEFIMode -and $firmwareInfo.SecureLaunchSupported) {
            Write-Host "System supports modern secure boot features."
        }

    .NOTES
        Requires: Administrator elevation
        Platform: Windows only
    #>
    [CmdletBinding()]
    param()

    if (-not ([System.Management.Automation.PSTypeName]'WDACFirmwareSecurityReader').Type) {
        Add-Type -TypeDefinition @'
using System;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32;

public static class WDACFirmwareSecurityReader
{
    // Firmware type enumeration
    private enum FirmwareType : uint
    {
        Unknown = 0,
        Bios = 1,
        Uefi = 2,
        Max = 3
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFirmwareType(ref FirmwareType firmwareType);

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

    /// <summary>
    /// Queries firmware and boot security state.
    /// Returns object[] with 11 elements corresponding to the output properties.
    /// </summary>
    public static object[] QueryFirmwareSecurity()
    {
        EnsureElevated();

        string biosVendor = string.Empty;
        string biosVersion = string.Empty;
        string biosReleaseDate = string.Empty;
        string smbiosVersion = string.Empty;
        string systemManufacturer = string.Empty;
        string systemProductName = string.Empty;
        string firmwareTypeString = "Unknown";
        bool uefiMode = false;
        bool secureLaunchSupported = false;
        string serialNumber = string.Empty;
        bool querySuccess = true;

        try
        {
            // Query 1: WMI Win32_BIOS
            try
            {
                using (var searcher = new ManagementObjectSearcher(@"root\CIMV2", "SELECT * FROM Win32_BIOS"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        biosVendor = GetPropertyValue(obj, "Manufacturer");
                        biosVersion = GetPropertyValue(obj, "SMBIOSBIOSVersion");
                        biosReleaseDate = GetPropertyValue(obj, "ReleaseDate");
                        serialNumber = GetPropertyValue(obj, "SerialNumber");

                        var majorVersion = GetPropertyValue(obj, "SMBIOSMajorVersion");
                        var minorVersion = GetPropertyValue(obj, "SMBIOSMinorVersion");

                        if (!string.IsNullOrEmpty(majorVersion) && !string.IsNullOrEmpty(minorVersion))
                        {
                            smbiosVersion = string.Format("{0}.{1}", majorVersion, minorVersion);
                        }

                        break; // Only need the first result
                    }
                }
            }
            catch (Exception ex)
            {
                // Log error but continue
                querySuccess = false;
                biosVendor += " [WMI Error: " + ex.Message + "]";
            }

            // Query 2: Registry HKLM\HARDWARE\DESCRIPTION\System\BIOS
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\BIOS"))
                {
                    if (key != null)
                    {
                        // Fallback to registry if WMI didn't provide values
                        if (string.IsNullOrEmpty(biosVendor))
                            biosVendor = GetRegistryValue(key, "BIOSVendor");
                        if (string.IsNullOrEmpty(biosVersion))
                            biosVersion = GetRegistryValue(key, "BIOSVersion");
                        if (string.IsNullOrEmpty(biosReleaseDate))
                            biosReleaseDate = GetRegistryValue(key, "BIOSReleaseDate");

                        systemManufacturer = GetRegistryValue(key, "SystemManufacturer");
                        systemProductName = GetRegistryValue(key, "SystemProductName");
                    }
                }
            }
            catch (Exception ex)
            {
                // Log error but continue
                querySuccess = false;
                systemManufacturer += " [Registry Error: " + ex.Message + "]";
            }

            // Query 3: NT API GetFirmwareType
            try
            {
                FirmwareType fwType = FirmwareType.Unknown;
                if (GetFirmwareType(ref fwType))
                {
                    switch (fwType)
                    {
                        case FirmwareType.Bios:
                            firmwareTypeString = "BIOS";
                            uefiMode = false;
                            break;
                        case FirmwareType.Uefi:
                            firmwareTypeString = "UEFI";
                            uefiMode = true;
                            break;
                        default:
                            firmwareTypeString = "Unknown";
                            uefiMode = false;
                            break;
                    }
                }
            }
            catch (Exception ex)
            {
                // Log error but continue
                querySuccess = false;
                firmwareTypeString = "Unknown [API Error: " + ex.Message + "]";
            }

            // Query 4: WMI Win32_DeviceGuard for Secure Launch (DRTM) support
            try
            {
                using (var searcher = new ManagementObjectSearcher(@"root\Microsoft\Windows\DeviceGuard",
                    "SELECT * FROM Win32_DeviceGuard"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        var availableSecurityProperties = obj["AvailableSecurityProperties"] as uint[];
                        if (availableSecurityProperties != null)
                        {
                            // Value 6 indicates Secure Launch (DRTM) support
                            foreach (var prop in availableSecurityProperties)
                            {
                                if (prop == 6)
                                {
                                    secureLaunchSupported = true;
                                    break;
                                }
                            }
                        }
                        break; // Only need the first result
                    }
                }
            }
            catch (Exception)
            {
                // DeviceGuard WMI namespace may not exist on older systems - not a critical error
                // Just leave secureLaunchSupported as false
            }
        }
        catch (Exception ex)
        {
            querySuccess = false;
            throw new InvalidOperationException(
                "Failed to query firmware security information: " + ex.Message, ex);
        }

        return new object[]
        {
            biosVendor,
            biosVersion,
            biosReleaseDate,
            smbiosVersion,
            systemManufacturer,
            systemProductName,
            firmwareTypeString,
            uefiMode,
            secureLaunchSupported,
            serialNumber,
            querySuccess
        };
    }

    private static string GetPropertyValue(ManagementObject obj, string propertyName)
    {
        try
        {
            var value = obj[propertyName];
            return value != null ? value.ToString() : string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    private static string GetRegistryValue(RegistryKey key, string valueName)
    {
        try
        {
            var value = key.GetValue(valueName);
            return value != null ? value.ToString() : string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }
}
'@ -ReferencedAssemblies $CIRefWmiReg
    }

    Write-Verbose "Querying firmware and boot security state..."

    $result = [WDACFirmwareSecurityReader]::QueryFirmwareSecurity()

    [PSCustomObject]@{
        BIOSVendor            = [string]$result[0]
        BIOSVersion           = [string]$result[1]
        BIOSReleaseDate       = [string]$result[2]
        SMBIOSVersion         = [string]$result[3]
        SystemManufacturer    = [string]$result[4]
        SystemProductName     = [string]$result[5]
        FirmwareType          = [string]$result[6]
        UEFIMode              = [bool]$result[7]
        SecureLaunchSupported = [bool]$result[8]
        SerialNumber          = [string]$result[9]
        QuerySuccess          = [bool]$result[10]
    }

    if ($result[10]) {
        Write-Verbose "Firmware security query completed successfully."
    }
    else {
        Write-Warning "Firmware security query completed with errors. Check property values for details."
    }
}
