function Get-WDACHypervisorDetail {
    <#
    .SYNOPSIS
        Retrieves detailed hypervisor and virtualization-based security information.

    .DESCRIPTION
        Queries hypervisor presence, vendor identification, and virtualization configuration
        to provide a comprehensive view of the system's hypervisor state and VBS capabilities.

        Primary vendor detection executes CPUID leaf 0x40000000 directly via dynamically
        emitted x64 machine code (VirtualAlloc + delegate invocation), which returns the
        12-byte hypervisor vendor signature from EBX+ECX+EDX. This works on both Hyper-V
        root partitions and guest VMs, unlike NtQuerySystemInformation(0xC5) which fails
        on the root partition with STATUS_NOT_IMPLEMENTED.

        Falls back through NtQuerySystemInformation(0xC5), then registry/WMI heuristics
        if CPUID execution is unavailable.

        Returns detailed information about:
        - Hypervisor presence and vendor identification (via CPUID 0x40000000 signature)
        - Virtualization-Based Security (VBS) status
        - HVCI (Hypervisor-protected Code Integrity) state
        - Nested virtualization support
        - System hardware model and manufacturer

    .OUTPUTS
        PSCustomObject with properties:
            - HypervisorPresent            [bool]     Hypervisor is detected
            - HypervisorVendor             [string]   Vendor name (e.g., 'Microsoft Hyper-V', 'VMware', 'KVM', 'Xen')
            - HypervisorInterfaceId        [string]   Raw vendor signature in hex format
            - VBSStatus                    [string]   'Running', 'NotRunning', 'NotConfigured'
            - HVCIEnabled                  [bool]     HVCI is active
            - NestedVirtualizationEnabled  [bool]     Nested virtualization is enabled
            - SystemModel                  [string]   System hardware model
            - SystemManufacturer           [string]   System manufacturer
            - NtApiQuerySuccess            [bool]     Direct vendor query succeeded (CPUID or NT API)
            - QuerySuccess                 [bool]     Overall query completed successfully

    .EXAMPLE
        Get-WDACHypervisorDetail
        Returns the full hypervisor and VBS assessment.

    .EXAMPLE
        (Get-WDACHypervisorDetail).HypervisorVendor
        Quick check of detected hypervisor vendor.

    .EXAMPLE
        Get-WDACHypervisorDetail | Format-List
        Displays all hypervisor properties in list format.

    .NOTES
        Requires: Administrator elevation
        Platform: Windows 10+ / Windows 11 (x64 only for CPUID execution)

        Detection Architecture:
        - CPUID leaf 0x40000000 executed via VirtualAlloc + native code delegation (primary)
        - NtQuerySystemInformation(0xC5) as secondary (fails on Hyper-V root partition)
        - Registry/WMI heuristics as last resort
    #>
    [CmdletBinding()]
    param()

    if (-not ([System.Management.Automation.PSTypeName]'WDACHypervisorDetailReader').Type) {
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;

public static class WDACHypervisorDetailReader
{
    // ── VirtualAlloc constants ──────────────────────────────────────
    private const uint MEM_COMMIT  = 0x1000;
    private const uint MEM_RESERVE = 0x2000;
    private const uint MEM_RELEASE = 0x8000;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAlloc(
        IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool VirtualFree(IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);

    // ── CPUID delegate ──────────────────────────────────────────────
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate void CpuidDelegate(uint leaf, uint subleaf, IntPtr output);

    // x86-64 machine code: CPUID wrapper (24 bytes)
    // Microsoft x64 ABI: RCX=leaf, RDX=subleaf, R8=output_ptr
    private static readonly byte[] CpuidCode64 = new byte[]
    {
        0x53,                         // push rbx
        0x89, 0xC8,                   // mov eax, ecx
        0x89, 0xD1,                   // mov ecx, edx
        0x0F, 0xA2,                   // cpuid
        0x41, 0x89, 0x00,             // mov [r8], eax
        0x41, 0x89, 0x58, 0x04,       // mov [r8+4], ebx
        0x41, 0x89, 0x48, 0x08,       // mov [r8+8], ecx
        0x41, 0x89, 0x50, 0x0C,       // mov [r8+12], edx
        0x5B,                         // pop rbx
        0xC3                          // ret
    };

    /// <summary>
    /// Executes the CPUID instruction with the given leaf and subleaf.
    /// Returns uint[4] = { EAX, EBX, ECX, EDX }.
    /// </summary>
    private static uint[] ExecuteCpuid(uint leaf, uint subleaf)
    {
        if (IntPtr.Size != 8)
            throw new PlatformNotSupportedException(
                "CPUID native execution requires x64 platform");

        IntPtr codePtr = VirtualAlloc(
            IntPtr.Zero, (UIntPtr)CpuidCode64.Length,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        if (codePtr == IntPtr.Zero)
            throw new InvalidOperationException(
                "VirtualAlloc failed for CPUID code page");

        try
        {
            Marshal.Copy(CpuidCode64, 0, codePtr, CpuidCode64.Length);

            var cpuid = (CpuidDelegate)Marshal.GetDelegateForFunctionPointer(
                codePtr, typeof(CpuidDelegate));

            uint[] result = new uint[4];
            GCHandle handle = GCHandle.Alloc(result, GCHandleType.Pinned);
            try
            {
                cpuid(leaf, subleaf, handle.AddrOfPinnedObject());
            }
            finally
            {
                handle.Free();
            }

            return result;
        }
        finally
        {
            VirtualFree(codePtr, UIntPtr.Zero, MEM_RELEASE);
        }
    }

    // ── NtQuerySystemInformation ────────────────────────────────────
    private const uint SystemHypervisorDetailInformation = 0xC5;  // 197

    private const uint STATUS_SUCCESS = 0x00000000;
    private const uint STATUS_NOT_IMPLEMENTED = 0xC0000002;

    [DllImport("ntdll.dll")]
    private static extern uint NtQuerySystemInformation(
        uint SystemInformationClass,
        IntPtr SystemInformation,
        uint SystemInformationLength,
        out uint ReturnLength);

    // ── VBS / HVCI constants ────────────────────────────────────────
    private const int VBSNotConfigured = 0;
    private const int VBSNotRunning = 1;
    private const int VBSRunning = 2;
    private const int SecurityServiceHVCI = 2;

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
    /// Maps raw vendor signature bytes to friendly vendor name.
    /// Vendor signature is 12 bytes from CPUID 0x40000000 (EBX, ECX, EDX).
    /// </summary>
    private static string ParseVendorSignature(byte[] signature)
    {
        if (signature == null || signature.Length < 12)
            return "Unknown";

        try
        {
            string vendor = Encoding.ASCII.GetString(signature, 0, 12).Trim('\0', ' ');

            // Known hypervisor vendor signatures
            if (vendor.StartsWith("Microsoft Hv")) return "Microsoft Hyper-V";
            if (vendor.StartsWith("VMwareVMware")) return "VMware";
            if (vendor.StartsWith("KVMKVMKVM")) return "KVM";
            if (vendor.StartsWith("XenVMMXenVMM")) return "Xen";
            if (vendor.StartsWith("TCGTCGTCGTCG")) return "QEMU";
            if (vendor.StartsWith("bhyve bhyve")) return "bhyve";
            if (vendor.StartsWith("VBoxVBoxVBox")) return "VirtualBox";

            // Return raw ASCII if recognized pattern not found
            return vendor.Length > 0 ? vendor : "Unknown";
        }
        catch
        {
            return "Unknown";
        }
    }

    /// <summary>
    /// Queries hypervisor vendor via CPUID leaf 0x40000000 (primary),
    /// then NtQuerySystemInformation(0xC5) as fallback.
    /// Returns object[3] = { success, vendorString, interfaceIdHex }.
    /// </summary>
    private static object[] QueryHypervisorDetail()
    {
        bool success = false;
        string vendorString = "Unknown";
        string interfaceIdHex = "N/A";

        // == Primary: CPUID leaf 0x40000000 ============================
        // The hypervisor intercepts this leaf and returns its vendor
        // signature. Works on both root partition and guest VMs.
        try
        {
            // First check CPUID leaf 1 ECX[31] for hypervisor present bit
            uint[] leaf1 = ExecuteCpuid(1, 0);
            bool hvBit = (leaf1[2] & (1u << 31)) != 0;

            if (hvBit)
            {
                // Hypervisor present -- query leaf 0x40000000 for vendor
                uint[] leaf40 = ExecuteCpuid(0x40000000, 0);

                // EAX: max hypervisor CPUID leaf (must be >= 0x40000000)
                if (leaf40[0] >= 0x40000000)
                {
                    // EBX + ECX + EDX: 12-byte vendor signature
                    byte[] vendorBytes = new byte[12];
                    BitConverter.GetBytes(leaf40[1]).CopyTo(vendorBytes, 0);  // EBX
                    BitConverter.GetBytes(leaf40[2]).CopyTo(vendorBytes, 4);  // ECX
                    BitConverter.GetBytes(leaf40[3]).CopyTo(vendorBytes, 8);  // EDX

                    vendorString = ParseVendorSignature(vendorBytes);
                    interfaceIdHex = Encoding.ASCII.GetString(vendorBytes, 0, 12).Trim('\0', ' ');
                    success = true;
                }
            }
        }
        catch { /* CPUID execution failed -- fall through */ }

        // == Fallback: NtQuerySystemInformation(0xC5) ==================
        // Works in guest VMs but returns STATUS_NOT_IMPLEMENTED on
        // Hyper-V root partition.
        if (!success)
        {
            try
            {
                uint returnLength = 0;

                uint status = NtQuerySystemInformation(
                    SystemHypervisorDetailInformation,
                    IntPtr.Zero, 0, out returnLength);

                if (status != STATUS_NOT_IMPLEMENTED && returnLength > 0)
                {
                    IntPtr buffer = Marshal.AllocHGlobal((int)returnLength);
                    try
                    {
                        status = NtQuerySystemInformation(
                            SystemHypervisorDetailInformation,
                            buffer, returnLength, out returnLength);

                        if (status == STATUS_SUCCESS && returnLength >= 16)
                        {
                            success = true;

                            // Structure: ULONG MaxFunction (EAX) + 12 bytes vendor (EBX,ECX,EDX)
                            byte[] vendorBytes = new byte[12];
                            Marshal.Copy(new IntPtr(buffer.ToInt64() + 4), vendorBytes, 0, 12);

                            vendorString = ParseVendorSignature(vendorBytes);
                            interfaceIdHex = Encoding.ASCII.GetString(vendorBytes, 0, 12).Trim('\0', ' ');
                        }
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(buffer);
                    }
                }
            }
            catch { }
        }

        return new object[] { success, vendorString, interfaceIdHex };
    }

    /// <summary>
    /// Queries comprehensive hypervisor and VBS information.
    /// Returns object[10]: hypervisorPresent, hypervisorVendor, interfaceId, vbsStatus,
    ///   hvciEnabled, nestedVirtEnabled, systemModel, systemManufacturer, ntApiSuccess, querySuccess
    /// </summary>
    public static object[] Query()
    {
        EnsureElevated();

        // Query hypervisor vendor via CPUID / NT API
        object[] hvDetail = QueryHypervisorDetail();
        bool ntApiSuccess = (bool)hvDetail[0];
        string hypervisorVendor = (string)hvDetail[1];
        string interfaceId = (string)hvDetail[2];

        // Initialize defaults
        bool hypervisorPresent = false;
        string vbsStatus = "NotConfigured";
        bool hvciEnabled = false;
        bool nestedVirtEnabled = false;
        string systemModel = "Unknown";
        string systemManufacturer = "Unknown";
        bool querySuccess = true;

        // Query Win32_ComputerSystem for hypervisor presence and system info
        try
        {
            using (var searcher = new ManagementObjectSearcher(
                "root\\CIMv2",
                "SELECT HypervisorPresent, Model, Manufacturer FROM Win32_ComputerSystem"))
            {
                foreach (ManagementObject obj in searcher.Get())
                {
                    var hvPresent = obj["HypervisorPresent"];
                    if (hvPresent != null)
                        hypervisorPresent = Convert.ToBoolean(hvPresent);

                    var model = obj["Model"];
                    if (model != null)
                        systemModel = model.ToString();

                    var manufacturer = obj["Manufacturer"];
                    if (manufacturer != null)
                        systemManufacturer = manufacturer.ToString();

                    break;
                }
            }
        }
        catch { querySuccess = false; /* WMI may fail */ }

        // Query Win32_DeviceGuard for VBS and HVCI status
        try
        {
            using (var searcher = new ManagementObjectSearcher(
                "root\\Microsoft\\Windows\\DeviceGuard",
                "SELECT VirtualizationBasedSecurityStatus, SecurityServicesRunning FROM Win32_DeviceGuard"))
            {
                foreach (ManagementObject obj in searcher.Get())
                {
                    // VBS status
                    var vbs = obj["VirtualizationBasedSecurityStatus"];
                    if (vbs != null)
                    {
                        switch (Convert.ToInt32(vbs))
                        {
                            case VBSRunning:    vbsStatus = "Running"; break;
                            case VBSNotRunning: vbsStatus = "NotRunning"; break;
                            default:            vbsStatus = "NotConfigured"; break;
                        }
                    }

                    // Check for HVCI in running services
                    var running = obj["SecurityServicesRunning"] as int[];
                    if (running != null)
                    {
                        foreach (int svc in running)
                        {
                            if (svc == SecurityServiceHVCI)
                            {
                                hvciEnabled = true;
                                break;
                            }
                        }
                    }

                    break;
                }
            }
        }
        catch { /* DeviceGuard WMI may not be available */ }

        // Check nested virtualization via registry
        try
        {
            using (var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization"))
            {
                if (key != null)
                {
                    var nested = key.GetValue("NestedVirtualization");
                    if (nested != null)
                        nestedVirtEnabled = Convert.ToInt32(nested) > 0;
                }
            }
        }
        catch { }

        // Fallback vendor detection when both CPUID and NT API fail
        if (hypervisorPresent && !ntApiSuccess)
        {
            try
            {
                // Check for Microsoft Hyper-V via Virtualization registry
                using (var key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization"))
                {
                    if (key != null)
                    {
                        hypervisorVendor = "Microsoft Hyper-V";
                    }
                }

                // If still unknown, check for VMware
                if (hypervisorVendor == "Unknown")
                {
                    using (var key = Registry.LocalMachine.OpenSubKey(
                        @"SOFTWARE\VMware, Inc.\VMware Tools"))
                    {
                        if (key != null)
                            hypervisorVendor = "VMware";
                    }
                }

                // If still unknown, check system BIOS for VM indicators
                if (hypervisorVendor == "Unknown")
                {
                    using (var searcher = new ManagementObjectSearcher(
                        "root\\CIMv2", "SELECT Manufacturer FROM Win32_BaseBoard"))
                    {
                        foreach (ManagementObject obj in searcher.Get())
                        {
                            var mfr = obj["Manufacturer"];
                            if (mfr != null)
                            {
                                string mfrStr = mfr.ToString();
                                if (mfrStr.Contains("Microsoft")) hypervisorVendor = "Microsoft Hyper-V";
                                else if (mfrStr.Contains("VMware")) hypervisorVendor = "VMware";
                                else if (mfrStr.Contains("QEMU")) hypervisorVendor = "QEMU/KVM";
                                else if (mfrStr.Contains("Xen")) hypervisorVendor = "Xen";
                                else if (mfrStr.Contains("innotek") || mfrStr.Contains("Oracle")) hypervisorVendor = "VirtualBox";
                            }
                            break;
                        }
                    }
                }
            }
            catch { /* Fallback detection is best-effort */ }
        }

        return new object[] {
            hypervisorPresent,      // 0
            hypervisorVendor,       // 1
            interfaceId,            // 2
            vbsStatus,              // 3
            hvciEnabled,            // 4
            nestedVirtEnabled,      // 5
            systemModel,            // 6
            systemManufacturer,     // 7
            ntApiSuccess,           // 8
            querySuccess            // 9
        };
    }
}
'@ -ReferencedAssemblies $CIRefWmiReg
    }

    Write-Verbose 'Querying hypervisor and VBS state via CPUID...'

    $result = [WDACHypervisorDetailReader]::Query()

    [PSCustomObject]@{
        HypervisorPresent           = [bool]$result[0]
        HypervisorVendor            = [string]$result[1]
        HypervisorInterfaceId       = [string]$result[2]
        VBSStatus                   = [string]$result[3]
        HVCIEnabled                 = [bool]$result[4]
        NestedVirtualizationEnabled = [bool]$result[5]
        SystemModel                 = [string]$result[6]
        SystemManufacturer          = [string]$result[7]
        NtApiQuerySuccess           = [bool]$result[8]
        QuerySuccess                = [bool]$result[9]
    }
}
