function Get-WDACMemoryEncryption {
    <#
    .SYNOPSIS
        Queries CPU memory encryption capabilities (AMD SEV, Intel TME/MKTME).

    .DESCRIPTION
        Detects hardware-based memory encryption features by executing the CPUID
        instruction directly to query CPU capability bits, providing definitive
        hardware-level detection independent of OS registry exposure.

        Primary detection uses native CPUID execution via dynamically emitted x64
        machine code (VirtualAlloc + delegate invocation):
        - Intel TME:  CPUID leaf 7 subleaf 0 ECX[13] for capability,
                      leaf 0x1B for algorithm enumeration and MKTME key count
        - AMD SEV:    CPUID leaf 0x8000001F EAX bits 1/3/4 for SEV/ES/SNP

        Enablement status (whether the feature is actually active) requires MSR
        access (ring 0), so registry is used as a secondary source for activation
        state where available. When registry keys are absent, enablement is
        reported as "BIOS-Controlled".

        Returns detailed information about:
        - CPU vendor identification (via CPUID leaf 0 vendor string)
        - AMD SEV, SEV-ES, and SEV-SNP support and enablement status
        - Intel TME and MKTME support, key count, and algorithm capabilities
        - Detection source and limitations

    .OUTPUTS
        PSCustomObject with properties:
            - CPUVendor              [string]  CPU manufacturer ("Intel", "AMD", or raw vendor string)
            - CPUName                [string]  Processor model name
            - SEVSupported           [string]  "Supported", "NotSupported", "NotApplicable", "NotDetectable"
            - SEVEnabled             [string]  "Enabled", "Disabled", "BIOS-Controlled", "NotApplicable", "NotDetectable"
            - SEVESSupported         [string]  SEV with Encrypted State support status
            - SEVSNPSupported        [string]  SEV Secure Nested Paging support status
            - TMESupported           [string]  Intel TME support status
            - TMEEnabled             [string]  Intel TME enablement status
            - MKTMESupported         [string]  Intel MKTME support status
            - MKTMEKeyCount          [int]     Number of MKTME encryption keys (0 if not available)
            - EncryptionAlgorithm    [string]  Supported algorithm(s) or "NotDetectable"
            - DetectionLimitations   [string]  Human-readable notes about detection constraints
            - QuerySuccess           [bool]    Overall query success indicator

    .EXAMPLE
        Get-WDACMemoryEncryption
        Returns the full memory encryption capability assessment.

    .EXAMPLE
        (Get-WDACMemoryEncryption).TMESupported
        Quick check whether Intel TME is supported by the CPU hardware.

    .EXAMPLE
        Get-WDACMemoryEncryption | Format-List
        Displays all memory encryption properties in list format.

    .NOTES
        Requires: Administrator elevation
        Platform: Windows 10+ / Windows 11 (x64 only for CPUID execution)

        Detection Architecture:
        - CPUID instruction executed via VirtualAlloc + native code delegation
        - Capability detection is definitive (hardware truth from CPU microcode)
        - Enablement detection is best-effort (MSR requires ring 0; registry used as proxy)
        - Falls back to registry-only detection if CPUID execution fails
    #>
    [CmdletBinding()]
    param()

    if (-not ([System.Management.Automation.PSTypeName]'WDACMemoryEncryptionReader').Type) {
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;

public static class WDACMemoryEncryptionReader
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
    // Microsoft x64 ABI: RCX=leaf, RDX=subleaf, R8=output_ptr
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate void CpuidDelegate(uint leaf, uint subleaf, IntPtr output);

    // x86-64 machine code: CPUID wrapper (24 bytes)
    // Executes CPUID(eax=leaf, ecx=subleaf) and stores EAX,EBX,ECX,EDX
    // at the address pointed to by R8.
    //
    //   push rbx              ; save callee-saved RBX (CPUID clobbers it)
    //   mov  eax, ecx         ; leaf  (1st arg RCX -> EAX)
    //   mov  ecx, edx         ; subleaf (2nd arg RDX -> ECX)
    //   cpuid                 ; execute -- clobbers EAX,EBX,ECX,EDX
    //   mov  [r8+0],  eax     ; store results at output pointer
    //   mov  [r8+4],  ebx
    //   mov  [r8+8],  ecx
    //   mov  [r8+12], edx
    //   pop  rbx              ; restore RBX
    //   ret
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
    /// Requires x64 platform (CPUID is a user-mode instruction on x86-64).
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
    /// Safely reads a DWORD registry value, returning default on failure.
    /// </summary>
    private static int GetRegistryDWord(RegistryKey baseKey, string subKeyPath, string valueName, int defaultValue)
    {
        try
        {
            using (var key = baseKey.OpenSubKey(subKeyPath))
            {
                if (key != null)
                {
                    var value = key.GetValue(valueName);
                    if (value != null)
                        return Convert.ToInt32(value);
                }
            }
        }
        catch { }
        return defaultValue;
    }

    /// <summary>
    /// Safely reads a string registry value, returning default on failure.
    /// </summary>
    private static string GetRegistryString(RegistryKey baseKey, string subKeyPath, string valueName, string defaultValue)
    {
        try
        {
            using (var key = baseKey.OpenSubKey(subKeyPath))
            {
                if (key != null)
                {
                    var value = key.GetValue(valueName);
                    if (value != null)
                        return value.ToString();
                }
            }
        }
        catch { }
        return defaultValue;
    }

    /// <summary>
    /// Detects CPU vendor and max CPUID leaf via CPUID leaf 0.
    /// Returns object[2] = { vendorString, maxStandardLeaf }.
    /// Falls back to registry if CPUID execution fails.
    /// </summary>
    private static object[] DetectCPUVendor()
    {
        string vendor = "Unknown";
        uint maxLeaf = 0;

        try
        {
            // CPUID leaf 0: vendor string in EBX+EDX+ECX, max leaf in EAX
            uint[] leaf0 = ExecuteCpuid(0, 0);
            maxLeaf = leaf0[0];

            byte[] vendorBytes = new byte[12];
            BitConverter.GetBytes(leaf0[1]).CopyTo(vendorBytes, 0);  // EBX -> bytes 0-3
            BitConverter.GetBytes(leaf0[3]).CopyTo(vendorBytes, 4);  // EDX -> bytes 4-7
            BitConverter.GetBytes(leaf0[2]).CopyTo(vendorBytes, 8);  // ECX -> bytes 8-11

            string rawVendor = Encoding.ASCII.GetString(vendorBytes);

            if (rawVendor == "GenuineIntel") vendor = "Intel";
            else if (rawVendor == "AuthenticAMD") vendor = "AMD";
            else vendor = rawVendor.Trim('\0', ' ');
        }
        catch
        {
            // CPUID failed -- fall back to registry
            string regVendor = GetRegistryString(
                Registry.LocalMachine,
                @"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
                "VendorIdentifier", "Unknown");

            if (regVendor.Contains("GenuineIntel")) vendor = "Intel";
            else if (regVendor.Contains("AuthenticAMD")) vendor = "AMD";
            else vendor = regVendor;
        }

        return new object[] { vendor, maxLeaf };
    }

    /// <summary>
    /// Queries CPU name via WMI Win32_Processor.
    /// </summary>
    private static string QueryCPUName()
    {
        try
        {
            using (var searcher = new ManagementObjectSearcher("SELECT Name FROM Win32_Processor"))
            {
                foreach (ManagementObject obj in searcher.Get())
                {
                    var name = obj["Name"];
                    if (name != null)
                        return name.ToString().Trim();
                }
            }
        }
        catch { }
        return "Unknown";
    }

    /// <summary>
    /// Detects Intel TME/MKTME capabilities via CPUID leaves 7 and 0x1B.
    /// Falls back to registry if CPUID is unavailable.
    /// Returns object[6] = { tmeSupported, tmeEnabled, mktmeSupported, mktmeKeyCount, algorithm, cpuidUsed }
    /// </summary>
    private static object[] DetectIntelTME(uint maxStandardLeaf)
    {
        string tmeSupported = "NotDetectable";
        string tmeEnabled = "NotDetectable";
        string mktmeSupported = "NotDetectable";
        int mktmeKeyCount = 0;
        string algorithm = "NotDetectable";
        bool cpuidUsed = false;

        // == Primary: CPUID-based detection ============================
        try
        {
            if (maxStandardLeaf >= 7)
            {
                // CPUID leaf 7, subleaf 0: Structured Extended Feature Flags
                // ECX bit 13 = TME capability
                uint[] leaf7 = ExecuteCpuid(7, 0);
                bool tmeBit = (leaf7[2] & (1u << 13)) != 0;

                tmeSupported = tmeBit ? "Supported" : "NotSupported";
                cpuidUsed = true;

                if (tmeBit)
                {
                    // TME hardware-capable -- check TME-MK (Multi-Key) enumeration
                    if (maxStandardLeaf >= 0x1B)
                    {
                        uint[] leaf1B = ExecuteCpuid(0x1B, 0);

                        // EAX: algorithm capability flags
                        //   bit 0 = AES-XTS-128
                        //   bit 1 = AES-XTS-256
                        var algos = new List<string>();
                        if ((leaf1B[0] & 0x01) != 0) algos.Add("AES-XTS-128");
                        if ((leaf1B[0] & 0x02) != 0) algos.Add("AES-XTS-256");
                        if (algos.Count > 0)
                            algorithm = string.Join(", ", algos);

                        // EBX bits [15:0]: number of MKTME keys
                        int keyCount = (int)(leaf1B[1] & 0xFFFF);
                        if (keyCount > 0)
                        {
                            mktmeSupported = "Supported";
                            mktmeKeyCount = keyCount;
                        }
                        else
                        {
                            mktmeSupported = "NotSupported";
                        }
                    }
                    else
                    {
                        // TME supported but leaf 0x1B not available
                        // TME defaults to AES-XTS-128
                        algorithm = "AES-XTS-128";
                        mktmeSupported = "NotSupported";
                    }

                    // If leaf 0x1B was queried but returned no algorithm bits
                    // (e.g. Hyper-V filtering), default to AES-XTS-128 which is
                    // the mandatory algorithm for TME per Intel specification
                    if (algorithm == "NotDetectable")
                        algorithm = "AES-XTS-128";

                    // Enablement: MSR IA32_TME_ACTIVATE (0x982) is ring-0 only
                    // Check registry as proxy for activation state
                    int encCaps = GetRegistryDWord(
                        Registry.LocalMachine,
                        @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
                        "EncryptionCapabilities", -1);

                    if (encCaps != -1)
                        tmeEnabled = (encCaps & 0x01) != 0 ? "Enabled" : "Disabled";
                    else
                        tmeEnabled = "BIOS-Controlled";
                }
            }
        }
        catch
        {
            // CPUID execution failed -- fall through to registry fallback
        }

        // == Fallback: registry-only detection =========================
        if (!cpuidUsed)
        {
            int encCaps = GetRegistryDWord(
                Registry.LocalMachine,
                @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
                "EncryptionCapabilities", -1);

            if (encCaps != -1)
            {
                tmeSupported = encCaps > 0 ? "Supported" : "NotSupported";
                tmeEnabled = (encCaps & 0x01) != 0 ? "Enabled" : "Disabled";
            }

            int keyCount = GetRegistryDWord(
                Registry.LocalMachine,
                @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
                "TotalMemoryEncryptionKeys", -1);

            if (keyCount > 0)
            {
                mktmeSupported = "Supported";
                mktmeKeyCount = keyCount;
            }

            string algoReg = GetRegistryString(
                Registry.LocalMachine,
                @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
                "EncryptionAlgorithm", "");

            if (!string.IsNullOrEmpty(algoReg))
                algorithm = algoReg;
        }

        return new object[] { tmeSupported, tmeEnabled, mktmeSupported, mktmeKeyCount, algorithm, cpuidUsed };
    }

    /// <summary>
    /// Detects AMD SEV/SEV-ES/SEV-SNP capabilities via CPUID leaf 0x8000001F.
    /// Falls back to registry if CPUID is unavailable.
    /// Returns object[5] = { sevSupported, sevEnabled, sevESSupported, sevSNPSupported, cpuidUsed }
    /// </summary>
    private static object[] DetectAMDSEV()
    {
        string sevSupported = "NotDetectable";
        string sevEnabled = "NotDetectable";
        string sevESSupported = "NotDetectable";
        string sevSNPSupported = "NotDetectable";
        bool cpuidUsed = false;

        // == Primary: CPUID-based detection ============================
        try
        {
            // Check max extended CPUID leaf
            uint[] leaf80 = ExecuteCpuid(0x80000000, 0);
            uint maxExtLeaf = leaf80[0];

            if (maxExtLeaf >= 0x8000001F)
            {
                // CPUID leaf 0x8000001F: AMD Encrypted Memory Capabilities
                //   EAX bit 0 = SME (Secure Memory Encryption)
                //   EAX bit 1 = SEV
                //   EAX bit 3 = SEV-ES
                //   EAX bit 4 = SEV-SNP
                //   ECX = Number of encrypted guests supported
                uint[] leafSEV = ExecuteCpuid(0x8000001F, 0);
                cpuidUsed = true;

                bool sevBit     = (leafSEV[0] & (1u << 1)) != 0;
                bool sevesBit   = (leafSEV[0] & (1u << 3)) != 0;
                bool sevsnpBit  = (leafSEV[0] & (1u << 4)) != 0;

                sevSupported    = sevBit    ? "Supported" : "NotSupported";
                sevESSupported  = sevesBit  ? "Supported" : "NotSupported";
                sevSNPSupported = sevsnpBit ? "Supported" : "NotSupported";

                // Enablement: MSR 0xC0010131 (SEV_STATUS) is ring-0 only
                // Check registry as proxy
                if (sevBit)
                {
                    int sevFlag = GetRegistryDWord(
                        Registry.LocalMachine,
                        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization",
                        "SEVEnabled", -1);

                    if (sevFlag != -1)
                        sevEnabled = sevFlag > 0 ? "Enabled" : "Disabled";
                    else
                        sevEnabled = "BIOS-Controlled";
                }
            }
        }
        catch
        {
            // CPUID execution failed -- fall through to registry
        }

        // == Fallback: registry-only detection =========================
        if (!cpuidUsed)
        {
            int sevFlag = GetRegistryDWord(
                Registry.LocalMachine,
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization",
                "SEVEnabled", -1);

            if (sevFlag != -1)
            {
                sevSupported = "Supported";
                sevEnabled = sevFlag > 0 ? "Enabled" : "Disabled";
            }

            string hvFeatures = GetRegistryString(
                Registry.LocalMachine,
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization",
                "HypervisorFeatures", "");

            if (hvFeatures.Contains("SEV-ES") || hvFeatures.Contains("SEVES"))
                sevESSupported = "Supported";
            if (hvFeatures.Contains("SEV-SNP") || hvFeatures.Contains("SEVSNP"))
                sevSNPSupported = "Supported";
        }

        return new object[] { sevSupported, sevEnabled, sevESSupported, sevSNPSupported, cpuidUsed };
    }

    /// <summary>
    /// Queries comprehensive memory encryption information.
    /// Returns object[13]: cpuVendor, cpuName, sevSupported, sevEnabled,
    ///   sevESSupported, sevSNPSupported, tmeSupported, tmeEnabled,
    ///   mktmeSupported, mktmeKeyCount, algorithm, detectionLimitations, querySuccess
    /// </summary>
    public static object[] Query()
    {
        EnsureElevated();

        bool querySuccess = true;
        var limitations = new List<string>();

        // == CPU identification ========================================
        string cpuVendor = "Unknown";
        string cpuName = "Unknown";
        uint maxStandardLeaf = 0;

        try
        {
            object[] vendorResult = DetectCPUVendor();
            cpuVendor = (string)vendorResult[0];
            maxStandardLeaf = (uint)vendorResult[1];
            cpuName = QueryCPUName();
        }
        catch (Exception ex)
        {
            querySuccess = false;
            limitations.Add("CPU identification failed: " + ex.Message);
        }

        // == Initialize defaults =======================================
        string sevSupported    = "NotDetectable";
        string sevEnabled      = "NotDetectable";
        string sevESSupported  = "NotDetectable";
        string sevSNPSupported = "NotDetectable";
        string tmeSupported    = "NotDetectable";
        string tmeEnabled      = "NotDetectable";
        string mktmeSupported  = "NotDetectable";
        int    mktmeKeyCount   = 0;
        string algorithm       = "NotDetectable";

        // == Vendor-specific detection =================================
        if (cpuVendor == "AMD")
        {
            try
            {
                object[] sevResults = DetectAMDSEV();
                sevSupported    = (string)sevResults[0];
                sevEnabled      = (string)sevResults[1];
                sevESSupported  = (string)sevResults[2];
                sevSNPSupported = (string)sevResults[3];
                bool cpuidUsed  = (bool)sevResults[4];

                if (sevSupported == "NotDetectable")
                    limitations.Add("AMD SEV: Detection unavailable (CPUID and registry both failed)");
                else if (!cpuidUsed)
                    limitations.Add("AMD SEV: CPUID execution failed; results from registry fallback");

                if (sevEnabled == "BIOS-Controlled")
                    limitations.Add("AMD SEV: Hardware capability confirmed via CPUID; enablement controlled by BIOS (MSR 0xC0010131 requires ring 0)");
            }
            catch (Exception ex)
            {
                querySuccess = false;
                limitations.Add("AMD SEV detection error: " + ex.Message);
            }

            // Intel features not applicable on AMD
            tmeSupported   = "NotApplicable";
            tmeEnabled     = "NotApplicable";
            mktmeSupported = "NotApplicable";
        }
        else if (cpuVendor == "Intel")
        {
            try
            {
                object[] tmeResults = DetectIntelTME(maxStandardLeaf);
                tmeSupported   = (string)tmeResults[0];
                tmeEnabled     = (string)tmeResults[1];
                mktmeSupported = (string)tmeResults[2];
                mktmeKeyCount  = (int)tmeResults[3];
                algorithm      = (string)tmeResults[4];
                bool cpuidUsed = (bool)tmeResults[5];

                if (tmeSupported == "NotDetectable")
                    limitations.Add("Intel TME: Detection unavailable (CPUID and registry both failed)");
                else if (!cpuidUsed)
                    limitations.Add("Intel TME: CPUID execution failed; results from registry fallback");

                if (tmeEnabled == "BIOS-Controlled")
                    limitations.Add("Intel TME: Hardware capability confirmed via CPUID; enablement controlled by BIOS/firmware (MSR 0x982 requires ring 0)");
            }
            catch
            {
                querySuccess = false;
                limitations.Add("Intel TME detection error");
            }

            // AMD features not applicable on Intel
            sevSupported    = "NotApplicable";
            sevEnabled      = "NotApplicable";
            sevESSupported  = "NotApplicable";
            sevSNPSupported = "NotApplicable";
        }
        else
        {
            limitations.Add("Unknown CPU vendor '" + cpuVendor + "' - cannot determine memory encryption features");
            querySuccess = false;
        }

        // == General notes =============================================
        limitations.Add("Enablement status requires MSR access (ring 0); registry used as proxy where available");

        string limitationsText = string.Join("; ", limitations);

        return new object[] {
            cpuVendor,          // 0
            cpuName,            // 1
            sevSupported,       // 2
            sevEnabled,         // 3
            sevESSupported,     // 4
            sevSNPSupported,    // 5
            tmeSupported,       // 6
            tmeEnabled,         // 7
            mktmeSupported,     // 8
            mktmeKeyCount,      // 9
            algorithm,          // 10
            limitationsText,    // 11
            querySuccess        // 12
        };
    }
}
'@ -ReferencedAssemblies $CIRefWmiReg
    }

    Write-Verbose 'Querying CPU memory encryption capabilities via CPUID...'

    $result = [WDACMemoryEncryptionReader]::Query()

    [PSCustomObject]@{
        CPUVendor             = [string]$result[0]
        CPUName               = [string]$result[1]
        SEVSupported          = [string]$result[2]
        SEVEnabled            = [string]$result[3]
        SEVESSupported        = [string]$result[4]
        SEVSNPSupported       = [string]$result[5]
        TMESupported          = [string]$result[6]
        TMEEnabled            = [string]$result[7]
        MKTMESupported        = [string]$result[8]
        MKTMEKeyCount         = [int]$result[9]
        EncryptionAlgorithm   = [string]$result[10]
        DetectionLimitations  = [string]$result[11]
        QuerySuccess          = [bool]$result[12]
    }
}
