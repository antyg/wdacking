function Unprotect-Pkcs7Policy {
    <#
    .SYNOPSIS
        Detects and unwraps PKCS#7 SignedData wrapping from CI policy binary data.

    .DESCRIPTION
        CI policy files (.p7b and signed .cip) may be wrapped in a PKCS#7
        SignedData envelope. This function detects the wrapping (ASN.1 SEQUENCE
        tag 0x30 at byte 0) and extracts the inner CI policy bytes using
        System.Security.Cryptography.Pkcs.SignedCms.

        Does NOT verify the signature — that is the OS kernel's responsibility.
        This function only peels the cryptographic envelope.

        Detection: CI policies start with FormatVersion 1-9 (small int).
        PKCS#7 starts with ASN.1 SEQUENCE tag 0x30 (48 decimal).

    .PARAMETER Data
        Raw byte array that may be PKCS#7 wrapped.

    .OUTPUTS
        [byte[]] The unwrapped CI policy bytes, or the original bytes if not PKCS#7.
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [byte[]]$Data
    )

    # Quick detection: first byte 0x30 = ASN.1 SEQUENCE (PKCS#7 signature)
    if ($Data.Length -lt 4 -or $Data[0] -ne 0x30) {
        return $Data
    }

    # Ensure the PKCS#7 assembly is available
    # PS 5.1 (.NET Framework): SignedCms lives in System.Security
    # pwsh 7+ (.NET Core):     SignedCms lives in System.Security.Cryptography.Pkcs
    try {
        if ($PSVersionTable.PSEdition -eq 'Core') {
            Add-Type -AssemblyName System.Security.Cryptography.Pkcs -ErrorAction Stop
        }
        else {
            Add-Type -AssemblyName System.Security -ErrorAction Stop
        }
    }
    catch {
        throw "PKCS#7 assembly not available for unwrapping: $_"
    }

    try {
        $cms = [System.Security.Cryptography.Pkcs.SignedCms]::new()
        $cms.Decode($Data)
        $content = $cms.ContentInfo.Content

        if ($null -eq $content -or $content.Length -eq 0) {
            throw 'PKCS#7 ContentInfo.Content is empty'
        }

        # Content may be wrapped in ASN.1 OCTET STRING (tag 0x04)
        if ($content[0] -eq 0x04) {
            $offset = 1

            if ($content[$offset] -lt 0x80) {
                # Short form: single-byte length
                $length = [int]$content[$offset]
                $offset++
            }
            else {
                # Long form: first byte = 0x80 | number of length bytes
                $sizeBytes = $content[$offset] -band 0x7F
                $offset++
                $length = 0
                for ($i = 0; $i -lt $sizeBytes; $i++) {
                    $length = ($length -shl 8) -bor [int]$content[$offset]
                    $offset++
                }
            }

            if (($offset + $length) -gt $content.Length) {
                throw 'Malformed OCTET STRING in PKCS#7 content'
            }

            $inner = [byte[]]::new($length)
            [Array]::Copy($content, $offset, $inner, 0, $length)
            return $inner
        }

        # Not wrapped in OCTET STRING — content is the raw policy bytes
        return $content
    }
    catch [System.Security.Cryptography.CryptographicException] {
        throw "Failed to decode PKCS#7 wrapper: $_"
    }
}
