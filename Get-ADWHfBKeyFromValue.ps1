#
# Get_ADWhfbKeyFromValue.ps1
#
# Copyright 2019 Microsoft. All rights reserved.
#

function Get-ADWHfBKeyFromValue
{
    <#.SYNOPSIS
        Parses a WHfB key from a msdsKeyCredentialLink dn-binary value.

    .DESCRIPTION
        Parses a WHfB key from a msdsKeyCredentialLink dn-binary value.

    .PARAMETER RawValue
        The raw value of the msdsKeyCredentialLink dn-binary attribute as
        queried via LDAP.

    .PARAMETER Logging
        This switch will enable additional diagnostic logging to a file.

    #>

    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory=$true
            )]
            [string]$RawValue,
        [Parameter(
            Mandatory=$false
            )]
            [bool]$Logging
    )

    Process
    {
        $memStream = $null;
        $binReader = $null;

        try
        {
            $parsedLink = $RawValue.Split(':');

            if($parsedLink.Length -ne 4)
            {
                if ($Logging)
                {
                    $output = "Key has unexpected number of elements: $parsedLink.Length"
                    DiagLog $output -logOnly
                }
                Write-Output $null;
                return;
            }

            $valueCount = [Convert]::ToInt32($parsedLink[1]);

            if ($parsedLink[2].Length -ne $valueCount)
            {
                if ($Logging)
                {
                    $output = "Key has unexpected valueCount: $parsedLink[2].Length $valueCount"
                    DiagLog $output -logOnly
                }
                Write-Output $null;
                return;
            }

            $keyBytes = Get-ByteArrayFromHexString -HexString $parsedLink[2];

            $memStream = New-Object System.IO.MemoryStream (,[byte[]]$keyBytes)
            $binReader = New-Object System.IO.BinaryReader $memStream;

            $key = Get-ADWHfBKeyFromRawValueBinary -Reader $binReader

            if($null -eq $key)
            {
                Write-Output $null;
                return;
            }

            $key.KeyLinkTargetDN = $parsedLink[3];
            $key.KeyRawLDAPValue = $RawValue;

            Write-Output $key;
        }
        catch
        {
            $output = "Get-ADWHfBKeyFromValue caught exception: " + $_.Exception.ToString()
            DiagLog $output -logOnly
            Write-Output $null
        }
        finally
        {
            if($null -ne $binReader)
            {
                $binReader.Close();
                $binReader.Dispose();
            }

            if($null -ne $memStream)
            {
                $memStream.Close();
                $memStream.Dispose();
            }
        }
    }
}

<#
    Get-ADWHfBKeyFromRawValueBinary
#>
function Get-ADWHfBKeyFromRawValueBinary
{
    <#.SYNOPSIS
        Parses a WHfB key from a msdsKeyCredentialLink dn-binary binary value.

    .DESCRIPTION
        Parses a WHfB key from a msdsKeyCredentialLink dn-binary binary value.

    .PARAMETER Reader
        The binary value loaded into a binary reader object.

    .PARAMETER Logging
        This switch will enable additional diagnostic logging to a file.
    #>

    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory=$true)]
            [System.IO.BinaryReader]$Reader,
        [Parameter(
            Mandatory=$false
            )]
            [bool]$Logging
    )

    Process
    {
        # Create empty key object with all fields
        $Key = [PSCustomObject]@{
            UserDomain = ""
            UserSamAccountName = ""
            UserDistinguishedName = ""
            KeyVersion = -1
            KeyId = ""
            KeyMaterial = $null
            KeySource = ""
            KeyUsage = ""
            KeyDeviceId = ""
            KeyApproximateLastLogonTimestamp = ""
            KeyCreationTime = ""
            CustomKeyInformation = $null
            KeyLinkTargetDN = ""
            ROCAVulnerable = "Unknown"
            OrphanedKey = "Unknown"
            KeyRawLDAPValue = ""
        }

        $keySourceString = [String]::Empty;
        $keySource = @(1);
        $lastReadKeyId = [KEY_OBJECT_ATTR_TYPE]::KeyObjectValueIdMsDsKeyVersion;

        # First four bytes is the key version
        $KeyVersionBytes = 0;
        $KeyVersionBytes = $Reader.ReadUInt32();
        switch($KeyVersionBytes)
        {
            0
            {
                if ($Logging)
                {
                    $output = "Key has zero (0) version : $parsedLink[2].Length $valueCount"
                    DiagLog $output -logOnly
                }
                return $null
            };
            0x100
            {
                $Key.KeyVersion = 1;
                break;
            };
            0x200
            {
                $Key.KeyVersion = 2;
                break;
            }
            default
            {
                if ($Logging)
                {
                    $output = "Key has unrecognized version: " + $KeyVersionBytes.ToString()
                    DiagLog $output -logOnly
                }
                return $null;
            }
        }

        # Each set in this stream is in the form of:
        # { keyValueCount (2bytes), keyId (1byte),  keyValue (keyValueCount bytes) }
        do
        {
            # Read the keyValueCount
            $keyValueCount = $Reader.ReadUInt16();

            # Read the keyId
            $keyId = $Reader.ReadByte();

            if ($keyId -ge 10 -or
                $keyId -lt 0)
            {
                if ($Logging)
                {
                    $output = "Key value has unrecognized id: $keyId"
                    DiagLog $output -logOnly
                }
                return $null
            }

            $readKeyId = [KEY_OBJECT_ATTR_TYPE]$keyId;

            if ($lastReadKeyId -ge $readKeyId)
            {
                if ($Logging)
                {
                    $output = "Key has duplicated key id value"
                    DiagLog $output -logOnly
                }
                return $null
            }

            # Read the actual keyValue.
            $keyValue = $Reader.ReadBytes($keyValueCount);

            switch($readKeyId)
            {
                "KeyObjectValueIdMsDsKeyUsage"
                {
                    if ($keyValueCount -eq 1)
                    {
                        switch ($keyValue[0])
                        {
                        0
                        {
                           $Key.KeyUsage = "AdminKey"
                        }
                        1
                        {
                           $Key.KeyUsage = "NGC"
                        }
                        2
                        {
                           $Key.KeyUsage = "STK"
                        }
                        3
                        {
                           $Key.KeyUsage = "BitlockerRecovery"
                        }
                        default
                        {
                           $Key.KeyUsage = "Unknown"
                        }
                        }
                    }
                    else
                    {
                        $Key.KeyUsage = [System.Text.Encoding.UTF8]::GetString($keyValue);
                    }
                    break;
                }

                "KeyObjectValueIdMsDsKeyId"
                {
                    $keyIdBytes = @();
                    $keyIdBytes = $keyValue;

                    if($Key.KeyVersion -eq 1)
                    {
                        # Version 1 keys had a guid in this field
                        $Key.KeyId = [System.BitConverter]::ToString($keyIdBytes).Replace("-", "");
                    }
                    else
                    {
                        # Version 2 keys have a SHA256 hash of the key material here
                        $Key.KeyId = [System.Convert]::ToBase64String($keyIdBytes);
                    }
                    break;
                }

                "KeyObjectValueIdMsDsKeyHash"
                {
                    # Do nothing.
                    break;
                }

                "KeyObjectValueIdMsDsKeyMaterial"
                {
                    $Key.KeyMaterial = [System.Convert]::ToBase64String($keyValue);
                    break;
                }

                "KeyObjectValueIdMsDsKeySource"
                {
                    $keySource = $keyValue;

                    if($Key.KeyVersion -le 1)
                    {
                        $Key.KeySource = "NA";
                    }
                    elseif($keySource[0]-eq 0)
                    {
                        $Key.KeySource = "AD";
                    }
                    elseif($keySource[0]-eq 1)
                    {
                        $Key.KeySource = "AzureAD";
                    }
                    else
                    {
                        $Key.KeySource = "Unknown";
                    }
                    break;
                }

                "KeyObjectValueIdMsDsDeviceId"
                {
                    $deviceId = New-Object System.Guid (,$keyValue)
                    $Key.KeyDeviceId = $deviceId.ToString()
                    break;
                }

                "KeyObjectValueIdMsDsCustomKeyInformation"
                {
                    $Key.CustomKeyInformation = [System.Convert]::ToBase64String($keyValue);
                    break;
                }

                "KeyObjectValueIdMsDsKeyApproximateLastLogonTimeStamp"
                {
                    $Key.KeyApproximateLastLogonTimestamp = Get-KeyTimeFromBytes `
                        -TimeData $keyValue `
                        -KeySource $keySource[0]`
                        -KeyVersion $Key.KeyVersion;
                    break;
                }

                "KeyObjectValueIdMsDsKeyCreationTime"
                {
                    $Key.KeyCreationTime = Get-KeyTimeFromBytes `
                        -TimeData $keyValue `
                        -KeySource $keySource[0]`
                        -KeyVersion $Key.KeyVersion;
                    break;
                }

                default
                {
                    $output = "Ignoring unrecognized key entry id: $readKeyId"
                    DiagLog $output -logOnly
                }
            }
        }
        while($Reader.BaseStream.Position -lt $Reader.BaseStream.Length);

        return $Key
    }
}

<#
    Get-KeyTimeFromBytes
#>
function Get-KeyTimeFromBytes
{
    <#.SYNOPSIS
        Parse time from byte array. The time format is inferred from the
        key source and version.

    .DESCRIPTION
        Parse time from byte array. The time format is inferred from the
        key source and version.

    .PARAMETER TimeData
        Byte array containing the time information.

    .PARAMETER KeySource
        The time source (AD or AAD).

    .PARAMETER KeyVersion
        The WHfB key version

    #>

    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory=$true,
            Position=0)]
            [byte[]]$TimeData,

        [Parameter(
            Mandatory=$true,
            Position=1)]
            [int]$KeySource,

        [Parameter(
            Mandatory=$true,
            Position=2)]
            [int]$KeyVersion
    )

    PROCESS
    {
        $dateTime64 = [System.BitConverter]::ToInt64($TimeData, 0);

        if ($dateTime64 -eq 0)
        {
            $time = [DateTime]::MinValue
        }
        elseif (($KeyVersion -le 1) -or ($KeySource -eq 1))
        {
            $time = [DateTime]::FromBinary($dateTime64);
        }
        elseif ($KeySource -eq 0)
        {
            $time = [DateTime]::FromFileTime($dateTime64);
        }
        else
        {
            throw New-Object System.Exception -ArgumentList "Unexpected time format.";
        }

        Write-Output $time.ToString("o");
    }
}

# SIG # Begin signature block
# MIIjhgYJKoZIhvcNAQcCoIIjdzCCI3MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD9PSpjJKruAPsO
# y4vS6PE/zIqzm9jn1NHXRYF1CVZ1LaCCDYEwggX/MIID56ADAgECAhMzAAABUZ6N
# j0Bxow5BAAAAAAFRMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMTkwNTAyMjEzNzQ2WhcNMjAwNTAyMjEzNzQ2WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQCVWsaGaUcdNB7xVcNmdfZiVBhYFGcn8KMqxgNIvOZWNH9JYQLuhHhmJ5RWISy1
# oey3zTuxqLbkHAdmbeU8NFMo49Pv71MgIS9IG/EtqwOH7upan+lIq6NOcw5fO6Os
# +12R0Q28MzGn+3y7F2mKDnopVu0sEufy453gxz16M8bAw4+QXuv7+fR9WzRJ2CpU
# 62wQKYiFQMfew6Vh5fuPoXloN3k6+Qlz7zgcT4YRmxzx7jMVpP/uvK6sZcBxQ3Wg
# B/WkyXHgxaY19IAzLq2QiPiX2YryiR5EsYBq35BP7U15DlZtpSs2wIYTkkDBxhPJ
# IDJgowZu5GyhHdqrst3OjkSRAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUV4Iarkq57esagu6FUBb270Zijc8w
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDU0MTM1MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAWg+A
# rS4Anq7KrogslIQnoMHSXUPr/RqOIhJX+32ObuY3MFvdlRElbSsSJxrRy/OCCZdS
# se+f2AqQ+F/2aYwBDmUQbeMB8n0pYLZnOPifqe78RBH2fVZsvXxyfizbHubWWoUf
# NW/FJlZlLXwJmF3BoL8E2p09K3hagwz/otcKtQ1+Q4+DaOYXWleqJrJUsnHs9UiL
# crVF0leL/Q1V5bshob2OTlZq0qzSdrMDLWdhyrUOxnZ+ojZ7UdTY4VnCuogbZ9Zs
# 9syJbg7ZUS9SVgYkowRsWv5jV4lbqTD+tG4FzhOwcRQwdb6A8zp2Nnd+s7VdCuYF
# sGgI41ucD8oxVfcAMjF9YX5N2s4mltkqnUe3/htVrnxKKDAwSYliaux2L7gKw+bD
# 1kEZ/5ozLRnJ3jjDkomTrPctokY/KaZ1qub0NUnmOKH+3xUK/plWJK8BOQYuU7gK
# YH7Yy9WSKNlP7pKj6i417+3Na/frInjnBkKRCJ/eYTvBH+s5guezpfQWtU4bNo/j
# 8Qw2vpTQ9w7flhH78Rmwd319+YTmhv7TcxDbWlyteaj4RK2wk3pY1oSz2JPE5PNu
# Nmd9Gmf6oePZgy7Ii9JLLq8SnULV7b+IP0UXRY9q+GdRjM2AEX6msZvvPCIoG0aY
# HQu9wZsKEK2jqvWi8/xdeeeSI9FN6K1w4oVQM4Mwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVWzCCFVcCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAVGejY9AcaMOQQAAAAABUTAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgLwGCNYHH
# 04VTe3dz78azxGeGHpi7MFlQ9SL0mPG+oiUwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQBzQkDTJF2TMkeqxyPlJgD+jDYIhbIPyWIgq5CzrOB4
# 2sFk00QL+loEMIqu4u9lPgF2ILCtU2kumaXajLxpim1nfS3f83X3JnTfWLOm9TEj
# t3ja1eeUwMp9M/kMnVnWEETSeMjUAq0zNTUCnsSccua4MX38S8zvT7sjfcBh7OAM
# aY8cW4gfv0Qr68UeS8neX0ian2waaDBhcRHT/y2ElBkUSqA7YCTkAR7A38C7YvJ2
# 25USmaX7zdiFik5oglsF+GbdIomFqEHycZQtsgMdo5Tq8UTI+mKpS+5hyV0lhWSy
# Rd8t/aY9Ax66LVS+l3jwOsEVG8V66H+pYgsF9JtORqtzoYIS5TCCEuEGCisGAQQB
# gjcDAwExghLRMIISzQYJKoZIhvcNAQcCoIISvjCCEroCAQMxDzANBglghkgBZQME
# AgEFADCCAVEGCyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIJ+0V8s79n99fhsS5hKb+hUyOvarMFpw5asulQBm
# TBAQAgZdtfNcnjEYEzIwMTkxMjA0MTQxMjEzLjA1NlowBIACAfSggdCkgc0wgcox
# CzAJBgNVBAYTAlVTMQswCQYDVQQIEwJXQTEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQg
# SXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOjNCRDQtNEI4MC02OUMzMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNloIIOPDCCBPEwggPZoAMCAQICEzMAAAEL5Pm+j29MHdAAAAAAAQsw
# DQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcN
# MTkxMDIzMjMxOTE1WhcNMjEwMTIxMjMxOTE1WjCByjELMAkGA1UEBhMCVVMxCzAJ
# BgNVBAgTAldBMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlv
# bnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046M0JENC00QjgwLTY5
# QzMxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggEiMA0G
# CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCXAtWdRjFBuM+D2nhUKLVuWv9cZcq1
# /8emykQBplDii8DqwwCNnD0zJhz7n94WtWjFsc5KL/dF8gKWTMRH5MVTa5dxCJu6
# VtZobc+sztM+0JPM5Vmcb/7D+AlFERGAkQGGxO/Z4fxHH1/EcZ/iwUimzafXjBOl
# IQ3RSxUAj980liuAyNCrj8JdunGR3nVSRvxJtWpUZvlIUrYY4LDmJJsFsI8gsch3
# LrchmPeBkoxsvy7RpKhcOQtTYacD48vz7fzT2ciciJqAXxZt7fth8sgqKiUURCVu
# SlcUKXBXm/1dcYCKqOoUz2YGu2i0t4K/X17JWZ5jdN1vxqzSQa9P4PHxAgMBAAGj
# ggEbMIIBFzAdBgNVHQ4EFgQUrR/Z6h2KHpzgmA1QRGX/921e3u8wHwYDVR0jBBgw
# FoAU1WM6XIoxkPNDe3xGG8UzaFqFbVUwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDov
# L2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljVGltU3RhUENB
# XzIwMTAtMDctMDEuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0
# cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNUaW1TdGFQQ0FfMjAx
# MC0wNy0wMS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDAN
# BgkqhkiG9w0BAQsFAAOCAQEAJuijnanvNrS63e87CK0gwImI8C4JdhxLLPnA6m/p
# USXWel9KCa3t95NRNO36NgemDxhskz7rVHiUigb1pJdm+TB5Shg2DlPi1UhdCTaN
# 5lTWZ+rHAFfDI4i2gdKOwdyug73m5ja2dqfDTl2Di5axwcBgDvGsZLfBm+aGut2v
# UGBBg1QjMKfqQGqMJCYwXPGdHmwRN1UN5MpORBkTmk2DEWWjRm0LKQ1/eV4KYiU5
# cV4GC0/8/q/X71wbrwdyH2Zyvh2mIOE+4T9mZc7H0CzZ8QdqTHd2xbTT1GSNReeY
# YlnTkWlCiELjYkInHUfwumC1pCuZMf4ITNw7KjeOGPyKDTCCBnEwggRZoAMCAQIC
# CmEJgSoAAAAAAAIwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRp
# ZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTEwMDcwMTIxMzY1NVoXDTI1MDcwMTIx
# NDY1NVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggEiMA0GCSqGSIb3
# DQEBAQUAA4IBDwAwggEKAoIBAQCpHQ28dxGKOiDs/BOX9fp/aZRrdFQQ1aUKAIKF
# ++18aEssX8XD5WHCdrc+Zitb8BVTJwQxH0EbGpUdzgkTjnxhMFmxMEQP8WCIhFRD
# DNdNuDgIs0Ldk6zWczBXJoKjRQ3Q6vVHgc2/JGAyWGBG8lhHhjKEHnRhZ5FfgVSx
# z5NMksHEpl3RYRNuKMYa+YaAu99h/EbBJx0kZxJyGiGKr0tkiVBisV39dx898Fd1
# rL2KQk1AUdEPnAY+Z3/1ZsADlkR+79BL/W7lmsqxqPJ6Kgox8NpOBpG2iAg16Hgc
# sOmZzTznL0S6p/TcZL2kAcEgCZN4zfy8wMlEXV4WnAEFTyJNAgMBAAGjggHmMIIB
# 4jAQBgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQU1WM6XIoxkPNDe3xGG8UzaFqF
# bVUwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1Ud
# EwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYD
# VR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwv
# cHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEB
# BE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9j
# ZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwgaAGA1UdIAEB/wSBlTCB
# kjCBjwYJKwYBBAGCNy4DMIGBMD0GCCsGAQUFBwIBFjFodHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vUEtJL2RvY3MvQ1BTL2RlZmF1bHQuaHRtMEAGCCsGAQUFBwICMDQe
# MiAdAEwAZQBnAGEAbABfAFAAbwBsAGkAYwB5AF8AUwB0AGEAdABlAG0AZQBuAHQA
# LiAdMA0GCSqGSIb3DQEBCwUAA4ICAQAH5ohRDeLG4Jg/gXEDPZ2joSFvs+umzPUx
# vs8F4qn++ldtGTCzwsVmyWrf9efweL3HqJ4l4/m87WtUVwgrUYJEEvu5U4zM9GAS
# inbMQEBBm9xcF/9c+V4XNZgkVkt070IQyK+/f8Z/8jd9Wj8c8pl5SpFSAK84Dxf1
# L3mBZdmptWvkx872ynoAb0swRCQiPM/tA6WWj1kpvLb9BOFwnzJKJ/1Vry/+tuWO
# M7tiX5rbV0Dp8c6ZZpCM/2pif93FSguRJuI57BlKcWOdeyFtw5yjojz6f32WapB4
# pm3S4Zz5Hfw42JT0xqUKloakvZ4argRCg7i1gJsiOCC1JeVk7Pf0v35jWSUPei45
# V3aicaoGig+JFrphpxHLmtgOR5qAxdDNp9DvfYPw4TtxCd9ddJgiCGHasFAeb73x
# 4QDf5zEHpJM692VHeOj4qEir995yfmFrb3epgcunCaw5u+zGy9iCtHLNHfS4hQEe
# gPsbiSpUObJb2sgNVZl6h3M7COaYLeqN4DMuEin1wC9UJyH3yKxO2ii4sanblrKn
# QqLJzxlBTeCG+SqaoxFmMNO7dDJL32N79ZmKLxvHIa9Zta7cRDyXUHHXodLFVeNp
# 3lfB0d4wwP3M5k37Db9dT+mdHhk4L7zPWAUu7w2gUDXa7wknHNWzfjUeCLraNtvT
# X4/edIhJEqGCAs4wggI3AgEBMIH4oYHQpIHNMIHKMQswCQYDVQQGEwJVUzELMAkG
# A1UECBMCV0ExEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9u
# cyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjozQkQ0LTRCODAtNjlD
# MzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcG
# BSsOAwIaAxUA8f35HTFqU9zwihI9ktmsPgpwMFKggYMwgYCkfjB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOGR4XMwIhgPMjAx
# OTEyMDQxNTQwMzVaGA8yMDE5MTIwNTE1NDAzNVowdzA9BgorBgEEAYRZCgQBMS8w
# LTAKAgUA4ZHhcwIBADAKAgEAAgIQoAIB/zAHAgEAAgIR2zAKAgUA4ZMy8wIBADA2
# BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIB
# AAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAJJdEswLZBU3tU9cOxF1QLqN61QQHoLf
# OMghOGfkj/5w0DPJHdoy6cL0GL+AqcWEDTnxTUpLQ+XBjLVj4xLKZQYQY3RxDasW
# 7vU4F5caypgQUezDFYoZWkmYlsMnRAXsS1neiWKGkDSE6ZtQvrNQkn1vGGaGaEEd
# cN8GZk8FgUSsMYIDDTCCAwkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAEL5Pm+j29MHdAAAAAAAQswDQYJYIZIAWUDBAIBBQCgggFKMBoG
# CSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgIJZqT48O
# I//zJF845jBE7f+2s3+Aa24sCtpI9pzr17IwgfoGCyqGSIb3DQEJEAIvMYHqMIHn
# MIHkMIG9BCA0j9DOIFM+OiSX8XAkXAXivRR0LPHA6cVU/ATAE1xziDCBmDCBgKR+
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABC+T5vo9vTB3QAAAA
# AAELMCIEIGaxKp9k22vwtngFQY2A7X7Jm6KMwHIlg3jxwzw8fXJPMA0GCSqGSIb3
# DQEBCwUABIIBAHXHvPTiGwrnx1EcFcR7wke/LDChXaS5Q53n6E1S7A/HsN5AoeOl
# OOZ1blxwH5mMQup19jDYNXardzReTmNUNnNwpu7LMC/N1SQt3aXNCmeRmMnNGmS9
# RpJlFeOz5nLynGpWIUC25WVbn0ORd/mTeoyMec1ber1x4wY1UNlndl8oTCJvmpro
# Kp/Np7TgYQxpt8+lhJqwpo29G59pJhF2rWmxDgYfYZ4jdfitB1bIfnXS5iD5dELc
# MA0gFojDtUd62LvNTLT6HD4AvyF523q524BDRTKXtfzqtQE13oPtJOKSKB0RWd9L
# U924Rm1hy4cbaHGNlgm/RQLyzoAzulkGUtg=
# SIG # End signature block
