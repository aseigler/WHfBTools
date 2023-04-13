#
# Utility.ps1
#
# Copyright 2019 Microsoft. All rights reserved.
#

<#
    ImportActiveDirectoryModuleIfNeeded
#>
function ImportActiveDirectoryModuleIfNeeded
{
    <#.SYNOPSIS
        Imports the ActiveDirectory PowerShell module if it is not already imported.

    .DESCRIPTION
        Imports the ActiveDirectory PowerShell module if it is not already imported.

    #>

    [CmdletBinding()]
    param ()

    $adModule = Get-Module -Name "ActiveDirectory"

    if (!$adModule)
    {
        Import-Module -Name ActiveDirectory -ErrorAction SilentlyContinue

        $adModule = Get-Module -Name ActiveDirectory
        if (!$adModule)
        {
            Write-Error ""
            Write-Error "The ActiveDirectory module is not available - please install the ActiveDirectory module. Refer to the following link for more information"
            Write-Error ""
            Write-Error "    https://www.microsoft.com/download/details.aspx?id=45520"
            Write-Error ""
            Exit-PSHostProcess
        }
    }
}

<#
    DoesDeviceObjectExistAD
#>
function DoesDeviceObjectExistAD
{
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory=$true
            )]
            [string]$DeviceContainerDC,
        [Parameter(
            Mandatory=$true
            )]
            [string]$DeviceContainerDomain,
        [Parameter(
            Mandatory=$true
            )]
            [string]$DeviceContainerDN,
        [Parameter(
            Mandatory=$true
            )]
            [Guid]$DeviceId,
        [Parameter(
            Mandatory=$true
            )]
            [bool]$Logging
    )

    ImportActiveDirectoryModuleIfNeeded

    # Review should this be switched to use "(msDS-DeviceID=$DeviceId)"

    $ldapFilter = "(cn=$DeviceId*)"

    $queryProperties = @(
        "msDS-DeviceID",
        "msDS-DeviceOSType",
        "msDS-DeviceOSVersion",
        "msDS-IsEnabled",
        "msDS-IsManaged"
    )

    try
    {
        $deviceObject = Get-ADObject `
            -Server $DeviceContainerDC `
            -SearchBase $DeviceContainerDN `
            -SearchScope Subtree `
            -LDAPFilter $ldapFilter `
            -Properties $queryProperties
    }
    catch
    {
        if ($Logging)
        {
            $output = "Get-ADObject failed: " + $_.Exception.ToString()
            DiagLog $output -logOnly
        }
        $deviceObject = $null
    }

    # Fail if device object didn't exist
    if (!$deviceObject)
    {
        return $false
    }

    # Fail if device object enabled property attribute is missing
    if (!$deviceObject.PropertyNames.Contains("msDS-IsEnabled"))
    {
        return $false
    }

    # Fail if device object is disabled
    if (!$deviceObject.'msDS-IsEnabled')
    {
        return $false
    }

    # Ok
    return $true
}

<#
    NormalizeADDomainName
#>
function NormalizeADDomainName
{
    <#.SYNOPSIS
        Normalizes an Active Directory domain name.

    .DESCRIPTION
        Normalizes an Active Directory domain name.Imports the ActiveDirectory PowerShell module if it is not already imported.

    .PARAMETER Domain
        The domain name to be normalized.

    #>

    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory=$true
            )]
            [string]$Domain
    )

    # Domain names come in many different forms - use DC locator to
    # normalize the input name into a fully-qualified domain name.
    $dc = Get-ADDomainController -DomainName $domain -Discover

    return $dc.Domain
}

<#
    Get-ByteArrayFromHexString
#>
function Get-ByteArrayFromHexString
{
    <#.SYNOPSIS
        Convert a hex string to a byte array.

    .DESCRIPTION
        Convert a hex string to byte array.

    .PARAMETER HexString
        The hex string to convert.

    #>

    [CmdletBinding()]
    param (

        [Parameter(
            Mandatory=$true,
            Position=0)]
            [String]$HexString
    )

    PROCESS
    {
        $i = 0;
        $bytes = @();
        while($i -lt $HexString.Length)
        {
            $chars = $HexString.SubString($i, 2);
            $b = [Convert]::ToByte($chars, 16);
            $bytes += $b;
            $i = $i+2;
        }

        Write-Output $bytes;
    }
}

<#
    Get-HexStringFromByteArray
#>
function Get-HexStringFromByteArray
{
    <#.SYNOPSIS
        Convert a byte array to a hex string.

    .DESCRIPTION
        Convert a byte array to a hex string.

    .PARAMETER Data
        The byte array to convert to hex string.

    .PARAMETER HexString
        Reference to a string that will be set to the data
        from the Data parameter.

    #>

    [CmdletBinding()]
    param (

        [Parameter(
            Mandatory=$true,
            Position=0)]
            [byte[]]$Data,

        [Parameter(
            Mandatory=$true,
            Position=1)]
            [ref]$HexString
    )

    PROCESS
    {
        $builder = New-Object System.Text.StringBuilder ($Data.Length * 2);
        foreach($b in $Data)
        {
            $builder.AppendFormat("{0:x2}", $b);
        }

        $HexString.Value = $builder.ToString().ToUpper([CultureInfo]::InvariantCulture);
    }
}

<#
    ImportMsalModuleIfNeeded
#>
function ImportMsalModuleIfNeeded
{
    [CmdletBinding()]
    param ()

    $msalModule = Get-Module -Name "MSAL.PS"

    if (!$msalModule)
    {
        Import-Module -Name MSAL.PS -ErrorAction SilentlyContinue

        $msalModule = Get-Module -Name MSAL.PS
        if (!$msalModule)
        {
            Write-Error ""
            Write-Error "The MSAL.PS  module is not available. Refer to the following link for more information:"
            Write-Error ""
            Write-Error "    https://www.powershellgallery.com/packages/MSAL.PS"
            Write-Error ""
            Write-Error "You may try to install the module using the following command:"
            Write-Error ""
            Write-Error "    Install-Module -Name MSAL.PS -RequiredVersion 4.5.1.1"
            Write-Error ""
            Exit-PSHostProcess
        }
    }
}

<#
    Initialize
#>
function InitializeAzureAD
{
    <#.SYNOPSIS
        Performs one time initialization of global variables.

    .DESCRIPTION
        If the global variables have not previously been initialized for this
        PowerShell session they are all initialized.
    #>

    [CmdletBinding()]
    param
        (
        [Parameter(Mandatory=$true)]
        $Tenant,
        [Parameter(Mandatory=$false)]
        $UserPrincipalName
        )

    ImportMsalModuleIfNeeded

    $script:tenant = $Tenant
    $script:loginHint = $UserPrincipalName
    $script:stopwatch =  [system.diagnostics.stopwatch]::StartNew()

    if ($script:Logfile -eq $null)
    {
        $script:logicalCores = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
        $timestamp = Get-TimeStamp
        $script:Logfile = "WHfBTools-$($timestamp).log"
        $script:clientId = "1b730954-1685-4b74-9bfd-dac224a7b894"
        $script:resourceUrl = "https://graph.windows.net/.default"
        $script:scope = "https://graph.windows.net/.default"
        $script:authority = "https://login.microsoftonline.com/$Tenant"
        $script:redirectUri = "urn:ietf:wg:oauth:2.0:oob"
        $script:enableLogging = 0
        $script:authReady = 0
    }

    if (Test-Path $script:Logfile)
    {
        Remove-Item $script:Logfile
    }
}

<#
    Initialize-AuthenticationAzureAD
#>
function Initialize-AuthenticationAzureAD
{
    <#.SYNOPSIS
        Authenticates to Azure Active Directory.

    .DESCRIPTION
        Prompts the user to authenticate to Azure Active Directory.

    .PARAMETER Tenant
        Specify the name of the tenant.

    .PARAMETER UserPrincipalName
        Specify this parameter to read all keys from a specific user.
    #>

    [CmdletBinding()]
    param
        (
        [Parameter(Mandatory=$true)]
        $Tenant,
        [Parameter(Mandatory=$false)]
        $UserPrincipalName
        )

    # Building Rest Api header with authorization token
    $script:AuthenticationResult = `
        Get-MsalToken -ClientId $script:clientId `
        -TenantId $Tenant `
        -Interactive `
        -Scope $script:resourceUrl `
        -LoginHint $UserPrincipalName `
        -RedirectUri $script:redirectUri

    $script:authHeader = @{
        'Content-Type'='application/json'
        'Authorization'=$script:AuthenticationResult.CreateAuthorizationHeader()
        }

    $script:loginHint = $script:AuthenticationResult.Account.Username

    $script:authReady = 1
}

<#
    MakeAzureADGraphRequest
#>
function MakeAzureADGraphRequest
{
    <#.SYNOPSIS
        Helper to manage requests to Azure Active Directory.

    .DESCRIPTION
        Sends the request to Azure Active Directory and returns the result.
        This routine handles the case of token expiration during a long running
        script by re-authenticating and repeating the failed query.

    .PARAMETER Uri
        The query Uri.

    .PARAMETER Method
        Specifies the HTTP verb for the request.

    .PARAMETER Body
        The body of the request. Typically empty unless performing a write e.g. PATCH.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Uri,
        [Parameter(Mandatory=$true)]
        $Method,
        [Parameter(Mandatory=$false)]
        $Body
        )

     # Tokens can expire so we'll detect, refresh token and retry query
     $result = $null
     $retry = 3

     do
     {
         try
         {
            $script:AuthenticationResult = `
                Get-MsalToken -ClientId $script:clientId `
                -TenantId $Tenant `
                -Scope $script:resourceUrl `
                -LoginHint $script:loginHint `
                -RedirectUri $script:redirectUri

            $script:authHeader = @{
                    'Content-Type'='application/json'
                    'Authorization'=$script:AuthenticationResult.CreateAuthorizationHeader()
                    }

            $result = Invoke-RestMethod -Uri $Uri -Headers $script:authHeader -Method $Method -Body $Body
            $retry = 0
         }
         catch
         {
            # Detect authentication issues related to expired token
            if ($_.Exception.Response.StatusCode.value__ -contains "Authentication_ExpiredToken" -or
                $_.Exception.Response.StatusCode.value__ -contains "Unauthorized")
            {
                DiagLog "Token expired, re-authenticating..." -foregroundcolor yellow

                $script:AuthenticationResult = `
                    Get-MsalToken -ClientId $script:clientId `
                    -TenantId $script:Tenant `
                    -Scope $script:resourceUrl `
                    -RedirectUri $script:redirectUri `
                    -LoginHint $script:loginHint `
                    -Silent -ForceRefresh
                #write-host $script:AuthenticationResult.AccessToken

                $script:authHeader = @{
                    'Content-Type'='application/json'
                    'Authorization'=$script:AuthenticationResult.CreateAuthorizationHeader()
                    }

                DiagLog "Success. New token expires on $script:AuthenticationResult.ExpiresOn" -foregroundcolor green
            }
            else
            {
                # Dig into the exception to get the Response details.
                # Note that value__ is not a typo.
                DiagLog "StatusCode: $_.Exception.Response.StatusCode.value__" -foregroundcolor red
                #Write-Host "StatusCode: " $_.Exception.Response.StatusCode.value__
                DiagLog "StatusDescription: $_.Exception.Response.StatusDescription" -foregroundcolor red
                DiagLog "ErrorDetails: $_.ErrorDetails" -foregroundcolor red
            }

            if ($result -ne $null)
            {
                $retry -= 1
            }
         }

     } while ($retry -gt 0)

     return $result
}

<#
    DoesDeviceObjectExistAzureAD
#>
function DoesDeviceObjectExistAzureAD
{
    <#.SYNOPSIS
        Queries Azure Active Directory to test if the specified device object exists.

    .DESCRIPTION
        Queries Azure Active Directory for the specified DeviceId in the specified Tenant
        and returns 1 if the object exists, otherwise 0.

    .PARAMETER Tenant
        Specifies the tenant to query.

    .PARAMETER DeviceId
        Specifies the DeviceId to query.
    #>

    [CmdletBinding()]
    param(
    [Parameter(ValueFromPipeline=$true)]
    [psObject]$KeyMetadata,
    [Parameter(Mandatory=$true)]
    $AuthorizationHeader
    )
    Begin
    {
        $script:authReady = 0
    }
    Process
    {
        $deviceId = $KeyMetadata.deviceId
        $tenant = $KeyMetadata.tenant

        $uri = "https://graph.windows.net/$tenant/devices()?`$filter=deviceId%20eq%20guid'$deviceId'&api-version=1.6-internal"

        # Initial query for first page of results
        $query = Invoke-RestMethod -Uri $uri -Headers $AuthorizationHeader -Method Get

        $orphaned = $false
        if ($query.value.count -ne 1)
        {
            $orphaned = $true
        }

        $result = $KeyMetadata
        $result | Add-Member -MemberType NoteProperty -Name Orphaned -Value $orphaned

        Write-Output $result
    }
}

<#
    Get-FreshTokenIfNeeded
#>
function Get-FreshTokenIfNeeded
{
    <#.SYNOPSIS
        Re-authenticates if token is nearing expiry.

    .DESCRIPTION
        Checks current token and re-authenticates if nearing expiry. If refreshed
        so is the authorization header cache.
    #>
    $tokenExpiry = $script:AuthenticationResult.ExpiresOn
    $difference = $tokenExpiry.Subtract([System.DateTime]::UtcNow)
    $minutesBetween = $difference.minutes

    # If less than 30 minutes left on token we'll refresh
    if ($minutesBetween -lt 30)
    {
        $script:AuthenticationResult = `
            Get-MsalToken -ClientId $script:clientId `
            -TenantId $script:Tenant `
            -Scope $script:resourceUrl `
            -RedirectUri $script:redirectUri `
            -LoginHint $script:loginHint `
            -Silent -ForceRefresh

        $script:authHeader = @{
            'Content-Type'='application/json'
            'Authorization'=$script:AuthenticationResult.CreateAuthorizationHeader()
            }
    }
}

<#
    DiagLog
#>
function DiagLog
{
    <#.SYNOPSIS
        Emits a log statement to a log file log and optionally to the console.

    .DESCRIPTION
        Emits a timestamped log statement to a log file and optionally to the console.

    .PARAMETER output
        Specifies the first string parameter comprising the log entry.

    .PARAMETER varArgs
        Specifies the variable number of remaining string arguments comprising a log entry.

    .PARAMETER foregroundcolor
        Specifies an optional override to console color when emitting log entries to the console.

    .PARAMETER logOnly
        Specifies an optional switch to suppress logging to console and only log to log file.
    #>

    param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$output,
    [Parameter(Mandatory=$false, ValueFromRemainingArguments=$true, Position=1)]
    [string[]]$varArgs,
    [Parameter(Mandatory=$false)]
    $foregroundcolor,
    [Parameter(Mandatory=$false)]
    [Switch]
    $logOnly = $false
    )

    if ($foregroundcolor -eq $null)
    {
        $foregroundcolor = "White"
    }

    $allOutput = $output
    foreach ($arg in $varArgs)
    {
        $allOutput += $arg
    }

    if ($logOnly -ne $true)
    {
        write-host $allOutput -foregroundcolor $foregroundcolor
    }

    LogWrite $output
}

<#
    Get-TimeStamp
#>
function Get-TimeStamp
{
    <#.SYNOPSIS
        Returns a time stamp of the current time.

    .DESCRIPTION
        Returns a time stamp of the current time.
    #>
    return "{0:MM-dd-yy}-{0:HH:mm:ss}" -f (Get-Date) | ForEach-Object { $_ -replace ":", "." }
}

<#
    LogWrite
#>
function LogWrite
{
    <#.SYNOPSIS
        Logs a specified string to a log with a time stamp prefix.

    .DESCRIPTION
        Logs a specified string to a log with a time stamp prefix.

    .PARAMETER logString
        Specifies the string to log to a file.
    #>

   Param (
   [string]$logstring
   )

   $logLine = "$(Get-TimeStamp) $logstring"

   if ($script:Logfile)
   {
       Add-Content $script:Logfile -value $logLine
   }
}

$script:AddedRocaTestCode = $false

$script:ROCACheckerCode = @"
    using System;
    using System.Diagnostics;
    using System.Numerics;
    using System.Text;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;

    //
    // For more information on the ROCA vulnerability, please see:
    //
    //   https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-15361
    //
    public static class ROCAChecker
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct BCRYPT_RSAKEY_BLOB
        {
            public uint Magic;
            public uint BitLength;
            public uint cbPublicExp;
            public uint cbModulus;
            public uint cbPrime1;
            public uint cbPrime2;
        }

        /// <summary>
        /// RSA public key magic header value
        /// </summary>
        private const uint BCRYPT_RSAPUBLIC_MAGIC = 0x31415352;

        public static bool
        TestRsaPublicKey(
            byte[] bcryptRsaPublicKey
            )
        {
            byte[] modulus;
            byte[] exponent;

            ExtractModulusAndExponent(
                bcryptRsaPublicKey,
                out modulus,
                out exponent);

            byte[] littleEndianModulus =
                BigEndianToLittleEndianBytes(modulus);

            return TestModulus(littleEndianModulus);
        }

        /// <summary>
        /// Extracts the modulus and exponent from a RSA public key
        /// </summary>
        /// <param name="bcryptRsaPublicKey">Public key</param>
        /// <param name="modulus">Modulus on success</param>
        /// <param name="exponent">Exponent on success</param>
        private static void
        ExtractModulusAndExponent(
            byte[] bcryptRsaPublicKey,
            out byte[] modulus,
            out byte[] exponent
            )
        {
            if (bcryptRsaPublicKey == null)
            {
                throw new System.ArgumentNullException("bcryptRsaPublicKey");
            }

            int headerSize = Marshal.SizeOf(typeof(BCRYPT_RSAKEY_BLOB));

            if (bcryptRsaPublicKey.Length < headerSize)
            {
                // Invalid format - buffer is too small for header
                throw new System.ArgumentException(
                    "Buffer is too small for header");
            }

            // Convert data from the buffer into header structure
            byte[] header = new byte[headerSize];

            Array.Copy(bcryptRsaPublicKey, header, headerSize);

            GCHandle handle = new GCHandle();
            BCRYPT_RSAKEY_BLOB bcryptBlobHeader;

            try
            {
                handle = GCHandle.Alloc(
                    header,
                    GCHandleType.Pinned);

                bcryptBlobHeader =
                    (BCRYPT_RSAKEY_BLOB)Marshal.PtrToStructure(
                        handle.AddrOfPinnedObject(),
                        typeof(BCRYPT_RSAKEY_BLOB));
            }
            finally
            {
                if (handle.IsAllocated)
                {
                    handle.Free();
                }
            }

            long length = bcryptBlobHeader.cbPublicExp + bcryptBlobHeader.cbModulus + headerSize;

            // Check signature and sizes
            if (bcryptBlobHeader.Magic != BCRYPT_RSAPUBLIC_MAGIC ||
                bcryptBlobHeader.cbPublicExp == 0 ||
                bcryptBlobHeader.cbModulus == 0 ||
                length != bcryptRsaPublicKey.Length)
            {
                // Invalid format - buffer is not of the right size or header magic is wrong or exponent/modulus size is 0
                throw new System.ArgumentException("bcryptRsaPublicKey");
            }

            // Extract modulus and exponent
            modulus = new byte[bcryptBlobHeader.cbModulus];
            exponent = new byte[bcryptBlobHeader.cbPublicExp];

            Array.Copy(bcryptRsaPublicKey, headerSize, exponent, 0, bcryptBlobHeader.cbPublicExp);
            Array.Copy(bcryptRsaPublicKey, headerSize + bcryptBlobHeader.cbPublicExp, modulus, 0, bcryptBlobHeader.cbModulus);

            return;
        }

        /// <summary>
        /// Method converts big endian byte array to little endian byte array
        /// </summary>
        /// <param name="bigEndianByteArr">Big endian byte array to convert</param>
        /// <returns>Little endian byte order of input</returns>
        public static byte[]
        BigEndianToLittleEndianBytes(
            byte[] bigEndianByteArr
            )
        {
            var hex = new StringBuilder(bigEndianByteArr.Length * 2);
            foreach (byte b in bigEndianByteArr)
            {
                hex.AppendFormat("{0:x2}", b);
            }

            string hexString = hex.ToString();
            hexString = hexString.Trim().ToLower();
            if (hexString.Length % 2 != 0)
            {
                hexString = "0" + hexString;
            }

            if (hexString.Length == 0)
            {
                throw new FormatException("Can't parse hex string");
            }

            var r = new byte[hexString.Length / 2];

            for (int i = 0; i < hexString.Length; i += 2)
            {
                r[(hexString.Length / 2) - (i / 2) - 1] = (byte)((HexDigitToByte(hexString[i]) << 4) | HexDigitToByte(hexString[i + 1]));
            }

            return r;
        }

        /// <summary>
        /// Convert hex digit to a byte
        /// </summary>
        /// <param name="c">Hex digit</param>
        /// <returns>Byte value</returns>
        private static byte
        HexDigitToByte(
            char c
            )
        {
            if (c >= '0' && c <= '9')
                return (byte) (c - '0');
            else if (c >= 'a' && c <= 'f')
                return (byte) (c - 'a' + 10);
            else if (c >= 'A' && c <= 'F')
                return (byte) (c - 'A' + 10);
            else
                throw new FormatException(
                    string.Format("Unable to parse hex digit: {0}", c));
        }

        /// <summary>
        /// Tests whether provided key is affected or not. Affected keys are
        /// considered vulnerable.
        /// </summary>
        /// <param name="littleEndianUnsignedBytes">Key as an array of bytes in
        /// little endian format (least significant byte first)</param>
        /// <returns>true if effects, false otherwise</returns>
        private static bool
        TestModulus(
            byte[] littleEndianUnsignedBytes
            )
        {
            if (littleEndianUnsignedBytes[littleEndianUnsignedBytes.Length - 1] >= 0x80)
            {
                // Append one more 0 big endian byte to keep the BigInteger unsigned
                var k = new byte[littleEndianUnsignedBytes.Length + 1];
                Array.Copy(littleEndianUnsignedBytes, k, littleEndianUnsignedBytes.Length);
                k[k.Length - 1] = 0;
                littleEndianUnsignedBytes = k;
            }

            var modulus = new BigInteger(littleEndianUnsignedBytes);

            // Vulnerable keys have the modulus of the form 65537^(r+s) (mod P)
            // where P is the product of the first N primes
            // By the Chinese Remainder Theorem we know this discrete logarithm
            // has a solution iff it has a solution for every factor of P
            // Per Infineon, it is sufficient to check against the first 39 primes

            // For each prime p in the first 39 primes (except 2)
            for (uint i = 0; i < primes.Length; i++)
            {
                // Calculate m (mod p)
                uint rem = (uint) (modulus%primes[i]);

                // Check against the precomputed table to see if m (mod p) has
                // no solution to the partial discrete logarithm.
                // If it has no solution to any partial discrete log problem,
                // it has no solution to the full discrete log problem, and this
                // key is not vulnerable.
                if ((prints[i, rem/8] & (1u << (int) (rem%8))) == 0)
                {
                    // not affected
                    return false;
                }
            }

            // affected
            return true;
        }

        private static uint[] primes = new uint[]
        {
            331,    // filters 1:165, 44 bytes, signal/byte = 0.167
            673,    // filters 1:112, 87 bytes, signal/byte = 0.078
            241,    // filters 1: 40, 33 bytes, signal/byte = 0.161
            523,    // filters 1: 29, 68 bytes, signal/byte = 0.071
            461,    // filters 1: 23, 60 bytes, signal/byte = 0.075
             97,    // filters 1: 16, 15 bytes, signal/byte = 0.267
            257,    // filters 1: 16, 35 bytes, signal/byte = 0.114
            239,    // filters 1: 14, 32 bytes, signal/byte = 0.119
             37,    // filters 1: 12,  7 bytes, signal/byte = 0.512
            229,    // filters 1: 12, 31 bytes, signal/byte = 0.116
            349,    // filters 1: 12, 46 bytes, signal/byte = 0.078
            233,    // filters 1:  8, 32 bytes, signal/byte = 0.094
            281,    // filters 1:  8, 38 bytes, signal/byte = 0.079
            353,    // filters 1:  8, 47 bytes, signal/byte = 0.064
             79,    // filters 1:  6, 12 bytes, signal/byte = 0.215
             11,    // filters 1:  5,  4 bytes, signal/byte = 0.580
            181,    // filters 1:  4, 25 bytes, signal/byte = 0.080
            197,    // filters 1:  4, 27 bytes, signal/byte = 0.074
             61,    // filters 1:  3, 10 bytes, signal/byte = 0.158
             73,    // filters 1:  3, 12 bytes, signal/byte = 0.132
            127,    // filters 1:  3, 18 bytes, signal/byte = 0.088
            151,    // filters 1:  3, 21 bytes, signal/byte = 0.075
             13,    // filters 1:  2,  4 bytes, signal/byte = 0.250
             17,    // filters 1:  2,  5 bytes, signal/byte = 0.200
             19,    // filters 1:  2,  5 bytes, signal/byte = 0.200
             53,    // filters 1:  2,  9 bytes, signal/byte = 0.111
             71,    // filters 1:  2, 11 bytes, signal/byte = 0.091
            103,    // filters 1:  2, 15 bytes, signal/byte = 0.067
        };

        private static byte[,] prints = new byte[28, 85]
        {
            { 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, },
            { 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, },
            { 0x02, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, },
            { 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x80, 0x30, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x20, 0x00, 0x00, 0x00, 0xc0, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, },
            { 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x10, 0x00, 0x08, 0x00, 0x21, 0x00, 0x40, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x21, 0x00, 0x04, 0x00, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, },
            { 0x02, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, },
            { 0x16, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x02, 0xa2, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, },
            { 0x42, 0x00, 0x40, 0x00, 0x10, 0x01, 0x08, 0x00, 0x88, 0x08, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x08, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, },
            { 0x02, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, },
            { 0x02, 0x00, 0x03, 0x08, 0x00, 0x1c, 0x20, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0x08, 0x40, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, },
            { 0x02, 0x00, 0x00, 0x80, 0x00, 0x02, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x00, 0x40, 0x40, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x11, 0x04, 0x00, 0x02, 0x82, 0x20, 0x04, 0x21, 0x02, 0x20, 0x01, 0x03, 0x04, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, },
            { 0x16, 0x01, 0x89, 0x00, 0x61, 0x40, 0x08, 0x80, 0x81, 0x14, 0x00, 0x10, 0x40, 0x00, 0x20, 0x40, 0x81, 0x40, 0x10, 0x01, 0x00, 0x80, 0x00, 0x01, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, },
            { 0x12, 0x00, 0x01, 0x00, 0x08, 0x00, 0x04, 0x8c, 0x01, 0x80, 0x60, 0x04, 0x24, 0xa0, 0x00, 0x08, 0x00, 0x10, 0x00, 0x0a, 0x2c, 0x00, 0x20, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00, 0x51, 0x00, 0x12, 0x01, 0x00, 0x82, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, },
            { 0x12, 0x00, 0x41, 0x00, 0x0c, 0x04, 0x00, 0x04, 0x01, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x06, 0x88, 0x11, 0x04, 0x00, 0x44, 0x09, 0x40, 0x8a, 0x00, 0x80, 0x20, 0x46, 0x80, 0x01, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x82, 0x00, 0x80, 0xc0, 0x00, 0x08, 0x02, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, },
            { 0x02, 0x05, 0x64, 0x00, 0x40, 0x40, 0x10, 0x40, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, },
            { 0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, },
            { 0x2a, 0xe2, 0x01, 0x2a, 0xc4, 0x3c, 0x01, 0x48, 0x42, 0x0a, 0x87, 0x00, 0x40, 0x00, 0x24, 0x62, 0x92, 0x00, 0x13, 0x00, 0x02, 0x06, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, },
            { 0x02, 0x00, 0x81, 0x31, 0x34, 0x05, 0x6a, 0xb8, 0x40, 0x10, 0x22, 0x05, 0x30, 0x03, 0x04, 0x00, 0xb0, 0x40, 0x40, 0x54, 0x10, 0x98, 0x44, 0xd8, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, },
            { 0x0a, 0x0b, 0x90, 0x19, 0x66, 0x02, 0x34, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, },
            { 0x8a, 0x07, 0x62, 0x49, 0x00, 0x48, 0x1a, 0x81, 0x47, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, },
            { 0x36, 0x05, 0x19, 0x0a, 0x43, 0x81, 0x4c, 0xa0, 0x05, 0x32, 0x81, 0xc2, 0x50, 0x98, 0xa0, 0x6c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, },
            { 0x0a, 0x03, 0x18, 0x3d, 0x00, 0x12, 0x24, 0x1a, 0x5b, 0xc3, 0xda, 0x58, 0x24, 0x48, 0x00, 0xbc, 0x18, 0xc0, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, },
            { 0x1a, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, },
            { 0x16, 0xa3, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, },
            { 0xf2, 0x0a, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, },
            { 0xd2, 0xae, 0x03, 0x33, 0x70, 0xdd, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, },
            { 0x7e, 0x97, 0x1d, 0x6b, 0x71, 0x29, 0x47, 0x16, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, },
            { 0x96, 0xe3, 0x8f, 0x76, 0x57, 0x42, 0x96, 0xbd, 0x15, 0x91, 0x0e, 0x38, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, },
        };
    }
"@

<#
    Probe-KeyForRocaVulnerability
#>
function Probe-KeyForRocaVulnerability
{
    <#.SYNOPSIS
        Probes a Windows Hello for Business (WHfB) key to determine if it is
        subject to the "Return of Coppersmith's attack" (ROCA) vulnerability.

    .DESCRIPTION
        Probes the keyBytes data from a Windows Hello for Business (WHfB) key to determine
        if it is subject to the "Return of Coppersmith's attack" (ROCA) vulnerability.

        For more information on the ROCA vulnerability, please see:

        https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-15361

        https://en.wikipedia.org/wiki/ROCA_vulnerability

    .PARAMETER keyBytes
        Specifies the Windows Hello for Business (WHfB) key data to be probed.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$keyBytes
        )

    if (!$script:AddedRocaTestCode)
    {
        Add-Type -ReferencedAssemblies @("System", "System.Numerics", "System.Diagnostics.Debug",  "System.Runtime", "System.Runtime.InteropServices", "System.Security.Cryptography.Algorithms") -TypeDefinition $script:ROCACheckerCode
        $script:AddedRocaTestCode = $true
    }

    # Check whether key is ROCA-vulnerable
    try
    {
        return [ROCAChecker]::TestRsaPublicKey([byte[]]$keyBytes)
    }
    catch
    {
        DiagLog "If keys are invalid (garbage or test values) this check will also fail" -logOnly
    }

    return $false
}

# SIG # Begin signature block
# MIIjhgYJKoZIhvcNAQcCoIIjdzCCI3MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA602e7RgxRIsJD
# LFG02b3fk+VWYLXUwRhU0AhJLWpUJaCCDYEwggX/MIID56ADAgECAhMzAAABUZ6N
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
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgFKiveT/L
# Su/lClVh6KAck8GYRKQuBfPE4VgaeNOC8hkwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQAjDUhraNgRjTfbaBvV/rf6IL9MGIB8P1g+c1WKYThz
# YmXLU3kK9y9tW6dmRDOnI6NevZEXpdsRB9ZxSO7LrCraGCityRiG5UpLza3cS8ju
# s/qbZaq13wPHj5C/AtpVjepL6I7b209girvbr92i1a2d51WP1HZ1CKwvQa6eeuHO
# 5TNA856XYYBeXtosmrnHqpzWhVRpOcAOfcaceB42CWUpzNIPD4XBhSIV7s86YQv1
# ZZGM+miCmT6oAWjvgtbJYbu5zfTHIOvjApU5xCKbZ+wuqwPxozSRZfL5mjCRSV+u
# JfwIki+2TRClN7EflqhF70H68TuIXOuVBi9ZsntTC+UBoYIS5TCCEuEGCisGAQQB
# gjcDAwExghLRMIISzQYJKoZIhvcNAQcCoIISvjCCEroCAQMxDzANBglghkgBZQME
# AgEFADCCAVEGCyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIDVG7EeuE1arEhpUu/xIh8zVQ0n/WkeqPsl+uSw8
# eGbHAgZdtfNcnjYYEzIwMTkxMjA0MTQxMjEzLjExNFowBIACAfSggdCkgc0wgcox
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
# CSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgRYH6W7jV
# y4B46FBUmYkO1QfNcEZe1/ypYZOrwFJYybUwgfoGCyqGSIb3DQEJEAIvMYHqMIHn
# MIHkMIG9BCA0j9DOIFM+OiSX8XAkXAXivRR0LPHA6cVU/ATAE1xziDCBmDCBgKR+
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABC+T5vo9vTB3QAAAA
# AAELMCIEIGaxKp9k22vwtngFQY2A7X7Jm6KMwHIlg3jxwzw8fXJPMA0GCSqGSIb3
# DQEBCwUABIIBAC6pEbRy9ZpOGAFWS7BZ58Yy+OlZJk2vI9qLgLbll8Xmk44to8D5
# bT5u4WSHCj+Eo4ie9RR37nYo3GhKkf1codCb7KhoO0BFUqFGazK0EQPobije/3Iu
# 3V2gVAH2biNX8c6aO1kUDw1YlES1+Wl1Q5xB1Xndq1DPAs+UL9nSBQuL/NF+86PI
# oHTsEWPengGRPRXU9ffJfGpINmpUVwtSI0icbx4cc4Or8/wtHn751Y4b/WVFyNID
# 1hBCd3gTHoyqgGIBPlU2lSGKtcpd2Rmt/+5L2MwbyoKOS6xMw7guyW0h1QfYhOAx
# kn3M/I8ZY++PsxlAYtqWnDK3BBPX3UWLJFQ=
# SIG # End signature block
