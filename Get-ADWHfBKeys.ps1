#
# Get-ADWHfBKeys.ps1
#
# Copyright 2019 Microsoft. All rights reserved.
#

<#
    Get-ADWHfBKeys
#>
function Get-ADWHfBKeys
{
    <#.SYNOPSIS
        Reads Windows Hello for Business (WHfB) keys from Active Directory.

    .DESCRIPTION
        Reads Windows Hello for Business (WHfB) keys from Active Directory. Two modes
        are supported:  read all keys from a specific AD domain, or all keys from a
        specific AD user. Any keys found are checked to see if they are vulnerable to
        the ROCA vulnerability. Any keys found are also checked to see if they are
        linked to a valid device object in the forest; any key that is not linked to
        a valid device object is deemed "orphaned".

        This cmdlet uses the current user to authenticate to Active Directory. To ensure
        the most accurate results, a privileged account such as a Domain Admin should be
        used to run this cmdlet. Lesser-privileged accounts may not have sufficient
        permissions to query users and/or their WHfB keys.

    .PARAMETER Domain
        Specify this parameter to read all keys from a specific domain, or a specific
        domain\user combination.

    .PARAMETER SamAccountName
        Specify this parameter to read all keys from a specific user.

    .PARAMETER SkipCheckForOrphanedKeys
        Optional.  This switch is used to suppress checking each key to see if it is linked to a valid
        device object. This option requires additional network queries to check therefore increasing
        run time of the command.

    .PARAMETER Report
        Optional. This switch will cause a summary report to be printed to console and log.

    .PARAMETER Logging
        Optional. This switch will enable additional diagnostic logging to a file.

    .INPUTS
        None. You cannot pipe objects to Get-ADWHfBKeys.

    .OUTPUTS
        Custom type representing WHfB key. Get-ADWHfBKeys returns zero or more based on results.

    .EXAMPLE
        PS C:\>Get-ADWHfBKeys -Domain contoso.com

        Scan the contoso.com AD domain for all WHfB keys and display summary report.

    .EXAMPLE
        PS C:\>Get-ADWHfBKeys -Report -Domain contoso.com -SkipCheckForOrphanedKeys

        Scan the contoso.com AD domain for all WHfB keys, without performing orphaned
        key checks, and display summary report.

    .EXAMPLE
        PS C:\>Get-ADWHfBKeys -Report -Domain contoso.com -SamAccountName TestUser

        Scan the contoso.com\TestUser AD user account for its WHfB keys and display summary report.

    .EXAMPLE
        PS C:\>Get-ADWHfBKeys -Logging -Report -Domain contoso.com | Export-Csv "contoso_whfb_keys.csv"

        Scan the contoso.com AD domain for all WHfB keys, pipe the results to a CSV file, emit diagnostic
        logging to file, and display summary report.

    #>

    [CmdletBinding()]
    param (
        [CmdletBinding()]
        [Parameter(
            Mandatory=$true,
            ParameterSetName='DomainUser'
            )]
        [Parameter(
            Mandatory=$true,
            ParameterSetName='Domain'
            )]
            [string]$Domain,
        [Parameter(
            Mandatory=$true,
            ParameterSetName='DomainUser'
            )]
            [string]$SamAccountName,
        [Parameter(
            Mandatory=$false
            )]
            [Switch]$SkipCheckForOrphanedKeys,
        [Parameter(
            Mandatory=$false
            )]
            [Switch]$Report,
        [Parameter(
            Mandatory=$false
            )]
            [Switch]$Logging
    )

    Begin
    {
        ImportActiveDirectoryModuleIfNeeded

        if ($Logging)
        {
            $timestamp = Get-TimeStamp
            $script:Logfile = "WHfBTools_$($timestamp).log"

            DiagLog "Get-ADWHfBKeys starting" -logOnly
        }
        else
        {
            $script:Logfile = $null
        }

        # Reset summary report counters
        $script:totalADUsers = 0
        $script:totalADUsersWithWHfBKeys = 0
        $script:totalADWHfBKeys = 0
        $script:totalADRocaVulnerableKeys = 0
        $script:totalADOrphanedKeys = 0

        $script:stopwatch =  [System.Diagnostics.Stopwatch]::StartNew()
    }
    Process
    {
        $domainController = Get-ADDomainController -Domain $Domain -Discover

        if (!$SkipCheckForOrphanedKeys)
        {
            $deviceContainerInfo = Get-ADDeviceRegistrationServiceContainerInfo -Domain $domainController.Domain

            if ($deviceContainerInfo)
            {
                $deviceContainerDC = Get-ADDomainController -Domain $deviceContainerInfo.DeviceContainerDomain -Discover

                $deviceContainerInfo = [PSCustomObject]@{
                    DeviceContainerDC = $deviceContainerDC.Name
                    DeviceContainerDomain = $deviceContainerInfo.DeviceContainerDomain
                    DeviceContainerDN = $deviceContainerInfo.DeviceContainerDN
                }

                if ($Logging)
                {
                    $output = "Device container domain: " + $deviceContainerInfo.DeviceContainerDomain
                    DiagLog $output -logOnly
                    $output = "Device container DN: " + $deviceContainerInfo.DeviceContainerDN
                    DiagLog $output -logOnly
                    $output = "Device container domain controller: " + $deviceContainerInfo.DeviceContainerDC
                    DiagLog $output -logOnly
                }
            }
            else
            {
                DiagLog "Error: failed to locate device container - forest may not be correctly configured." -foregroundcolor Yellow
                Exit-PSHostProcess
            }
        }
        else
        {
            if ($Logging)
            {
                $output = "-SkipCheckForOrphanedKey was specified, not checking for orphaned keys"
                DiagLog $output -logOnly
            }
            $deviceContainerInfo = $null
        }

        if ($SamAccountName)
        {
            $LDAPFilter = "(samAccountName=$SamAccountName)"
        }
        else
        {
            $LDAPFilter = "(objectClass=*)"
        }

        if ($Logging)
        {
            $output = "Ready to start query"
            DiagLog $output -logOnly
            $output = "Domain controller: " + $domainController.Name
            DiagLog $output -logOnly
            $output = "LDAP search filter: " + $LDAPFilter
            DiagLog $output -logOnly
        }

        Update-GetADWHfBKeysProgress $SkipCheckForOrphanedKeys

        # Start the query pipeline
        Get-ADUser `
            -Server $domainController.Name `
            -LDAPFilter $LDAPFilter `
            -Properties "msds-KeyCredentialLink" |
                Get-ADWHfBKeysFromADUser -Domain $domainController.Domain -SkipCheckForOrphanedKeys $SkipCheckForOrphanedKeys -DeviceContainerInfo $deviceContainerInfo -Logging $Logging
    }
    End
    {
        if ($Report)
        {
            DiagLog "Report of summary results:" -foregroundcolor yellow
            DiagLog "Users scanned: $script:totalADUsers" -foregroundcolor yellow
            DiagLog "Users with WHfB keys: $script:totalADUsersWithWHfBKeys" -foregroundcolor yellow
            DiagLog "Total WHfB Keys: $script:totalADWHfBKeys" -foregroundcolor yellow
            DiagLog "Total ROCA vulnerable keys: $script:totalADRocaVulnerableKeys" -foregroundcolor yellow
            if (!$SkipCheckForOrphanedKeys)
            {
                DiagLog "Total orphaned keys: $script:totalADOrphanedKeys" -foregroundcolor yellow
            }
        }

        if ($Logging)
        {
            DiagLog "Get-ADWHfBKeys ending" -logOnly
        }
    }
}

<#
    Update-GetADWHfBKeysProgress
#>
function Update-GetADWHfBKeysProgress
{
    <#.SYNOPSIS
        Updates the progress bar with current status.

    .DESCRIPTION
        Updates the progress bar with current status.

    .PARAMETER SkipCheckForOrphanedKeys
        Specifies whether skip-orphaned-key-checks was specified by the user.

    #>

    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory=$true
            )]
            [bool]$SkipCheckForOrphanedKeys
    )

    $activity = "Get-ADWHfBKeys  -  " + $script:stopwatch.Elapsed.ToString("dd\:hh\:mm\:ss")

    $progressDescription = "Scanning Active Directory and Compiling Statistics"

    $progressResults = "$script:totalADUsers users scanned | $script:totalADWHfBKeys WHfB keys found | $script:totalADRocaVulnerableKeys ROCA vulnerable keys"
    if (!$SkipCheckForOrphanedKeys)
    {
        $progressResults = $progressResults + " | $script:totalADOrphanedKeys orphaned keys"
    }

    Write-Progress -Id 1 -Activity $activity -Status $progressDescription -PercentComplete -1 -CurrentOperation $progressResults
}

<#
    Get-ADWHfBKeysFromADUser
#>
function Get-ADWHfBKeysFromADUser
{
    <#.SYNOPSIS
        Reads WHfB keys from the specified Active Directory user object.

    .DESCRIPTION
        Reads WHfB keys from the specified Active Directory user object.

    .PARAMETER User
        A user object returned from the Get-ADUser PowerShell cmdlet.

    .PARAMETER Domain
        The AD domain that contains User.

    .PARAMETER SkipCheckForOrphanedKeys
        This switch is used to suppress checking each key to see if it is linked to a valid
        device object. This option requires additional network queries to check therefore
        increasing run time of the command.

    .PARAMETER DeviceContainerInfo
        PSObject containing information about the device container in the current forest as
        as well which domain controller in that domain to use for queries.

    .PARAMETER Logging
        This switch will enable additional diagnostic logging to a file.

    .INPUTS
        AD user object returned from Get-ADUser.

    .OUTPUTS
        Array of ADWHfBKey objects from the user object, or $null if none exist.

    #>

    [CmdletBinding()]
    param (
        [Parameter(
            ValueFromPipeline=$true
            )]
            [PSObject]$User,
        [Parameter(
            Mandatory=$false
            )]
            [string]$Domain,
        [Parameter(
            Mandatory=$false
            )]
            [bool]$SkipCheckForOrphanedKeys,
        [Parameter(
            Mandatory=$false
            )]
            [PSObject]$DeviceContainerInfo,
        [Parameter(
            Mandatory=$false
            )]
            [bool]$Logging
    )

    Begin
    {
    }
    Process
    {
        # Increment total # of users seen
        $script:totalADUsers += 1

        # Noop if user does not have any keys
        if (!$User.PropertyNames.Contains("msds-KeyCredentialLink"))
        {
            return
        }

        # Increment total # of users with WHfB keys
        $script:totalADUsersWithWHfBKeys += 1

        $rawKeys = $User.'msds-KeyCredentialLink'

        foreach ($rawKey in $rawKeys)
        {
            # Parse the raw value
            $key = Get-ADWHfBKeyFromValue -RawValue $rawKey

            # Parsing failures result in a null result. Sometimes seen due
            # to malformed or test key values.
            if (!$key)
            {
                if ($Logging)
                {
                    $output = "Unable to parse key from user '$User.SamAccountName' $User.DistinguishedName"
                    DiagLog $output -logOnly
                    $output = "Unparseable key raw value: " + $rawKey
                    DiagLog $output -logOnly
                }
                continue;
            }

            if ($key.KeyUsage -ne "NGC")
            {
                # Currently we are only focused on NGC keys which are intended for
                # authentication. Ignore all other key types for now.
                $output = "Ignoring non-NGC key ($key.KeyUsage) from user $User.SamAccountName $User.DistinguishedName"
                DiagLog $output -logOnly
                $output = "Ignored key raw value: " + $rawKey
                DiagLog $output -logOnly
                continue;
            }

            # Increment total # of WHfB keys seen
            $script:totalADWHfBKeys += 1

            # Add user identifying data to the key object
            $key.UserDomain = $Domain
            $key.UserSamAccountName = $User.SamAccountName
            $key.UserDistinguishedName = $User.DistinguishedName

            # Do post-parsing key validation checks

            # Always check whether key is ROCA-vulnerable
            $rawKeyBytes = [System.Convert]::FromBase64String($key.KeyMaterial);
            $key.ROCAVulnerable = Probe-KeyForRocaVulnerability $rawKeyBytes

            if ($key.ROCAVulnerable)
            {
                # Increment total # of ROCA-vulnerable WHfB keys
                $script:totalADRocaVulnerableKeys += 1
            }

            # Optionally check whether key is soft-linked to a device object
            if (!$SkipCheckForOrphanedKeys)
            {
                if ($deviceContainerInfo)
                {
                    $hasValidDeviceObject = DoesDeviceObjectExistAD `
                        $DeviceContainerInfo.DeviceContainerDC `
                        $DeviceContainerInfo.DeviceContainerDomain `
                        $DeviceContainerInfo.DeviceContainerDN `
                        $key.KeyDeviceId `
                        $Logging

                    $key.OrphanedKey = !$hasValidDeviceObject
                }
                else
                {
                    $key.OrphanedKey = $true
                }

                if ($key.OrphanedKey)
                {
                    $script:totalADOrphanedKeys += 1
                }
            }
            else
            {
                $key.OrphanedKey = "Not checked"
            }

            Update-GetADWHfBKeysProgress $SkipCheckForOrphanedKeys

            # Write keys to the pipeline as we finish them
            Write-Output $key
        }
    }
    End
    {
    }
}

# SIG # Begin signature block
# MIIjhQYJKoZIhvcNAQcCoIIjdjCCI3ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA2vcDG509RJfx7
# mNi/k/gg6CudpJnXPgvxRG3QFmDz0KCCDYEwggX/MIID56ADAgECAhMzAAABUZ6N
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVWjCCFVYCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAVGejY9AcaMOQQAAAAABUTAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgqbTb3gCu
# 2bHXsX0Y0YpDLKu8R0NBz5i4mZf9C3OURDUwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQBMrC/u3tpldRn+ExiMtCMjITI3Yt0g46IZZAAIardl
# F2la5i7yh88CDaFKFmApViVuBDZDGLxHlGcPrNuCz99HHQF+XZAsjZXBIVPIih/c
# Xjz1JWAUEdU9PDFd2u60nH9vY38VnvxrxlAPC0Tcz/wUZSeP61rRtoQgn2uL4Gml
# MYGIzpILrvSBJi4bgc5mbRseAC9J+5fLeptevK0DGBoK84Mf5DPXcgZTnWGS+30t
# vuZbEo+43/ncQac/68ESUlYxctTLLVuOQ12YKW8gmiggHxdNgGA/WqrBZfzuJNry
# NiUktCWbgqhgqLEgjx0313bWloAnyaOuEd/I/FlXQpjioYIS5DCCEuAGCisGAQQB
# gjcDAwExghLQMIISzAYJKoZIhvcNAQcCoIISvTCCErkCAQMxDzANBglghkgBZQME
# AgEFADCCAVAGCyqGSIb3DQEJEAEEoIIBPwSCATswggE3AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIEWBBs67mJnZjQb608k0clpLa34SJ4OwrIGe/C6r
# p4sxAgZdtfNcnjMYEjIwMTkxMjA0MTQxMjEzLjA3WjAEgAIB9KCB0KSBzTCByjEL
# MAkGA1UEBhMCVVMxCzAJBgNVBAgTAldBMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046M0JENC00QjgwLTY5QzMxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2Wggg48MIIE8TCCA9mgAwIBAgITMwAAAQvk+b6Pb0wd0AAAAAABCzAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0x
# OTEwMjMyMzE5MTVaFw0yMTAxMjEyMzE5MTVaMIHKMQswCQYDVQQGEwJVUzELMAkG
# A1UECBMCV0ExEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9u
# cyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjozQkQ0LTRCODAtNjlD
# MzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCASIwDQYJ
# KoZIhvcNAQEBBQADggEPADCCAQoCggEBAJcC1Z1GMUG4z4PaeFQotW5a/1xlyrX/
# x6bKRAGmUOKLwOrDAI2cPTMmHPuf3ha1aMWxzkov90XyApZMxEfkxVNrl3EIm7pW
# 1mhtz6zO0z7Qk8zlWZxv/sP4CUUREYCRAYbE79nh/EcfX8Rxn+LBSKbNp9eME6Uh
# DdFLFQCP3zSWK4DI0KuPwl26cZHedVJG/Em1alRm+UhSthjgsOYkmwWwjyCxyHcu
# tyGY94GSjGy/LtGkqFw5C1NhpwPjy/Pt/NPZyJyImoBfFm3t+2HyyCoqJRREJW5K
# VxQpcFeb/V1xgIqo6hTPZga7aLS3gr9fXslZnmN03W/GrNJBr0/g8fECAwEAAaOC
# ARswggEXMB0GA1UdDgQWBBStH9nqHYoenOCYDVBEZf/3bV7e7zAfBgNVHSMEGDAW
# gBTVYzpcijGQ80N7fEYbxTNoWoVtVTBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8v
# Y3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNUaW1TdGFQQ0Ff
# MjAxMC0wNy0wMS5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1RpbVN0YVBDQV8yMDEw
# LTA3LTAxLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0G
# CSqGSIb3DQEBCwUAA4IBAQAm6KOdqe82tLrd7zsIrSDAiYjwLgl2HEss+cDqb+lR
# JdZ6X0oJre33k1E07fo2B6YPGGyTPutUeJSKBvWkl2b5MHlKGDYOU+LVSF0JNo3m
# VNZn6scAV8MjiLaB0o7B3K6DvebmNrZ2p8NOXYOLlrHBwGAO8axkt8Gb5oa63a9Q
# YEGDVCMwp+pAaowkJjBc8Z0ebBE3VQ3kyk5EGROaTYMRZaNGbQspDX95XgpiJTlx
# XgYLT/z+r9fvXBuvB3IfZnK+HaYg4T7hP2ZlzsfQLNnxB2pMd3bFtNPUZI1F55hi
# WdORaUKIQuNiQicdR/C6YLWkK5kx/ghM3DsqN44Y/IoNMIIGcTCCBFmgAwIBAgIK
# YQmBKgAAAAAAAjANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlm
# aWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMTAwNzAxMjEzNjU1WhcNMjUwNzAxMjE0
# NjU1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBAKkdDbx3EYo6IOz8E5f1+n9plGt0VBDVpQoAgoX7
# 7XxoSyxfxcPlYcJ2tz5mK1vwFVMnBDEfQRsalR3OCROOfGEwWbEwRA/xYIiEVEMM
# 1024OAizQt2TrNZzMFcmgqNFDdDq9UeBzb8kYDJYYEbyWEeGMoQedGFnkV+BVLHP
# k0ySwcSmXdFhE24oxhr5hoC732H8RsEnHSRnEnIaIYqvS2SJUGKxXf13Hz3wV3Ws
# vYpCTUBR0Q+cBj5nf/VmwAOWRH7v0Ev9buWayrGo8noqCjHw2k4GkbaICDXoeByw
# 6ZnNPOcvRLqn9NxkvaQBwSAJk3jN/LzAyURdXhacAQVPIk0CAwEAAaOCAeYwggHi
# MBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBTVYzpcijGQ80N7fEYbxTNoWoVt
# VTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0T
# AQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNV
# HR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9w
# cm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEE
# TjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2Nl
# cnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDCBoAYDVR0gAQH/BIGVMIGS
# MIGPBgkrBgEEAYI3LgMwgYEwPQYIKwYBBQUHAgEWMWh0dHA6Ly93d3cubWljcm9z
# b2Z0LmNvbS9QS0kvZG9jcy9DUFMvZGVmYXVsdC5odG0wQAYIKwYBBQUHAgIwNB4y
# IB0ATABlAGcAYQBsAF8AUABvAGwAaQBjAHkAXwBTAHQAYQB0AGUAbQBlAG4AdAAu
# IB0wDQYJKoZIhvcNAQELBQADggIBAAfmiFEN4sbgmD+BcQM9naOhIW+z66bM9TG+
# zwXiqf76V20ZMLPCxWbJat/15/B4vceoniXj+bzta1RXCCtRgkQS+7lTjMz0YBKK
# dsxAQEGb3FwX/1z5Xhc1mCRWS3TvQhDIr79/xn/yN31aPxzymXlKkVIArzgPF/Uv
# eYFl2am1a+THzvbKegBvSzBEJCI8z+0DpZaPWSm8tv0E4XCfMkon/VWvL/625Y4z
# u2JfmttXQOnxzplmkIz/amJ/3cVKC5Em4jnsGUpxY517IW3DnKOiPPp/fZZqkHim
# bdLhnPkd/DjYlPTGpQqWhqS9nhquBEKDuLWAmyI4ILUl5WTs9/S/fmNZJQ96LjlX
# dqJxqgaKD4kWumGnEcua2A5HmoDF0M2n0O99g/DhO3EJ3110mCIIYdqwUB5vvfHh
# AN/nMQekkzr3ZUd46PioSKv33nJ+YWtvd6mBy6cJrDm77MbL2IK0cs0d9LiFAR6A
# +xuJKlQ5slvayA1VmXqHczsI5pgt6o3gMy4SKfXAL1QnIffIrE7aKLixqduWsqdC
# osnPGUFN4Ib5KpqjEWYw07t0MkvfY3v1mYovG8chr1m1rtxEPJdQcdeh0sVV42ne
# V8HR3jDA/czmTfsNv11P6Z0eGTgvvM9YBS7vDaBQNdrvCScc1bN+NR4Iuto229Nf
# j950iEkSoYICzjCCAjcCAQEwgfihgdCkgc0wgcoxCzAJBgNVBAYTAlVTMQswCQYD
# VQQIEwJXQTEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25z
# IExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjNCRDQtNEI4MC02OUMz
# MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYF
# Kw4DAhoDFQDx/fkdMWpT3PCKEj2S2aw+CnAwUqCBgzCBgKR+MHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUAAgUA4ZHhczAiGA8yMDE5
# MTIwNDE1NDAzNVoYDzIwMTkxMjA1MTU0MDM1WjB3MD0GCisGAQQBhFkKBAExLzAt
# MAoCBQDhkeFzAgEAMAoCAQACAhCgAgH/MAcCAQACAhHbMAoCBQDhkzLzAgEAMDYG
# CisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEA
# AgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAkl0SzAtkFTe1T1w7EXVAuo3rVBAegt84
# yCE4Z+SP/nDQM8kd2jLpwvQYv4CpxYQNOfFNSktD5cGMtWPjEsplBhBjdHENqxbu
# 9TgXlxrKmBBR7MMVihlaSZiWwydEBexLWd6JYoaQNITpm1C+s1CSfW8YZoZoQR1w
# 3wZmTwWBRKwxggMNMIIDCQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMAITMwAAAQvk+b6Pb0wd0AAAAAABCzANBglghkgBZQMEAgEFAKCCAUowGgYJ
# KoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCDGeAjqLamc
# Gudr7kYRLoU2wlNng7tIxobJZ6XHedQMOjCB+gYLKoZIhvcNAQkQAi8xgeowgecw
# geQwgb0EIDSP0M4gUz46JJfxcCRcBeK9FHQs8cDpxVT8BMATXHOIMIGYMIGApH4w
# fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAEL5Pm+j29MHdAAAAAA
# AQswIgQgZrEqn2Tba/C2eAVBjYDtfsmboozAciWDePHDPDx9ck8wDQYJKoZIhvcN
# AQELBQAEggEAk8JitspfMhnhPylrzWSQRansvw7ya3uUHxtSUyw+fHZCTG4LfW1h
# itHiEHUQ2VLrkvEkkk0oOoGpMdL6lZtBmwBUITjRpd35UcK0uq5oGnjptgq1Rm55
# lczqofqo/mV9kQx99FvvMQIp73m867gKkIL7CN3J61NNYllQ3a7S+pSdBcyuPITe
# rku3qcALcl4+/zbC+oe8Kv8szecwVw1Q/KDbvNAUZmOC3LEwtBLN27sc8j1bEe+9
# fZqVMg/GiaeWWKiZHlrqaeAc4cW5bZ4NxrcjFrwEix75B5dLZI6EOfXk3+UxTM0j
# E6Wq1rUr7KsigbXicRpu1hTuke0KHkQChg==
# SIG # End signature block
