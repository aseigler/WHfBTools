#
# Get-AzureADWHfBKeys.ps1
#
# Copyright 2019 Microsoft. All rights reserved.
#

<#
    Get-AzureADWHfBKeys
#>
function Get-AzureADWHfBKeys
{
    <#.SYNOPSIS
        Reads Windows Hello for Business (WHfB) keys from Azure Active Directory.

    .DESCRIPTION
        Reads Windows Hello for Business (WHfB) keys from Azure Active Directory. Two modes
        are supported:  read all keys from the current tenant or all keys from a specific user.

    .PARAMETER Tenant
        Specify this parameter to read all keys from the current tenant.

    .PARAMETER UserPrincipalName
        Optional. Specify this parameter to read all keys from a specific user. This parameter
        cannot be combined with -All.

    .PARAMETER SkipCheckForOrphanedKeys
        Optional.  This switch is to suppress check for each key to see if it is linked to a valid
        device object. This option requires additional network queries to check therefore increasing
        run time of the command.

    .PARAMETER BatchSize
        Optional. Specify to override the default query batch size.

    .PARAMETER Logging
        Optional. This switch will enable logging to a file

    .PARAMETER All
        Optional. This switch will cause a scan of all users in the tenant. This parameter
        cannot be combined with -UserPrincipalName.

    .PARAMETER Report
        Optional. This switch will cause a summary report to be printed to console and log.

    .INPUTS
        None. You cannot pipe objects to Get-AzureADWHfBKeys.

    .OUTPUTS
        Custom type representing WHfB key. Get-AzureADWHfBKeys returns one or more based on results.

    .EXAMPLE
        PS C:\>Get-AzureADWHfBKeys -Tenant contoso.com -UserPrincipalName user@contoso.com -Report | Out-Null

        Scan WHfB keys for a single user in Azure AD tenant and display summary report.

    .EXAMPLE
        PS C:\>Get-AzureADWHfBKeys -Tenant contoso.com -Logging -Report -All | Out-Null

        Scan all WHfB keys in Azure AD tenant and maintain a log file (WHfBTools-<Timestamp>.log).

    .EXAMPLE
        PS C:\>Get-AzureADWHfBKeys -Tenant contoso.com -SkipCheckForOrphanedKeys -Logging -Report -All | Out-Null

        Scan all WHfB keys in Azure AD tenant and maintain a log file (WHfBTools-<Timestamp>.log).
        Suppresses extra check for orphaned keys which improves runtime. Orphaned keys are no longer usable because the
        associated device object has been deleted from Azure Active Directory.

    .EXAMPLE
        PS C:\>Get-AzureADWHfBKeys -Tenant contoso.com -report -all | Export-Csv "contoso_whfb_keys.csv"

        Scan all WHfB keys in Azure AD tenant and export them to a CSV file.
    #>

    [CmdletBinding()]
    param
        (
        [Parameter(Mandatory=$true)]
        $Tenant,
        [Parameter(Mandatory=$false)]
        $UserPrincipalName,
        [Parameter(Mandatory=$false)]
        [Switch]
        $SkipCheckForOrphanedKeys,
        [Parameter(Mandatory=$false)]
        $BatchSize,
        [Parameter(Mandatory=$false)]
        [Switch]
        $logging,
        [Parameter(Mandatory=$false)]
        [Switch]
        $All,
        [Parameter(Mandatory=$false)]
        [Switch]
        $Report
        )
    Begin
    {
        InitializeAzureAD -Tenant $Tenant -UserPrincipalName $UserPrincipalName

        # Setup counters
        $script:totalAzureADWHfBKeys = 0
        $script:totalAzureADOrphanedKeys = 0
        $script:totalAzureADUsersWithWHfBKeys = 0
        $script:totalAzureADUsers = 0
        $script:totalAzureADRocaVulnerableKeys = 0
        $script:totalADUsersWithWHfBKeysOnMobile = 0
    }

    Process
    {
        $script:enableLogging = 0
        $script:authReady = 0
        $script:tenantTracker = $Tenant
        $script:skipCheckOrphaned = $false

        if ($logging -eq $true)
        {
            $script:enableLogging = 1
            DiagLog "Started Get-AzureADtotalAzureADWHfBKeys." -logOnly
        }

        if ($SkipCheckForOrphanedKeys -eq $true) { $script:skipCheckOrphaned = $true }
        if ($report -eq $true) { $script:reporting = 1 }
        if($BatchSize -eq $null) {$BatchSize=100}

        # Parameter checking
        if ($All -ne $true -and $UserPrincipalName -eq $null)
        {
            write-host "Parameter '-UserPrincipalName' must be set if -All not $true" -foregroundcolor red
            return;
        }

        if ($All -eq $true -and $UserPrincipalName -ne $null)
        {
            write-host "Parameter '-UserPrincipalName' must not be set if -All is $true" -foregroundcolor red
            return;
        }

        # Get the authorization token
        Initialize-AuthenticationAzureAD -Tenant $Tenant -UserPrincipalName $UserPrincipalName

        # Initial URI Construction, override this filter for advanced scoping of the user query
        $Searchfilter ="`$filter=accountEnabled eq true"

        # Pick search filter based on single or All users
        if ($All -eq $true)
        {
            $uri = "https://graph.windows.net/$Tenant/users/?`$top=$BatchSize&$($Searchfilter)&api-version=1.6-internal"
        }
        else
        {
            $uri = "https://graph.windows.net/$Tenant/users?`$filter=startswith(userPrincipalName, '" + $UserPrincipalName + "')&api-version=1.6-internal"
        }

        # Initial query for first page of results
        $query = MakeAzureADGraphRequest -Uri $uri -Method Get

        if ($logging)
        {
            $output = "Query result: " + $query
            DiagLog $output -logOnly
        }

        # Setup result tracking
        $moreObjects = $query

        # We're processing all users or a specified user
        if ($All)
        {
            Update-GetAzureADWHfBKeysProgress
            Get-FreshTokenIfNeeded

            $keys = Get-UserFromQuery -query $query -tenant $Tenant |
                Get-KeysForUser -tenant $Tenant |
                    Get-KeyMetadataForSingleKey -tenant $Tenant

            if ($keys)
            {
                Get-OrphanedStatus -Keys $keys
            }
        }
        else
        {
            # Targeting a single user
            $keys = Get-KeysForUser -user $query.value -tenant $Tenant |
                Get-KeyMetadataForSingleKey -tenant $tenant
            
            if ($keys)
            {
                Get-OrphanedStatus -Keys $keys
            }
        }

        # Get all the remaining objects in batches
        if ($All -eq $true -and $query.'odata.nextLink'){
            $moreObjects.'odata.nextLink' = $query.'odata.nextLink'

            do
            {
                $pageFragment = $moreObjects.'odata.nextLink'
                $uriPaged = "https://graph.windows.net/$($script:Tenant)/$pageFragment&`$top=$BatchSize&api-version=1.6-internal"

                Get-FreshTokenIfNeeded
                $moreObjects = MakeAzureADGraphRequest -Uri $uriPaged -Method Get

                $keys = Get-UserFromQuery -query $moreObjects -tenant $Tenant |
                    Get-KeysForUser -tenant $Tenant |
                        Get-KeyMetadataForSingleKey -tenant $Tenant

                Get-FreshTokenIfNeeded

                if ($keys)
                {
                    Get-OrphanedStatus -Keys $keys
                }

            } while ($moreObjects.'odata.nextLink')
        }

        if ($reporting)
        {
            DiagLog "Report of summary results:" -foregroundcolor yellow
            DiagLog "Users scanned: $script:totalAzureADUsers" -foregroundcolor yellow
            DiagLog "Users with WHfB keys: $script:totalAzureADUsersWithWHfBKeys" -foregroundcolor yellow
            DiagLog "Total WHfB Keys: $script:totalAzureADWHfBKeys" -foregroundcolor yellow
            DiagLog "Total ROCA vulnerable keys: $script:totalAzureADRocaVulnerableKeys" -foregroundcolor yellow

            if ($script:skipCheckOrphaned -eq $false)
            {
                DiagLog "Total orphaned keys: $script:totalAzureADOrphanedKeys" -foregroundcolor yellow
            }
            #DiagLog "Total users with WHfB keys on mobile: $script:totalADUsersWithWHfBKeysOnMobile" -foregroundcolor yellow
        }

        clear-variable -Name tenantTracker -Force
    }
}

<#
    Get-OrphanedStatus
#>
function Get-OrphanedStatus
{
    <#.SYNOPSIS
        Invokes concurrent jobs to query for devices associated with keys

    .DESCRIPTION
        For every key query AzureAD for existence of the device.

    .PARAMETER Keys
        Specifies the key metadata objects.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [psObject[]]$Keys
        )

    if ($script:skipCheckOrphaned -eq $false)
    {
        Invoke-Async -Set $Keys -SetParam KeyMetadata `
            -Params @{"AuthorizationHeader" = $script:authHeader} `
            -CmdLet DoesDeviceObjectExistAzureAd `
            -ThreadCount $script:logicalCores
    }
}

<#
    Get-UserFromQuery
#>
function Get-UserFromQuery
{
    <#.SYNOPSIS
        Scans all users in the query result.

    .DESCRIPTION
        Reads Windows Hello for Business (WHfB) keys from the Azure Active Directory query response.

    .PARAMETER query
        Specifies the query results from an Azure Active Directory query.

    .PARAMETER tenant
        Specifies the tenant associated with the request.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $query,
        [Parameter(Mandatory=$true)]
        $tenant
        )
    Process
    {
        $userHasWHfB = 0
        $userHasWHfBOnMobile = 0
        $usersWithKeys += 1
        $batchtotalAzureADWHfBKeys = 0

        foreach ($user in $query.value)
        {
            Write-Output $user
        }

        if ($logging)
        {
            DiagLog "Total scanned: $script:totalAzureADUsers - Batch contained $($query.value.count) users. Total WHfB ROCA vulnerable keys: $script:totalAzureADRocaVulnerableKeys. Total orphaned WHfB keys: $script:totalAzureADOrphanedKeys"
        }
    }
}

<#
    Update-GetAzureADWHfBKeysProgress
#>
function Update-GetAzureADWHfBKeysProgress
{
    <#.SYNOPSIS
        Updates the progress bar with current status.

    .DESCRIPTION
        Updates the progress bar with current status.

    #>

    $activity = "Get-AzureADWHfBKeys  -  " + $script:stopwatch.Elapsed.ToString("dd\:hh\:mm\:ss")
    $progressDescription = "Scanning AzureAD and Compiling Statistics"
    if ($script:skipCheckOrphaned -eq $false)
    {
        $progressDescription = $progressDescription + " | # of Orphaned keys"
    }

    $progressResults = "$script:totalAzureADUsers users scanned | $script:totalAzureADWHfBKeys WHfB keys found | $script:totalAzureADRocaVulnerableKeys ROCA vulnerable keys | $script:totalAzureADOrphanedKeys orphaned keys"
    if ($script:skipCheckOrphaned -eq $false)
    {
        $progressResults = $progressResults + " | $script:totalAzureADOrphanedKeys"
    }

    Write-Progress -Id 1 -ParentId -1 -Activity $activity -Status $progressDescription -PercentComplete -1 -CurrentOperation $progressResults
}

<#
    Get-KeysForUser
#>
function Get-KeysForUser
{
    <#.SYNOPSIS
        Scans the Hello for Business (WHfB) keys from a user query result.

    .DESCRIPTION
        Reads Windows Hello for Business (WHfB) keys for the user data and emits a
        custom object representing each key and its metadata into the pipeline.

    .PARAMETER user
        Specifies the user query result containing the user object data read from
        Azure Active Directory

    .PARAMETER tenant
        Specifies the tenant associated with the request.
    #>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$true)]
        $user,
        [Parameter(Mandatory=$true)]
        $tenant
        )

    Process
    {
        $userHasWHfB = 0
        $userHasWHfBOnMobile = 0

        if ($script:enableLogging)
        {
            DiagLog "$script:totalAzureADUsers) Processing user: $($user.userPrincipalName)" -logOnly
        }

        # Ignore any B2B users as their credentials are in home tenant
        if ($user.UserPrincipalName.Contains("#EXT#"))
        {
            return;
        }

        foreach ($key in $user.searchableDeviceKey)
        {
            if ($key.usage -ne "NGC") { continue }
            if ($userHasWHfB -eq 0) { $userHasWHfB += 1 }

            $rawKeyAndUpn = New-Object -TypeName psObject
            $rawKeyAndUpn | Add-Member -MemberType NoteProperty -Name rawKey -Value $key.value__
            $rawKeyAndUpn | Add-Member -MemberType NoteProperty -Name userPrincipalName -Value $user.UserPrincipalName
            $rawKeyAndUpn | Add-Member -MemberType NoteProperty -Name KeyMaterial -Value $key.keyMaterial
            $rawKeyAndUpn | Add-Member -MemberType NoteProperty -Name Tenant -Value $tenant
            $rawKeyAndUpn | Add-Member -MemberType NoteProperty -Name Usage -Value $key.usage
            $rawKeyAndUpn | Add-Member -MemberType NoteProperty -Name KeyIdentifier -Value $key.keyIdentifier
            $rawKeyAndUpn | Add-Member -MemberType NoteProperty -Name CreationTime -Value $key.creationTime
            $rawKeyAndUpn | Add-Member -MemberType NoteProperty -Name CustomKeyInformation -Value $key.customKeyInformation
            $rawKeyAndUpn | Add-Member -MemberType NoteProperty -Name DeviceId -Value $key.deviceId

            Write-Output $rawKeyAndUpn
        }

        $script:totalAzureADUsers += 1
        $script:totalAzureADUsersWithWHfBKeys += $userHasWHfB

        # SupportsNotify
        $script:totalADUsersWithWHfBKeysOnMobile += $userHasWHfBOnMobile
    }
}

<#
    Get-KeyMetadataForSingleKey
#>
function Get-KeyMetadataForSingleKey
{
    <#.SYNOPSIS
        Scans the Hello for Business (WHfB) keys from a user query result.

    .DESCRIPTION
        Reads Windows Hello for Business (WHfB) keys for the user data and emits a
        custom object representing each key and its metadata into the pipeline.

    .PARAMETER user
        Specifies the user query result containing the user object data read from
        Azure Active Directory

    .PARAMETER tenant
        Specifies the tenant associated with the request.
    #>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$true)]
        [psObject]$rawKeyAndUpn,
        [Parameter(Mandatory=$true)]
        $tenant
        )

    Process
    {
        $userHasWHfB = 0
        $batchtotalAzureADWHfBKeys += 1
        $script:totalAzureADWHfBKeys += 1

        # Build up custom key metadata object
        $keyObject = New-Object -TypeName psobject
        $keyObject | Add-Member -MemberType NoteProperty -Name userPrincipalName -Value $rawKeyAndUpn.UserPrincipalName
        $keyObject | Add-Member -MemberType NoteProperty -Name Tenant -Value $tenant
        $keyObject | Add-Member -MemberType NoteProperty -Name DeviceId -Value $rawKeyAndUpn.deviceId
        $keyObject | Add-Member -MemberType NoteProperty -Name Usage -Value $rawKeyAndUpn.usage
        $keyObject | Add-Member -MemberType NoteProperty -Name Id -Value $rawKeyAndUpn.keyIdentifier
        $keyObject | Add-Member -MemberType NoteProperty -Name CreationTime -Value $rawKeyAndUpn.creationTime

        # SupportsNotify: indicates mobile device
        # Get the byte array for custom key info
        $bytes = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($rawKeyAndUpn.customKeyInformation))

        # Fourth byte determines if supports notification
        if ($bytes[3] -eq 1)
        {
            if ($userHasWHfBOnMobile -eq 0) { $userHasWHfBOnMobile += 1 }
        }

        # Capture supports notification on the custom object
        if ($userHasWHfBOnMobile -eq 1)
        {
            #$keyObject | Add-Member -MemberType NoteProperty -Name SupportsNotify -Value $true
        }
        else
        {
            #$keyObject | Add-Member -MemberType NoteProperty -Name SupportsNotify -Value $false
        }

        # Test for ROCA vulnerability
        [byte[]]$keyBytes = [System.Convert]::FromBase64String($rawKeyAndUpn.keyMaterial)

        $rocaVulnerable = Probe-KeyForRocaVulnerability -keyBytes ($keyBytes)

        $keyObject | Add-Member -MemberType NoteProperty -Name RocaVulnerable -Value $rocaVulnerable

        if ($rocaVulnerable)
        {
            $script:totalAzureADRocaVulnerableKeys += 1

            if ($logging)
            {
                DiagLog "Key is vulnerable to ROCA: $keyObject.Id" -logOnly
            }
        }

        Update-GetAzureADWHfBKeysProgress

        # Emit keyObject in pipeline
        Write-Output $keyObject
    }
}

# SIG # Begin signature block
# MIIjhgYJKoZIhvcNAQcCoIIjdzCCI3MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCpOdnh+f3r3wvP
# bKgDO8JjWm2bRRztZNNeebH0ecI5k6CCDYEwggX/MIID56ADAgECAhMzAAABUZ6N
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
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgubro2YVw
# YO67leFZ9IllYovp0bMUsRbC8Z4IrV7TjXMwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQApi4FByBZYd1/xDpsavGQ58dcTMg8R0rHvs7qT/xQT
# bSPl5Yvhrul7j6ZEMXkvfyTIEJwOpLh8fIAU/suAeBx+eKDGDRzneS89ET6hWo7x
# JUTLkfwcAr6PExKGXUr7ajBBu8rds8ELY62SehK8pOiX/xptf7yH75Kle4hDDc7s
# EjSnhfUSq3ScIEfUEMUG+995GpN1YkAGbeEpImx3TL0WGymm2zDEwf5sqCTIU24h
# 0Omutru7kGH6ncR5Y+on4xbceasbDXj+fwKc5Wyk3Tpael8Pm28u1d+Gu4UqVKp5
# AVjLld4hLATLHyI+CxYRQOOArAtF/NAdAZWuWl240acnoYIS5TCCEuEGCisGAQQB
# gjcDAwExghLRMIISzQYJKoZIhvcNAQcCoIISvjCCEroCAQMxDzANBglghkgBZQME
# AgEFADCCAVEGCyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEICpNInK2ArKSWYsZAkBxe5t+UUCuFeWwS4SBHX0S
# jlg4AgZdtfNcni8YEzIwMTkxMjA0MTQxMjEzLjA1MlowBIACAfSggdCkgc0wgcox
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
# CSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgjUKblpSV
# QMaD5ODwSViF7Hb3fU5LMUThDH+d6/HtuuEwgfoGCyqGSIb3DQEJEAIvMYHqMIHn
# MIHkMIG9BCA0j9DOIFM+OiSX8XAkXAXivRR0LPHA6cVU/ATAE1xziDCBmDCBgKR+
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABC+T5vo9vTB3QAAAA
# AAELMCIEIGaxKp9k22vwtngFQY2A7X7Jm6KMwHIlg3jxwzw8fXJPMA0GCSqGSIb3
# DQEBCwUABIIBAAOR7ifMAuUmBnUzVeL5TebOgvcYS2+B/HUgBfcAud9gzTfKzl03
# awex6I1+jKNrzflHSfLQ9TDwzr/sBAqEylSge7vNsFJpM3UWozRaO7hIRa817TMc
# fh4LXJb9vsmBykMAG8MgO2uNRZM/UbJ7M2SxMm644qHtCeERaeDVOumWyYyBfRhU
# GABkadLKgSxpi+hq+t/3azppyWRVc5CUywloDqH0Z4dSqPBmmAnDXbUDGas/jFwq
# 6Hpw+s+hZXsuMVffMoIzjwJ9vDnaa0OeyJvcZrvfwhR3y+/krQlNT3MPVKJgmJ0B
# +EGFIQgXYm0f9JSSLEuVH3yv1EwpubYCz+k=
# SIG # End signature block
