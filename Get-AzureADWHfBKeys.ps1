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

                $moreObjects = MakeAzureADGraphRequest -Uri $uriPaged -Method Get

                $keys = Get-UserFromQuery -query $moreObjects -tenant $Tenant |
                    Get-KeysForUser -tenant $Tenant |
                        Get-KeyMetadataForSingleKey -tenant $Tenant

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
