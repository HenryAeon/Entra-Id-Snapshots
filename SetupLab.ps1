Import-Module Microsoft.Graph.Users
Import-Module Microsoft.Graph.Identity.DirectoryManagement
$workDir = "R:\" # I placed the scripts here
Import-Module "$($workDir)GraphRunner.ps1" #Thank you to https://github.com/dafthack/GraphRunner for building the script
Import-Module "$($workDir)RefreshOauthToken.psm1"

<#
.DESCRIPTION
    Use Entra ID custom security Attribute 
    Create an Attribute Set with an Attribute and Value
    
.EXAMPLE
    # Define the custom security attribute values
    $foods = @(
        [PSCustomObject]@{ Id  = "isApple"; Status = "Available"; Type = "Boolean"; Description = "Red and Juicy" },
        [PSCustomObject]@{ Id  = "isPear"; Status = "Available"; Type = "Boolean"; Description = "green and hard"  },
        [PSCustomObject]@{ Id  = "isBanana"; Status = "Available"; Type = "Boolean"; Description = "yellow and long" }
    )

    Setup-AttributeSet -attributeSetName "FoodGroups" -attributeSetDescription "Creating a shopping list of foods" -attributes $foods

.PERMISSIONS
    Entra ID permissions
    - Attribute Definition Administrator

    Graph command line permissions
    - CustomSecAttributeDefinition.ReadWrite.All
#>
function Setup-AttributeSet {
    param (
        [Parameter(Mandatory=$true)]
        [Object[]]$attributes,

        [Parameter(Mandatory=$false)]
        [String]$attributeSetDescription="",

        [Parameter(Mandatory=$true)]
        [string]$attributeSetName
    )

    # create the Attribute Set
    $AttrSetBody = @{
	    id = $attributeSetName
	    description = $attributeSetDescription
	    maxAttributesPerSet = 25
    }

    New-MgDirectoryAttributeSet -BodyParameter $AttrSetBody -ErrorAction SilentlyContinue

    # for each attribute and value pair, add it to our Set
    foreach ($attribute in $attributes) {
        $body = @{
            AttributeSet = $attributeSetName
            Name = $attribute.Id
            Description = $attribute.Description
            Type = $attribute.Type
            Status = $attribute.Status
            IsCollection = $false
            UsePreDefinedValuesOnly = $false
            isSearchable = $false
        }

        #Write-Host $body
        try{
            New-MgDirectoryCustomSecurityAttributeDefinition -BodyParameter $body -ErrorAction Stop
        }catch{
            Write-Warning "$($attribute.Id) $($_.Exception.Message)" 
        }
    }

    Write-Output "Created $($attributes.count) custom security attributes on the set $attributeSetName"
}


function CreateUpdate-Watchlist{
<#
.SYNOPSIS
    Create or Upload a CSV to watchlist into a log analytics workspace

.DESCRIPTION
    Create or Upload a CSV to watchlist into a log analytics workspace. Have a subscripition, a resourcegroup, a log analytic workspace, and a sentinel workspace created.
    Author: Henry Lopez
    Last Update: 17 Nov 2024

.PARAMETER SubscriptionId
    Required - The subscriptition id with the log analytics workspace
    
.PARAMETER ResourceGroupName
    Required - The Resource Group Name with the log analytics workspace
    
.PARAMETER LAWorkspaceName
    Required - The name of the log analytics workspace to place the watchlist
    
.PARAMETER WatchlistAlias
    Required - Name of the watchlist alias, must start with alphabet character. This will be the same as the displayname

.PARAMETER Access_token
    Required - Provide an already authenticated access token. app must be authenticated with url "https://management.core.windows.net"

.PARAMETER Description
    Describe contents the watchlist

.PARAMETER CsvContent
    Provide a raw CSV file without any quotes and header on the first line. If not included, then the watchlist will only be created

.PARAMETER ItemsSearchKey
    Required - Provide unique column that will be used to join tables

.EXAMPLE
    # create a bulk item watchlist of Important people
    $microsoftDocsId = [guid]"18fbca16-2224-45f6-85b0-f7bf2b39b3f3"
    $AuthUri = "https://management.core.windows.net" #https://management.azure.com
    Get-OauthTokens -AppID $microsoftDocsId -AuthUri $AuthUri -Scope "user_impersonation" -TenantId $tenantId -AutoRefresh

    CreateUpdate-Watchlist -SubscriptionId "XXXXXXXX-2222-4444-6666-XXXXXXXXXXXX" `
                            -LAWorkspaceName "mylogWorkspace" `
                            -ResourceGroupName "myrg" `
                            -WatchlistAlias "Important_People_List" `
                            -Access_token $tokens.access_token `
                            -Description "List of my orgs important people" `
                            -ItemsSearchKey "TargetUPN" `
                            -CsvContent "TargetName,TargetUPN`nJane Doe,janedoe@example.com`nJoe Doe,joedoe@example.com"

    >> Successfully uploaded the watchlist Important_People_List
#>
    Param(
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [guid]  $SubscriptionId,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [string]  $ResourceGroupName,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [string]  $LAWorkspaceName,
    
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [string]  $WatchlistAlias,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [string] $Access_token,
        [string] $Description= "",
        [string] $CsvContent,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [string] $ItemsSearchKey
    )

    Write-Debug "`n`tSubscriptionId: $SubscriptionId`n`tLAWorkspaceName: $LAWorkspaceName`n`tWatchlistAlias: $WatchlistAlias`n`tDescription: $Description`n`tItemsSearchKey: $ItemsSearchKey"

    # generate the uri for the watchlists
    $uri_base = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$LAWorkspaceName/providers/Microsoft.SecurityInsights/watchlists/"
    $restAPIVersion = "`?api-version=2024-03-01"
    $uri_theWatchlist = "$uri_base$WatchlistAlias$restAPIVersion"

    <# Grab a list of watchlists
    # Create or update the watchlist
    $headers = @{"Authorization" = "Bearer $access_token"}
    $uri_watchlist_list = "$uri_base$restAPIVersion"

    try {
        $list_watchlists = (Invoke-WebRequest -UseBasicParsing -Uri $uri_watchlist_list -Headers $headers | ConvertFrom-Json).value.id | % {($_ -split "/")[-1]}
    } catch {
        Write-Host -ForegroundColor Magenta "Error: Cannot grab watchlist - $($_.ErrorDetails.Message)"
        return
    }
    #>

    ####################################
    # Upload the csv to the watchlist
    ####################################
    $create_watchlist_body = @{
        properties = @{
            displayName = $WatchlistAlias
            source = "Local file"
            provider = "Microsoft"
            description = $Description
            itemsSearchKey = $ItemsSearchKey
        }
    } 

    if($csvContent){
        Write-Host "CSV has content to upload!"
        #we have csv content, lets upload it
        $create_watchlist_body['properties']['rawContent'] = $csvContent
        $create_watchlist_body['properties']['contentType'] = "text/csv"
    }

    $create_watchlist_body = $create_watchlist_body | ConvertTo-Json

    Write-Debug $create_watchlist_body

    $headers = @{
        Authorization = "Bearer $access_token"
        "Content-Type" = "application/json"
    }

    try {
        $create_watchlists = Invoke-WebRequest -Method PUT -UseBasicParsing -Uri $uri_theWatchlist -Headers $headers -Body $create_watchlist_body
    } catch {
        $b = ($_.ErrorDetails.Message | ConvertFrom-Json).error
        Write-Host "Error: uploading the watchlist $($b.code): $($b.message)" -ForegroundColor Magenta 
        return
    }

    Write-Host "Successfully uploaded the watchlist $WatchlistAlias" -ForegroundColor Green
}


function Get-UsersWithAttributeValue {
# Ex usage:
# 
<#
.DESCRIPTION
    Provide a list of users with custom security attribute of targetName and targetValue
    
.EXAMPLE
    $usersWithPizza = Get-UsersWithAttributeValue -allUsers $allUsers -targetValue "pizza"

    Setup-AttributeSet -attributeSetName "FoodGroups" -attributeSetDescription "Creating a shopping list of foods" -attributes $foods

.PERMISSIONS
    Entra ID permissions
    - Attribute Definition Administrator

    Graph command line permissions
    - CustomSecAttributeDefinition.Read.All
#>
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$targetName,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [object]$targetValue,
        
        [switch] $v #verbose
    )

    if ($targetValue -isnot [string] -and $targetValue -isnot [bool]) {
        Write-Host "$targetValue is not a string or bool" -ForegroundColor Red
        return $null
    }

    $allUsers = Get-MgUser -All -Property "DisplayName,userPrincipalName,customSecurityAttributes,Id" 

    $usersWithTargetValue = @()

    foreach ($user in $allUsers) {
        $attributeDict = $user.CustomSecurityAttributes.AdditionalProperties
        
        # Loop through the dictionary and output the key set and attributes
        foreach ($keySetName in $attributeDict.Keys) {
            foreach ($key in $attributeDict[$keySetName].Keys) {
                if ($key -eq $targetName -and
                    $attributeDict[$keySetName][$key] -eq $targetValue ) {
                    

                    if ($v) {
                        $value = $attributeDict[$keySetName][$key]
                        #Write-Host "$($user.DisplayName) $keySetName Name: $key == $targetName >> Value: $($attributeDict[$keySetName][$key]) == $value"
                        Write-Host "$($user.DisplayName) found as a sec attribute match"
                    }

                    $usersWithTargetValue += @{
                        DisplayName = $user.DisplayName
                        UserPrincipalName = $user.UserPrincipalName
                        Id = $user.Id
                        SecurityAttribute = @{$key = $attributeDict[$keySetName][$key]}
                    }
                }
            }
        } # end of foreach dictionary key
    }

    return $usersWithTargetValue
}


function Clean-Lab {
<#
.DESCRIPTION
    Delete users with isNoise and isCompromised custom attribute
    
.EXAMPLE
    Clean-Lab
#>
    param (
        [switch] $v #verbose
    )

    # get all users
    #delete users with isNoise and isCompromised custom attribute
    $deleteUsers = @()
    if($v){
        $deleteUsers += Get-UsersWithAttributeValue -targetName "isCompromised" -targetValue $true -v
        $deleteUsers += Get-UsersWithAttributeValue -targetName "isNoise" -targetValue $true -v
    }else{
        $deleteUsers += Get-UsersWithAttributeValue -targetName "isCompromised" -targetValue $true
        $deleteUsers += Get-UsersWithAttributeValue -targetName "isNoise" -targetValue $true
    }
    foreach ($user in $deleteUsers){
        # delete the account
        
        try{
            Remove-mgUser -userid $user.Id -ErrorAction Stop
            Write-Host "Successfully deleted $($user.UserPrincipalName) with attribute $($user["SecurityAttribute"].keys)" -ForegroundColor Green
        }catch{
            Write-Host "$UserDisplayName $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}


function Create-User {
<#
.DESCRIPTION
    Create a user in entra
    
.EXAMPLE
    $randomuser = Create-User -UserDisplayName "Edgar Vil In Lake" -UserPrincipalName "EVIL"
    write-host "Random username is $($randomuser.DisplayName)"
#>
  param (
        [Parameter(Mandatory=$true)]
        [string]$UserDisplayName,

        [Parameter(Mandatory=$true)]
        [string]$UserPrincipalName
    )

    #create a random password
    $length = 16 #16 character password using dictionary below
    $allowedCharts = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@'
    $random = New-Object System.Random
    $password = -join ((1..$length) | ForEach-Object { $allowedCharts[$random.Next(0, $allowedCharts.Length)] })
    $password += "!"

    # Create the new user
    $PasswordProfile = @{
        ForceChangePasswordNextSignIn = $true
        Password  = $password
        ForceChangePasswordNextSignInWithMfa = $false
    }

    Write-Host "Attempting to create $UserPrincipalName"


    # Create the new user
    try{
        $user = New-MgUser -DisplayName $UserDisplayName -PasswordProfile $PasswordProfile -AccountEnabled `
        -MailNickName $UserPrincipalName  -UserPrincipalName ($UserPrincipalName + "@" + $tenantDomain) `
        -erroraction Stop
        Write-Host -ForegroundColor Green "Successfully created $($UserPrincipalName + "@" + $tenantDomain) with password $password" 
    }catch{
        Write-Host "$UserDisplayName $($_.Exception.Message)" -ForegroundColor Yellow
        $user = Get-MgUser -UserId ($UserPrincipalName + "@" + $tenantDomain)
    }

    return $user
}


function Capture-Snapshot {
<#
.DESCRIPTION
    Capture a snapshot of all Entra Users

    Assumption, this function is a snapshot and not continuous. 
    Future work is to make this script continuous by adding new users to a table or watchlist
    
.EXAMPLE
    $randomuser = 

    write-host "Random username is $($randomuser.DisplayName)"
#>
  param (
        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [string]$saveCSVLocation = "",
        [switch]$v
    )
    $addedUsers = (Get-MgAuditLogDirectoryAudit -All -Property "ActivityDateTime,ActivityDisplayName,Result,TargetResources,InitiatedBy" |
                     ?{$_.ActivityDisplayName -like "Add user" -and $_.Result -eq "success"}) |
                     select ActivityDateTime,ActivityDisplayName,Result,TargetResources,InitiatedBy

    ##########
    # Create a list of recently added users
    ##########
    $createdList = @()
    foreach ( $newuser in $addedUsers) {
        try{
            $targetUser = Get-MgUser -UserId $newuser.TargetResources.Id `
            -Property "DisplayName,userPrincipalName,CreatedDateTime,Id" -errorAction Stop |
            select DisplayName,userPrincipalName,CreatedDateTime,Id
        }catch{
            $targetUser = @{
                DisplayName = "deleted user"
                UserPrincipalName = "deleted user"
                Id = $newuser.TargetResources.Id
            }
        }

        if ($newuser.InitiatedBy.App.DisplayName -like "" ) {
            #user made the account
            Write-host "$($targetUser.DisplayName) created by User $($newuser.InitiatedBy.User.UserPrincipalName)"

            $userHash = @{
                TargetName = $targetUser.DisplayName
                TargetUPN = $targetUser.UserPrincipalName
                TargetId = $targetUser.Id
                CreatedByName = $newuser.InitiatedBy.User.DisplayName | select -first 1
                CreatedByUPN = ($newuser.InitiatedBy.User.UserPrincipalName.PSObject.BaseObject -join ' ').Trim()
                CreatedById = ($newuser.InitiatedBy.User.Id | ConvertTo-Json).tostring()
                CreatedDateTime = $newuser.ActivityDateTime
            }

            $createdList +=  $userHash
        } else {
            #spn created the account
            Write-Verbose "$($targetUser.DisplayName) created by App $($newuser.InitiatedBy.App.DisplayName)"
            $userHash = @{
                TargetName = $targetUser.DisplayName
                TargetUPN = $targetUser.UserPrincipalName
                TargetId = $targetUser.Id
                CreatedByName = $newuser.InitiatedBy.App.DisplayName | select -first 1
                CreatedByUPN = ($newuser.InitiatedBy.App.ServicePrincipalName.PSObject.BaseObject -join ' ').Trim()
                CreatedById = ($newuser.InitiatedBy.App.ServicePrincipalId | ConvertTo-Json).tostring()
                CreatedDateTime = $newuser.ActivityDateTime
            }

            $createdList +=  $userHash
        }

    }# end of all users

    ##########
    # Join all users and the new users
    ##########
    $combinedUserLists = @()
    $allUsers = Get-MgUser -All -Property "DisplayName,userPrincipalName,Id,AccountEnabled,CreatedDateTime,DeletedDateTime,SignInSessionsValidFromDateTime" |
                select DisplayName,userPrincipalName,Id,CreatedDateTime,AccountEnabled,DeletedDateTime,SignInSessionsValidFromDateTime
    foreach($user in $allUsers){
        $recentlyAdded = $createdList | ? {$_.targetId -match $user.Id}

        if($recentlyAdded.count -eq 0){
            # was not recently added
            $combinedUserLists += new-object PSObject -Property @{ #@{ 
                TimeGenerated = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                TargetName = $user.DisplayName
                TargetUPN = $user.UserPrincipalName
                TargetId = $user.Id

                CreatedByName = ""
                CreatedByUPN = ""
                CreatedById = ""
                CreatedDateTime = $user.CreatedDateTime
                TargetAccountEnabled = $user.AccountEnabled
            }
        } else {
            # was recently added
            write-host "Recently Added $($user.DisplayName) by $($recentlyAdded.CreatedByUPN)"
            $combinedUserLists += new-object PSObject -Property @{ #@{ 
                TimeGenerated = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                TargetName = $user.DisplayName
                TargetUPN = $user.UserPrincipalName
                TargetId = $user.Id

                CreatedByName = $recentlyAdded.CreatedByName
                CreatedByUPN = $recentlyAdded.CreatedByUPN
                CreatedById = $recentlyAdded.CreatedById
                CreatedDateTime = $user.CreatedDateTime
                TargetAccountEnabled = $user.AccountEnabled
            }
        }
    }

    if($saveCSVLocation.Length -ne 0 -and !(Test-Path $saveCSVLocation)){
        $combinedUserLists | select CreatedById, CreatedByName, CreatedByUPN, CreatedDateTime, TargetAccountEnabled, TargetId, TargetName, TargetUPN, TimeGenerated| Export-Csv $saveCSVLocation -NoTypeInformation -Force 
        write-host "File snapshot saved to "$saveCSVLocation -ForegroundColor Green
    }

    return $combinedUserLists
}


function Remove-EntraRole {
<#
.DESCRIPTION
    Remove the entra Role from a user
    
.EXAMPLE
    Remove-EntraRole
#>
  param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [guid]$roleTemplateId,
        
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [guid]$userId,
        
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [string]$userDisplayName
    )

    try {
        $DirectoryRole = Get-MgDirectoryRoleByRoleTemplateId -RoleTemplateId $roleTemplateId

        # Remove the user from the specified directory role
        Remove-MgDirectoryRoleMemberDirectoryObjectByRef -DirectoryObjectId $userId -DirectoryRoleId $DirectoryRole.Id -erroraction Stop
        Write-Host "Successfully removed $userDisplayName from $($DirectoryRole.DisplayName)"
    }
    catch {
        Write-Host "Warning: remove $userDisplayName from $($DirectoryRole.DisplayName) $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

function Activate-EntraRole {
<#
.DESCRIPTION
    Add the entra role to the user

.EXAMPLE
    Activate-EntraRole
#>
  param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [guid]$roleTemplateId,
        
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [guid]$userId,
        
        [Parameter(Mandatory=$true)]
        [ValidateNotNullorEmpty()]
        [string]$userDisplayName
    )

    #add evil to user admin
    #user admin
    
    $DirectoryRole = Get-MgDirectoryRole -Filter "roleTemplateId eq '$roleTemplateId'"

    try{
        New-MgDirectoryRoleMemberByRef -DirectoryRoleId $DirectoryRole.Id `
        -BodyParameter @{ "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$userId" } `
        -erroraction Stop
        Write-Host "Successfully added $userDisplayName to $($DirectoryRole.DisplayName)"
    }catch{
        Write-Host "Warning: Adding $userDisplayName to $($DirectoryRole.DisplayName) $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

<#
.SYNOPSIS
    Grant-AppConsentBehalfOfUser adds user consent on a tenant app such as graph command line

.DESCRIPTION
    Grant-AppConsentBehalfOfUser adds user consent on a tenant app. The script runner must have 
    graph command line permissions
        User.ReadBasic.All - non privileged, read all user profiles
        Application.ReadWrite.All to list and create service principals, 
        DelegatedPermissionGrant.ReadWrite.All to create delegated permission grants, 
        and AppRoleAssignment.ReadWrite.All to assign an app role.
        WARNING: These are high-privilege permissions!

    Steps
    1 connects to graph using Microsoft Graph PowerShell
    2 grabs users via user id
    3 sets the permissions to the app consented by user

    Author: Henry Lopez
    License: CC0 1.0 Universal
    Last Update: 19 Nov 2024

.PARAMETER resourceAppId
    The app id underlying app. Microsoft Graph API

.PARAMETER appId
    The uri to have the app authenticate. Default is the graph command line app
    
.PARAMETER userUPNOrId
    Required - The user of interest, can be a user principal name or an id

.PARAMETER user_permissions
    Required - set of permissions to add user consent on
    
.PARAMETER TenantId
    Required - The tenant id we are performing permission changes

.PARAMETER access_token
    The access token to connect to msgraph
    
.EXAMPLE
    # grant graph powershell to read and write all user profiles and read audit logs on behalf of person@example
    Grant-AppConsentBehalfOfUser -userUPNOrId "person@example.com" -TenantId "00000000-XXXX-XXXX-XXXX-000000000000" -user_permissions "User.ReadWrite.All AuditLog.Read.All"
#>
function Grant-AppConsentBehalfOfUser{
    param(
    [guid]$resourceAppId = "00000003-0000-0000-c000-000000000000", # Microsoft Graph API
    [guid]$appId = "be82726e-93bb-45eb-b5bb-3f81bd44c592", # Microsoft Graph Command line
    [ValidateNotNullOrEmpty()]
    [String]$userUPNOrId,
    [ValidateNotNullOrEmpty()]
    [String]$user_permissions,
    [Parameter(Mandatory=$True)]
    [guid]$TenantId,
    [string]$Access_token
    )
    <#
    $resourceAppId = '00000003-0000-0000-c000-000000000000'
	$appId = 'be82726e-93bb-45eb-b5bb-3f81bd44c592'
	$userUPNOrId = 'e0fd8ce9-fe1c-4bb3-8a90-56579eee4be1'
	$user_permissions = 'User.ReadWrite.All' 
	$TenantId = '2986cc2a-4772-4e47-8368-457b6ef13e85'
    #>

    Write-debug "`n`t`$resourceAppId = $resourceAppId `n`t`$appId = $appId `n`t`$userUPNOrId = $userUPNOrId `n`t`$user_permissions = $user_permissions `n`t`$TenantId = $TenantId"

    $requiredPermissions = "User.ReadBasic.All Application.ReadWrite.All DelegatedPermissionGrant.ReadWrite.All AppRoleAssignment.ReadWrite.All"
    $accessScopes = (Convert-AccessToken $access_token).scp -split " "
#    $accessScopes = (Convert-AccessToken $graphTokens.access_token).scp -split " "
    
    Write-debug "`n`t`$accessScopes = $accessScopes"

    $newToken = $false
    foreach ($perm in ($requiredPermissions  -split " ")) {
        if ($accessScopes -notcontains $perm) {
            Write-Host -ForegroundColor Red "Error: missing permissions '$perm' is missing from the scope."
            $newToken = $true
        }
    }

    if(-not $access_token -or $newToken){
        try {
            Connect-MgGraph -NoWelcome -Scopes $requiredPermissions -TenantId $TenantId -UseDeviceCode
        } catch {
            Write-Host "Error: Failed to connect to graph $($_.Exception.Message). Grant-AppConsentBehalfOfUser" -BackgroundColor Black -ForegroundColor Red
            return
        }
    }else{
        try {
            Connect-MgGraph -NoWelcome -AccessToken (ConvertTo-SecureString -String $access_token -AsPlainText -Force) -erroraction stop
        } catch {
            Write-Host "Error: Failed to connect to graph $($_.Exception.Message). Grant-AppConsentBehalfOfUser" -BackgroundColor Black -ForegroundColor Red
            return
        }
    }

    #######
    # grab the user on behalf of whom access will be granted
    $user = Get-MgUser -UserId $userUpnOrId

    #######
    # grab the spn, then remove all consents by the user
    $sp = Get-MgServicePrincipal -ServicePrincipalId $appId 
    # Get all delegated  user_permissions for the service principal
    $spOAuth2PermissionsGrants = Get-MgServicePrincipalOauth2PermissionGrant -ServicePrincipalId $sp.Id -All | where {$_.PrincipalId -eq $user.Id }

    # Remove all delegated permissions, clean up
    $spOAuth2PermissionsGrants | ForEach-Object {
        Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $_.Id
    }

    # the client app accessing the API, on behalf of the user. 
    $resourceSp = Get-MgServicePrincipal -Filter "appId eq '$($resourceAppId)'"

    try {
        New-MgOauth2PermissionGrant -ResourceId $resourceSp.Id -Scope $user_permissions -ClientId $appId -ConsentType "Principal" -PrincipalId $user.Id -ErrorAction Stop
    }catch{
        Write-Host "$user_permissions for $userUpnOrId  $($resourceSp.DisplayName) $($_.Exception.Message)"
    }
}


function Get-RandomName {
<#
.DESCRIPTION
    Returns a random username
    
.EXAMPLE
    $randomuser = Get-RandomName 
    write-host "Random username is $randomuser"
#>
    $firstNames = @("Alex", "Jordan", "Taylor", "Casey", "Morgan", "Sydney", "Riley", "Cameron", "Jamie", "Logan", "Peyton", "Avery", "Quinn", "Reese", "Dakota", "Kendall")
    $lastNames = @("Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor")

    # Create a random object
    $random = New-Object System.Random

    # Generate random first and last names
    $firstName = $firstNames[$random.Next($firstNames.Count)]
    $lastName = $lastNames[$random.Next($lastNames.Count)]

    return "$firstName $lastName"
}

# Function to validate GUID
function Is-Guid {
    param ([string]$Guid)
    return $Guid -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
}

<#
.SYNOPSIS
    Creates an Entra Id for a Lab Participant

.DESCRIPTION
    Add-LabUser Creates an Entra Id for a Lab Participant
    Using the name provided, adds user to the entra roles required to act in the lab
    Note: You will need to provide resource access for this new user

    Author: Henry Lopez
    License: CC0 1.0 Universal
    Last Update: 8 Dec 2024

.PARAMETER UserDisplayName
    Required - Friendly display name of the user

.PARAMETER UserPrincipalName
    Required - UPN of the user
    
.EXAMPLE
    Add-LabUser -UserDisplayName "adam mac" -UserPrincipalName "adammac"
#>
function Add-LabUser{
    param(
        [ValidateNotNullOrEmpty()]
        [String]$UserDisplayName,
        [ValidateNotNullOrEmpty()]
        [String]$UserPrincipalName
    )
    
    #create a lab participant
    $user = Create-User -UserDisplayName $UserDisplayName -UserPrincipalName $UserPrincipalName
    #add evil to user admin
    $userAdminId = [guid]"fe930be7-5e62-47db-91af-98c3a49a38b1"
    $reportsReaderId = [guid]"4a5d8f65-41da-4de4-8968-e035b65339cf"
    Activate-EntraRole -roleTemplateId $userAdminId -userId $user.Id -userDisplayName $user.DisplayName
    Activate-EntraRole -roleTemplateId $reportsReaderId -userId $user.Id -userDisplayName $user.DisplayName
}


################################
################################
# Main function starts here
################################
################################

# Path to the secrets file
$secretsFilePath = "$($workDir)secrets.key"

<# sample secrets file
tenantDomain=labsnapshots.onmicrosoft.com
tenantId=bbbbbbbb-XXXX-XXXX-XXXX-aaaaaaaaaa
subscriptionId=bbbbbbbb-XXXX-XXXX-XXXX-aaaaaaaaaa
resourceGroupName=rg-snapshots-lab
LAWorkspaceName=la-workspace-lab
watchlistAlias=PreCompromise
clientId=bbbbbbbb-XXXX-XXXX-XXXX-aaaaaaaaaa
#>

# Read the secrets file and create a hash table
$secrets = Get-Content $secretsFilePath | ForEach-Object {
    $key, $value = $_.Split("=")
    @{ $key.Trim() = $value.Trim() }
}

$tenantDomain = $secrets.tenantDomain
$tenantId = $secrets.tenantId
$subscriptionId = $secrets.subscriptionId
$resourceGroupName = $secrets.resourceGroupName
$LAWorkspaceName = $secrets.LAWorkspaceName
$watchlistAlias = $secrets.watchlistAlias
$resourceId = $secrets.resourceId

$badinput = $false
# Validate tenantDomain
if ([string]::IsNullOrEmpty($tenantDomain) -or $tenantDomain.Length -gt 60 -or $secrets.tenantDomain -notmatch '^[a-zA-Z0-9.]+$') {
    Write-Host "Error: tenantDomain is invalid." -ForegroundColor Red
    $badinput = $true
}

# Validate tenantId
if (-not (Is-Guid -Guid $tenantId)) {
    Write-Host "Error: tenantId is not a valid GUID." -ForegroundColor Red
    $badinput = $true
}

# Validate subscriptionId
if (-not (Is-Guid -Guid $subscriptionId)) {
    Write-Host "Error: subscriptionId is not a valid GUID." -ForegroundColor Red
    $badinput = $true
}

# Validate resourceGroupName
if ([string]::IsNullOrEmpty($resourceGroupName) -or $resourceGroupName.Length -gt 60 -or $resourceGroupName -notmatch '^[a-zA-Z0-9-]+$') {
    Write-Host "Error: resourceGroupName is invalid." -ForegroundColor Red
    $badinput = $true
}

# Validate LAWorkspaceName
if ([string]::IsNullOrEmpty($LAWorkspaceName) -or $LAWorkspaceName.Length -gt 60 -or $LAWorkspaceName -notmatch '^[a-zA-Z0-9-]+$') {
    Write-Host "Error: LAWorkspaceName is invalid." -ForegroundColor Red
    $badinput = $true
}

# Validate watchlistAlias
if ([string]::IsNullOrEmpty($watchlistAlias) -or $watchlistAlias.Length -gt 60 -or $watchlistAlias -notmatch '^[a-zA-Z0-9-]+$') {
    Write-Host "Error: watchlistAlias is invalid." -ForegroundColor Red
    $badinput = $true
}

# Validate resourceId
if ([string]::IsNullOrEmpty($resourceId) -or $resourceId.Length -gt 250 -or $resourceId -notmatch '^[a-zA-Z0-9-/.]+$') {
    Write-Host "Error: resourceId is invalid." -ForegroundColor Red
    $badinput = $true
}

if($badinput){
    Write-Host "Exit = 1" -ForegroundColor Red
    return
}

# If all validations pass
Write-Host "All secret inputs are valid." -ForegroundColor Green


# delegated login
<#
[pscustomobject]@{ClientID='00b41c95-dab0-4487-9791-b9d2c32c80f2'; App='Office 365 Management'}
[pscustomobject]@{ClientID='18fbca16-2224-45f6-85b0-f7bf2b39b3f3'; App='Microsoft Docs'}
[pscustomobject]@{ClientID='1950a258-227b-4e31-a9cf-717495945fc2'; App='Microsoft Azure PowerShell'}
[pscustomobject]@{ClientID='1b730954-1685-4b74-9bfd-dac224a7b894'; App='Azure Active Directory PowerShell'}
[pscustomobject]@{ClientID='04b07795-8ddb-461a-bbee-02f9e1bf7b46'; App='Microsoft Azure CLI'}
#>

$azureCLIId = [guid]"04b07795-8ddb-461a-bbee-02f9e1bf7b46"
$microsoftDocsId = [guid]"18fbca16-2224-45f6-85b0-f7bf2b39b3f3"
$AppID = $azureCLIId
$AuthUri = "https://management.core.windows.net" #https://management.azure.com
Get-OauthTokens -AppID $AppID -AuthUri $AuthUri -Scope "user_impersonation" -TenantId $tenantId -TaskName "resourceTokens" #-AutoRefresh  -AutoRefreshInterval 1

$permissions = "User.ReadWrite.All AuditLog.Read.All RoleManagement.ReadWrite.Directory Directory.ReadWrite.All CustomSecAttributeAssignment.ReadWrite.All CustomSecAttributeDefinition.ReadWrite.All User.DeleteRestore.All User.ReadBasic.All Application.ReadWrite.All DelegatedPermissionGrant.ReadWrite.All AppRoleAssignment.ReadWrite.All"
Get-OauthTokens -Scope $permissions -TenantId $tenantId -TaskName "graphTokens" #-AutoRefresh #-AutoRefreshInterval 1

try {
    Connect-MgGraph -NoWelcome -AccessToken (ConvertTo-SecureString -String $graphTokens.access_token -AsPlainText -Force) -erroraction stop
} catch {
    Write-Host "Error: Failed to connect to graph $($_.Exception.Message) main" -BackgroundColor Black -ForegroundColor Red
    return
}

#Disconnect-MgGraph

#####
# Define custom security attribute values in Entra Id
#####
$attrValues = @(
    [PSCustomObject]@{ Id  = "isCompromised"; Status = "Available"; Type = "Boolean"; Description = "Malware has confirmed compromised this account." },
    [PSCustomObject]@{ Id  = "isNoise"; Status = "Available"; Type = "Boolean"; Description = "Lab Setup automation created an account to get in the way of the analyst."  },
    [PSCustomObject]@{ Id  = "isPermanent"; Status = "Available"; Type = "Boolean"; Description = "This account should not be touched by automation." }
)

$labAttributeSet = "SnapshotLabSet"
$attributeIsCompromised = "isCompromised"
$attributeIsNoise = "isNoise"
Setup-AttributeSet -attributeSetName $labAttributeSet -attributeSetDescription "Using this security tag for the lab experiment" -attributes $attrValues

########################################
#Create a pre-exploit list of users
########################################

#####
# create 20 random Entra Id users
# return userid of new users
#####
$numOfNewUsers = 20 # Generates 20 new users
write-host "################################################" -ForegroundColor Green
write-host "# Creating $numOfNewUsers distraction accounts" -ForegroundColor Green
write-host "################################################" -ForegroundColor Green

for( [int] $i=0; $i -lt $numOfNewUsers; $i++){
    $randDisplayName = Get-RandomName

    $user = Create-User -UserDisplayName $randDisplayName -UserPrincipalName ($randDisplayName -replace " ")
    
    Add-AttributeToUsers -userids $user.Id -attributeSet $labAttributeSet -attributeName $attributeIsNoise -attributeValue $true
}

$minutes = 4
Write-Host "Sleeping for $minutes minutes so auditlogs can catch up"
Start-Sleep -Milliseconds ($minutes * 60000) #sleep for 4 minutes
Write-Host "Sleeping done"

$saveCSVLocation = "$($workDir)EntraIds_Snapshot_preExploit_" + (get-date -format 'yyyyMMddTHHmmss') +".csv"
$preExploitList = Capture-Snapshot #-saveCSVLocation $saveCSVLocation

$preExploitListCSV = $preExploitList | ConvertTo-Csv
$preExploitListCSV = $preExploitListCSV[1..($preExploitListCSV.Length - 1)] -replace '"', '' -join "`n" #remove first line and perform some formatting

CreateUpdate-Watchlist -SubscriptionId $subscriptionId -LAWorkspaceName $LAWorkspaceName -ResourceGroupName $ResourceGroupName -WatchlistAlias "PreExploit_EntraSnapshot" `
        -Access_token $resourceTokens.access_token -Description "Watchlist from CSV content" -ItemsSearchKey "TargetName" -CsvContent $preExploitListCSV

########################################
# create the evil account
########################################
# evil account claims user admin
$user = Create-User -UserDisplayName "Edgar Lake" -UserPrincipalName "EdgarVilInLake"
Add-AttributeToUsers -userids $user.Id -attributeSet $labAttributeSet -attributeName $attributeIsCompromised -attributeValue $true

$user = get-mguser -userid 'EdgarVilInLake@pioler.onmicrosoft.com'

#add evil to user admin
$userAdminId = [guid]"fe930be7-5e62-47db-91af-98c3a49a38b1"
$cloudAppAdminId = [guid]"158c047a-c907-4556-b7ef-446551a6b5f7"
Activate-EntraRole -roleTemplateId $userAdminId -userId $user.Id -userDisplayName $user.DisplayName
Activate-EntraRole -roleTemplateId $cloudAppAdminId -userId $user.Id -userDisplayName $user.DisplayName
$permissions = "User.ReadWrite.All Directory.ReadWrite.All"
Grant-AppConsentBehalfOfUser -userUPNOrId $user.Id -TenantId $tenantId -user_permissions $permissions -Access_token $graphTokens.access_token # -debug

####################
# sleep randomly between 5 and 7 minutes
####################
$random = New-Object System.Random
$minutes = $random.Next(5, 8) # Generates a random number between 5 (inclusive) and 8 (exclusive)
# Convert minutes to milliseconds
$milliseconds = $minutes * 60 * 1000

Write-Host "Sleeping for $minutes minutes."
Start-Sleep -Milliseconds $milliseconds

################################################
# Login from Russia ip using vpn
################################################
# Name the account Evil
Write-Host "Please connect your VPN, then hit any key to continue. log into evil" -ForegroundColor DarkYellow
pause

#connect to graph with graph powershell
$scopes = "User.ReadWrite.All Directory.ReadWrite.All"
Get-OauthTokens -TenantId $tenantId  -TaskName "evilGraphTokens" -Scope $scopes #-AutoRefresh

try {
    Disconnect-MgGraph
    #Connect-MgGraph -NoWelcome -UseDeviceCode 
    Connect-MgGraph -NoWelcome -AccessToken (ConvertTo-SecureString -String $evilGraphTokens.access_token -AsPlainText -Force) -erroraction stop
} catch {
    Write-Host "Error: Failed to connect to graph $($_.Exception.Message) main" -BackgroundColor Black -ForegroundColor Red
    return
}

################################################
# Create 1 internal persistent account
################################################
# evil persistence account claims sharepoint and teams admin
$persistInteralDisplayName =  "Welma Hildo"
$persistInternalUser = Create-User -UserDisplayName $persistInteralDisplayName -UserPrincipalName ($persistInteralDisplayName -replace " ")
#Start-Sleep -seconds 60 # sleep 1 minute

################################################
# Create 1 external persistent account
################################################
#invite one persistent account

#call 2 different persistence methods to make it clear

$persistExtDisplayName = 'EdgarVilInLake'
$persistExtUPN = 'yah00.com'
Invoke-InviteGuest -Tokens $evilGraphTokens -EmailAddress ($persistExtDisplayName + '@' + $persistExtUPN) -displayname $persistExtDisplayName -CustomMessageBody 'backdoor' -RedirectUrl '' -SendInvitationMessage $false
Start-Sleep -seconds 60 # sleep 1 minute
$persistExtUser = Get-MgUser -UserId ($persistExtDisplayName + '_' + $persistExtUPN + '#EXT#@' + $tenantDomain)

Write-Host "Done with evil account." -ForegroundColor Green
Write-Host "Time to log into a random good account to create noise. Please change vpn, log into office.com, and continue"
pause

Write-Host "Done with noise account sigin. Please turn off vpn and continue"
pause

################################################
# Mark the persistence accounts as compromised
################################################
try {
    Disconnect-MgGraph
    Connect-MgGraph -NoWelcome -AccessToken (ConvertTo-SecureString -String $graphTokens.access_token -AsPlainText -Force) -erroraction stop
    
} catch {
    Write-Host "Error: Failed to connect to graph $($_.Exception.Message) main" -BackgroundColor Black -ForegroundColor Red
    return
}
Add-AttributeToUsers -userids $persistInternalUser.Id -attributeSet $labAttributeSet -attributeName $attributeIsCompromised -attributeValue $true
Add-AttributeToUsers -userids $persistExtUser.Id -attributeSet $labAttributeSet -attributeName $attributeIsCompromised -attributeValue $true

# remove admin roles from edgar
Remove-EntraRole -roleTemplateId $userAdminId -userId $user.Id -userDisplayName $user.DisplayName
Remove-EntraRole -roleTemplateId $cloudAppAdminId -userId $user.Id -userDisplayName $user.DisplayName

################################################
# create one more distraction account
################################################
$randDisplayName = "Peyton Mayor"
$user = Create-User -UserDisplayName $randDisplayName -UserPrincipalName ($randDisplayName -replace " ")
Add-AttributeToUsers -userids $user.Id -attributeSet $labAttributeSet -attributeName $attributeIsNoise -attributeValue $true
Start-Sleep -seconds 60 # sleep 1 minute

################################################
# Create 1 high privileged spn (cutting this out)
################################################
# Invoke-InjectOAuthApp


$saveCSVLocation = "$($workDir)EntraIds_Snapshot_postExploit_" + (get-date -format 'yyyyMMddTHHmmss') +".csv"
$postExploitList = Capture-Snapshot #-saveCSVLocation $saveCSVLocation
$postExploitListCSV = $postExploitList | ConvertTo-Csv
$postExploitListCSV = $postExploitListCSV[1..($postExploitListCSV.Length - 1)] -replace '"', '' -join "`n" #remove first line and perform some formatting

CreateUpdate-Watchlist -SubscriptionId $subscriptionId -LAWorkspaceName $LAWorkspaceName -ResourceGroupName $ResourceGroupName -WatchlistAlias "PostExploit_EntraSnapshot" `
        -Access_token $resourceTokens.access_token -Description "Watchlist from CSV content" -ItemsSearchKey "TargetName" -CsvContent $postExploitListCSV

<#
Clean-Lab

## check permissions
#(Find-MgGraphCommand -Command Get-MgAuditLogDirectoryAudit).permissions
RoleAssignmentSchedule.ReadWrite.Directory
write-host "Microsoft Graph Command Line Tools | Permissions"
(get-mgcontext).scopes | sort

Disconnect-MgGraph
#>

