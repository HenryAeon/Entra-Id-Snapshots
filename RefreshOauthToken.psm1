<#
.SYNOPSIS
    Get-OauthTokens uses devicecode authentication method to retrieve a Microsoft oauth token and stores tokens in the global $tokens 

.DESCRIPTION
    Get-GraphTokens is the main user authentication module for GraphRunner. Upon authenticating it will store your tokens in the global $tokens variable as well as the tenant ID in $tenantid. To use them with other GraphRunner modules use the Tokens flag (Example. Invoke-DumpApps -Tokens $tokens)     
    Author: Henry Lopez
    License: MIT
    Last Update: 17 Nov 2024

.PARAMETER AppId
    The app id of the app we are using to connect to Azure. Default is the graph command line app

.PARAMETER AuthUri
    The uri to have the app authenticate. Default is https://graph.microsoft.com/
    
.PARAMETER UserAgent
    The user agent to spoof. Default is a random agent

.PARAMETER TenantId
    Required - The tenant to join the app
    
.PARAMETER Scope
    The permissions for the app. Default is openid

.PARAMETER AutoRefreshInterval
    The time between refreshing the oauth token. Must be paired with AutoRefresh flag. Default is 59 minutes

.PARAMETER AutoRefresh
    Flag to enable auto refreshing the oauth token within the same powershell session. Default is no auto refreshing.

.PARAMETER TaskName
    Variable will be used to name the background task and the global variable to assign the tokens
    
.EXAMPLE
    # Ask user to authenticate using a device code auth on a browser, then return the MS graph command line app with User and audit log permissions. 
    # Refresh token while command line is open every 30 minutes. Then token will be set in global variable $token
    $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36'
    Get-OauthTokens -Scope "User.ReadWrite.All AuditLog.Read.All" -UserAgent $UserAgent -AutoRefresh -AutoRefreshInterval 30
#>
function Get-OauthTokens{
    param(
    [ValidateNotNullOrEmpty()]
    [String]$AppId = "14d82eec-204b-4c2f-b7e8-296a70dab67e", #default graph command line app
    [ValidateNotNullOrEmpty()]
    [String]$AuthUri = "https://graph.microsoft.com", #default graph login
    [String]$UserAgent = '',

    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [guid]$TenantId,
    [String]$Scope = 'openid',
    [switch]$AutoRefresh,
    [int]$AutoRefreshInterval = 59, #59 minutes
    [string]$TaskName = "tokens"
    )

    Write-debug "Get-OauthTokens`n`t`$AppId = $AppID `n`t`$AuthUri = $AuthUri `n`t`$UserAgent = $UserAgent `n`t`$Scope = $Scope `n`t`$AutoRefresh = $AutoRefresh`n`t`$AutoRefreshInterval = $AutoRefreshInterval"

    #setup the user-agent
    if ($UserAgent.Length -eq 0) {
		$UserAgent = Get-ForgedUserAgent
    }

    #########################################
    # Grab a devicecode before we access the app
    #########################################
    Write-Verbose "[*] Grabbing device Code"
    $body = @{
        "client_id" =     $AppId
        "resource" =      $AuthUri
    }
    $headers=@{"User-Agent" = $UserAgent}

    Write-debug "`nbody: $($body | ConvertTo-Json) `nheaders: $($headers | ConvertTo-Json)"

    try {
        #########################################
        # Grab a devicecode
        #########################################
        $authResponse = Invoke-RestMethod -UseBasicParsing -Method Post -Headers $headers -Body $body `
            -Uri "https://login.microsoftonline.com/$TenantId/oauth2/devicecode?api-version=1.0"
    } catch {
        Write-Host "Error: $($_.ErrorDetails.Message)" -ForegroundColor Red
    }

    Write-Host -ForegroundColor yellow $authResponse.Message

    $attempt_counts = 0 # 5 minutes of waiting
    while ($attempt_counts -le 6000) {
        $body = @{
            "client_id"   = $AppID
            "grant_type"  = "urn:ietf:params:oauth:grant-type:device_code" #required
            "code"        = $authResponse.device_code
            "scope"       = $Scope
        }
        Write-debug "`$body = $($body | ConvertTo-Json)"

        try {
            #########################################
            # Using the devicecode access obtain the oauth for the app
            #########################################
            $tokens = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/token?api-version=1.0" -Headers $Headers -Body $body
        } catch {
            $error_details = $_.ErrorDetails.Message | ConvertFrom-Json

            if( ($error_details.error_codes | Select-String 70016).count){
                #ignore authorization_pending
                $attempt_counts++
                Start-Sleep -Seconds 3
                continue
            }

            # any other error we must stop
            Write-Host "Error: $($_.ErrorDetails.Message | ConvertFrom-Json).error" -ForegroundColor Red
            return
        }

        #decode the token to grab the expiration time
        $accessJWT = Convert-AccessToken $tokens.access_token

        $a = Set-Variable -Name $TaskName -Value $tokens -Scope global
        Set-Variable -Name 'bobby' -Value 'hi' -Scope global


        Write-Host -ForegroundColor Green "[$(Get-Date -Format HH:mm)] Successful authentication. Access and refresh tokens written to `$$TaskName. Token expires [$(Get-Date (Convert-AccessToken $tokens.access_token).expireLocalTime -Format HH:mm)]"
        #Write-Host -ForegroundColor Green '[*] Successful authentication. Access and refresh tokens written to the $tokens'
        #Write-Verbose "Access token expiration: $($accessJWT['expireLocalTime'])"

        break
    }

    if($attempt_counts -gt 6000){
        Write-Host "Error: Devicecode signin timeout. Try calling the command again" -ForegroundColor Red
    }

    #create the reauthenticate function to pass to the background job
    if($AutoRefresh){
        AutoRefreshToken -TaskName $TaskName -tenantid $tenantid -AppID $AppID -Scope $Scope `
                -AuthUri $AuthUri -UserAgent $UserAgent -AutoRefreshInterval $AutoRefreshInterval
    }
}

function AutoRefreshToken{
<#
.SYNOPSIS
    Private function that auto refresh a Microsoft Oauth tokens.

.DESCRIPTION
    This module is a private function for RefreshToken to refresh an Microsoft Oauth token
    Author: Henry Lopez
    Last Update: 21 Nov 2024

.PARAMETER TaskName
    The name of the task and global variable

.PARAMETER TenantId
    Supply a tenant domain or ID to authenticate to.
        
.PARAMETER AppId
    Supply a application id that we want to use to authenticate with. Default is graph command line app
    
.PARAMETER Scope
    Supply the permissions for the app. Default is openid.
    
.PARAMETER AuthUri
    Supply the authentication uri that the app will use. Default is graph.
    
.PARAMETER UserAgent
    Supply a user agent to mask the request
    
.PARAMETER AutoRefreshInterval
    Supply an interval in minutes to refresh the token. Default 59 minutes.
    
.EXAMPLE
    #Refresh token to aquire a new access_token and refresh_token, save it to the $tokenGraph variable and to the Outfile.
    AutoRefreshToken -TaskName "tokenGraph" -TenantId $tenantid -AppId $AppID -Scope "user_impersonate" -AuthUri $AuthUri -UserAgent $UserAgent -AutoRefreshInterval 30
#>
    param(
    [ValidateNotNullOrEmpty()]
    [String]$TaskName,
    [ValidateNotNullOrEmpty()]
    [String]$tenantid,
    [ValidateNotNullOrEmpty()]
    [String]$AppID,
    [ValidateNotNullOrEmpty()]
    [String]$Scope,
    [ValidateNotNullOrEmpty()]
    [String]$AuthUri,
    [ValidateNotNullOrEmpty()]
    [String]$UserAgent,
    [Parameter(Mandatory=$True)]
    [int]$AutoRefreshInterval
    )

    #######################################
    #cleanup any previous refresh task
    #######################################
    #lets run the function on a timer
    $eventName = $TaskName + 'Task'
    try{
        #$timerEvent = Get-EventSubscriber | Where-Object { $_.SourceObject -eq $script:timer }
        $timerEvent = Get-EventSubscriber -SourceIdentifier $eventName -ErrorAction Stop
    }catch{
        $timerEvent = $null
    }
    if($timerEvent){
        #timer already exists
        Write-Host -ForegroundColor Yellow "Warning: Found the refresh old event. Performing cleanup."
        $timerEvent.SourceObject.stop()

        $j = $timerEvent.Action
        $timerEvent | %{Get-EventSubscriber | Unregister-Event -Force -ErrorAction SilentlyContinue }
        $j | Remove-Job
    }

    #make a background task to refresh the token
    Write-Debug "`n`t`$refresh = $($tokens.refresh_token)`n`t`$TenantId = $tenantid`n`t`$AppID = $AppID`n`t`$Scope = $Scope`n`t`$AuthUri = $AuthUri`n`t`$UserAgent = $UserAgent`n`t`$AutoRefreshInterval = $AutoRefreshInterval"

    $timer = New-Object Timers.Timer
    $timer.Interval = $AutoRefreshInterval * 60000 # $AutoRefreshInterval minutes (60000 is a minute)
    $timer.AutoReset = $true

    $ActionArgs = @{
        TaskName = $taskName
        TenantId = $tenantid 
        AppId = $AppID 
        Scope = $Scope 
        AuthUri = $AuthUri
        UserAgent = $UserAgent
        AutoRefreshInterval = $AutoRefreshInterval
    }

    #######################################
    #start the job
    #######################################

    $eventRefresh = Register-ObjectEvent -SourceIdentifier $eventName -InputObject $timer -EventName Elapsed -MessageData $ActionArgs -Action {
        $EventTaskName = $Event.MessageData.taskname
        $EventTenantId = $Event.MessageData.tenantid 
        $EventAppId = $Event.MessageData.AppID 
        $EventScope = $Event.MessageData.Scope 
        $EventAuthUri = $Event.MessageData.AuthUri
        $EventUserAgent = $Event.MessageData.UserAgent
        $EventInterval = $Event.MessageData.AutoRefreshInterval
        $EventToken = (Get-Variable -Name $EventTaskName -Scope global).Value

        Write-Host "Register-ObjectEvent`t`$EventTaskName = $EventTaskName`n`t`$refresh = $($EventToken.refresh_token.Substring($EventToken.refresh_token.Length - 10)) `n`t`$EventTenantId =  $EventTenantId `n`t`$AppID =  $EventAppId `n`t`$Scope =  $EventScope`n`t`$AuthUri =  $EventAuthUri `n`t`$EventUserAgent = $EventUserAgent`n`t`$EventInterval = $EventInterval"
        
        #stop the timer
        (Get-EventSubscriber -SourceIdentifier $eventName).SourceObject.stop()

        $authUrl = "https://login.microsoftonline.com/$EventTenantId/oauth2/token"
        $headers=@{"User-Agent" = $EventUserAgent}
        $body = @{
            "resource" =      $EventAuthUri
            "client_id" =     $EventAppId
            "grant_type" =    "refresh_token"
            "scope"=          $EventScope
        }

        while ($true){
            Write-Host "[$(Get-Date -Format HH:mm)] Refreshing `$$EventTaskName Oauth Tokens..." -ForegroundColor yellow
        
            $EventToken = (Get-Variable -Name $EventTaskName -Scope global).Value
            $body["refresh_token"] = $EventToken.refresh_token

            #Write-Host "InfLoop`t`$EventTaskName = $EventTaskName`n`t`$body = $($body | ConvertTo-Json)"
        
            try {
                $newtoken = Invoke-RestMethod -UseBasicParsing -Method Post -Uri $authUrl -Headers $headers -Body $body
            } catch {
                Write-Host "Error: $(($_.ErrorDetails.Message | ConvertFrom-Json).error)" -BackgroundColor Black -ForegroundColor Red
                return
            }

            #Write-Host "Completed newtoken`n`t`$newtoken = $($newtoken | ConvertTo-Json)"

            if($newtoken){
                #success, save the token
                Set-Variable -Name $EventTaskName -Value $newtoken -Scope global
                Write-Host -ForegroundColor Green "[$(Get-Date -Format HH:mm)] Successful refresh. Access and refresh tokens written to `$$EventTaskName. Token expires [$(Get-Date (Convert-AccessToken $newtoken.access_token).expireLocalTime -Format HH:mm)]"
            } else {
                #error, stop the background task
                Write-Host -ForegroundColor Red -BackgroundColor Black "[$(Get-Date -Format HH:mm)] Failed to refresh. Canceling `$EventTaskName Task"
                try{
                    $timerEvent = Get-EventSubscriber -SourceIdentifier $EventTaskName -ErrorAction Stop
                    $timerEvent.SourceObject.Stop() #stop the timer
                    $timerEvent | %{$_ | Unregister-Event }
                }catch{}
                return
            }

            #Write-Host "Sleeping for $EventInterval minutes"
            Start-Sleep -Seconds ($EventInterval * 60) # $AutoRefreshInterval minutes (60s is a minute)
        }#end of while
    }# Register-ObjectEvent
    
    $timer.Start()

    Write-Host -ForegroundColor Green "[*] Created token refresh background task $eventName every $AutoRefreshInterval minutes until powershell closes"
}#end of AutoRefreshToken


<#
.SYNOPSIS
    Convert-AccessToken takes an Microsoft accesstoken converts it and returns it as a JWT

.DESCRIPTION
    Convert-AccessToken decodes the accesstoken into a JWT and returns it has a hashtable with expiration date in local time.
    Author: Henry Lopez
    License: MIT
    Last Update: 19 Nov 2024

.PARAMETER access_token
    The access token that needs to be decoded

.EXAMPLE
    # Ask user to authenticate using a device code auth on a browser, then return the MS graph command line app with User and audit log permissions. 
    # Refresh token while command line is open every 30 minutes. Then token will be set in global variable $token
    $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36'
    Decode-AccessToken $token.access_token
#>
function Convert-AccessToken{
    param(
    [ValidateNotNullOrEmpty()]
    [String]$access_token
    )

    Write-Debug "`n`t`$access_token = $access_token"

    #########################################
    # decode the access token, take last part, convert and decode base64
    #########################################
    $encodedPayload = $access_token.Split(".")[1].Replace('-', '+').Replace('_', '/')
    while ($encodedPayload.Length % 4) { $encodedPayload += "=" }
    $accessJWT = [System.Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($encodedPayload)) | ConvertFrom-Json
    
    #hash the table, add the expiration time
    $ret_hashJWT = @{}
    foreach ($member in $accessJWT.PSObject.Properties) { $ret_hashJWT[$member.Name] = $member.Value }
    $ret_hashJWT['expireLocalTime'] = [System.DateTimeOffset]::FromUnixTimeSeconds($accessJWT.exp).LocalDateTime

    Write-Debug "Decoded JWT payload:`n`t`$ret_hashJWT = $($ret_hashJWT | ConvertTo-Json)"
    Write-Verbose "Access token expiration: $($ret_hashJWT['expireLocalTime'])"

    return $ret_hashJWT
}

<#
.SYNOPSIS
    Select a useragent from a pre define list of devices and/or browsers

.DESCRIPTION
    Select a useragent from the list of devices and/or browsers. No params is a random user agent. This is good for masking your actions when making requests on the internet.
    Author: Henry Lopez
    Last Update: 17 Nov 2024

.PARAMETER Device
    Select a device that will be spoof the request

.PARAMETER Browser
    Select a browser on the device that will be spoof the request
    
.EXAMPLE
    #Get a random useragent
    Get-ForgedUserAgent
    
.EXAMPLE
    #Get a random Device with browser Vivaldi
    Get-ForgedUserAgent -Browser Vivaldi
    
.EXAMPLE
    #Get a Mac Device with browser Edge
    Get-ForgedUserAgent -Device Mac -Browser Vivaldi
#>
function Get-ForgedUserAgent {
    param (
    [ValidateSet('Mac','Windows','Linux','Android','iPad','iPhone')]
    [String]$Device, 
    [ValidateSet('Safari', 'Opera', 'Firefox', 'Edge', 'Chrome', 'Brave', 'Vivaldi','Midori', 'Falkon')]
    [String]$Browser
    )

    #create a list of some user agents
    $userAgents = @{
        Windows = @{
            Chrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            Firefox = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
            Edge = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59"
            Opera = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 OPR/77.0.4054.172"
            Brave = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Brave/91.0.4472.124"
        }
        Mac = @{
            Safari = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15"
            Chrome = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            Firefox = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0"
            Opera = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15.7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 OPR/77.0.4054.172"
            Edge = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59"
        }
        Linux = @{
            Chrome = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            Firefox = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"
            Opera = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 OPR/77.0.4054.172"
            Brave = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Brave/91.0.4472.124"
            Vivaldi = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Vivaldi/4.1.2369.21"
            Midori = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Midori/1.1.3 Chrome/91.0.4472.124 Safari/537.36"
            Falkon = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Falkon/3.1.0 Chrome/91.0.4472.124 Safari/537.36"
            Edge = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59"
        }
        iPhone = @{
            Safari = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"
            Chrome = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/537.36 (KHTML, like Gecko) CriOS/91.0.4472.124 Mobile/15E148 Safari/604.1"
            Firefox = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/34.0 Mobile/15E148 Safari/605.1.15"
            Opera = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/537.36 (KHTML, like Gecko) OPiOS/68.0.3590.178 Mobile/15E148 Safari/605.1.15"
            Edge = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) EdgiOS/91.0.4472.124 Mobile/15E148 Safari/604.1"
        }
        iPad = @{
            Safari = "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"
            Chrome = "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/537.36 (KHTML, like Gecko) CriOS/91.0.4472.124 Mobile/15E148 Safari/604.1"
            Firefox = "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/34.0 Mobile/15E148 Safari/605.1.15"
            Opera = "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/537.36 (KHTML, like Gecko) OPiOS/68.0.3590.178 Mobile/15E148 Safari/605.1.15"
            Edge = "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) EdgiOS/91.0.4472.124 Mobile/15E148 Safari/604.1"
        }
        Android = @{
            Chrome = "Mozilla/5.0 (Linux; Android 11; SM-G998U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36"
            Firefox = "Mozilla/5.0 (Android 11; Mobile; rv:89.0) Gecko/89.0 Firefox/89.0"
            Opera = "Mozilla/5.0 (Linux; Android 11; SM-G998U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36 OPR/77.0.4054.172"
            Brave = "Mozilla/5.0 (Linux; Android 11; SM-G998U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36 Brave/91.0.4472.124"
            Edge = "Mozilla/5.0 (Linux; Android 11; SM-G998U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36 EdgA/91.0.864.59"
        }
    }

    # Browser specified, no device
    if(-not $Device -and $Browser){
        #grab a list of devices that contain our browser
        $deviceMatches = $userAgents.Keys | ? { $userAgents[$_].ContainsKey($Browser) }
        if (-not $deviceMatches) {
            #no devices has the desired browser
            Write-Host "Error: No devices have the desired browser $Browser. Selecting a random agent" -ForegroundColor Red
            $Browser = $null
        } else {
            $Device = Get-Random -InputObject @($deviceMatches)
        }
    }
        
    # Device specified, no Browser
    if($Device -and -not $Browser){
        $deviceMatches = $userAgents.ContainsKey($Device)
        if(-not $deviceMatches){
            Write-Host "Error: No devices matching the desired device $Device. Selecting a random agent" -ForegroundColor Red
            $Device = $null
        }else{
            $Browser = Get-Random -InputObject @($userAgents[$Device].Keys)
        }
    }
    
    # no device and browser specified, select randomly
    if(-not ($Device -or $Browser)){
        $Device = Get-Random -InputObject @($userAgents.Keys)
        $Browser = Get-Random -InputObject @($userAgents[$Device].Keys)
    }

    #grab the user's device and browser
    $retAgent = $userAgents[$Device][$Browser]

    if( -not $retAgent ){
        #something went wrong, return a default agent
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59"
    }

    return $retAgent
} # end of Get-ForgedUserAgent

<#
.SYNOPSIS
    Select a useragent from a pre define list of devices and/or browsers

.DESCRIPTION
    Select a useragent from the list of devices and/or browsers. No params is a random user agent. This is good for masking your actions when making requests on the internet.
    Author: Henry Lopez
    Last Update: 19 Nov 2024

.PARAMETER Device
    Select a device that will be spoof the request

.PARAMETER Browser
    Select a browser on the device that will be spoof the request
    
.EXAMPLE
    #Get a random useragent
    Get-ForgedUserAgent
    
.EXAMPLE
    #Get a random Device with browser Vivaldi
    Get-ForgedUserAgent -Browser Vivaldi
    
.EXAMPLE
    #Get a Mac Device with browser Edge
    Get-ForgedUserAgent -Device Mac -Browser Vivaldi
#>
function Get-Fosomethingent {
    param (
    [ValidateSet('Mac','Windows','Linux','Android','iPad','iPhone')]
    [String]$Device, 
    [ValidateSet('Safari', 'Opera', 'Firefox', 'Edge', 'Chrome', 'Brave', 'Vivaldi','Midori', 'Falkon')]
    [String]$Browser
    )


    return $retAgent
} # end of Get-ForgedUserAgent


# 
# call Connect-MgGraph before this function
# Add-AttributeToUsers
# provide a list of users ids
# 
function Add-AttributeToUsers {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$userids,

        [Parameter(Mandatory=$true)]
        [string]$attributeName,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [object]$attributeValue,

        [Parameter(Mandatory=$true)]
        [string]$attributeSet
    )

    if ($attributeValue -isnot [string] -and $attributeValue -isnot [bool]) {
        Write-Host "$targetValue is not a string or bool" -ForegroundColor Red
        return $null
    }


    foreach ($userid in $userids) {
        $customSecurityAttr = @{
            $attributeSet = @{
	            "@odata.type" = "#Microsoft.DirectoryServices.CustomSecurityAttributeValue"
	            $attributeName = $attributeValue
            }
        }

        # Get the user by ID
        try {
            Update-MgUser -UserId $userid -CustomSecurityAttributes $customSecurityAttr
        } catch {
            Write-Host "Error: User not found or invalid user ID. $($userid)"
            continue
        }
    } # end of for each user loop
}

# Export only the public function
Export-ModuleMember -Function Get-OauthTokens
Export-ModuleMember -Function Convert-AccessToken
Export-ModuleMember -Function Get-ForgedUserAgent
Export-ModuleMember -Function Add-AttributeToUsers
#Export-ModuleMember -Function RefreshToken
