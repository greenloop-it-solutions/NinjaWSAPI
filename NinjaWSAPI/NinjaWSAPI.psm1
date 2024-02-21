#Requires -Modules TOTP

# TOTP Module is from https://github.com/ecspresso/TOTPPowerShellModule. Install-ModuleFromGithub has some issues and requires admin.

# Install-ModuleFromGitHub -GitHubRepo ecspresso/TOTPPowerShellModule

if (!$NINJA_BASE_FQDN) {
    $NINJA_BASE_FQDN = 'app.ninjarmm.com' #if not defined, will use the default 'us' instance.
}

function New-NinjaWSSession {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Username,
        
        [Parameter(Mandatory=$true)]
        [string]$UserPassword,
        
        [Parameter(Mandatory=$true)]
        [string]$MfaToken
    )
    
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $session.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0"
    $loginResponse = Invoke-RestMethod -UseBasicParsing -Uri "https://$NINJA_BASE_FQDN/ws/account/login" `
    -Method "POST" `
    -WebSession $session `
    -ContentType "application/json" `
    -Body "{`"email`":`"$username`",`"password`":`"$userPassword`",`"staySignedIn`":false}"

    $loginToken = $loginResponse.loginToken

    $mfaResponse = Invoke-RestMethod -UseBasicParsing -Uri "https://$NINJA_BASE_FQDN/ws/account/mfa-login" `
    -Method "POST" `
    -WebSession $session `
    -ContentType "application/json" `
    -Body "{`"loginToken`":`"$loginToken`",`"code`":`"$mfaToken`"}"

    $sessionKey = $mfaResponse.sessionKey
    $sessionKey
}

function Get-NinjaWSClientOrgs ($SESSIONKEY) {
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $session.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0"
    $session.Cookies.Add((New-Object System.Net.Cookie("sessionKey", "$SESSIONKEY", "/", "$NINJA_BASE_FQDN")))
    $clientList = Invoke-RestMethod -UseBasicParsing -Uri "https://$NINJA_BASE_FQDN/ws/client/list" `
    -WebSession $session
    $clientList
}

function Get-NinjaWSClientById ($clientId,$SESSIONKEY) {
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $session.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0"
    $session.Cookies.Add((New-Object System.Net.Cookie("sessionKey", "$SESSIONKEY", "/", "$NINJA_BASE_FQDN")))
    $client = Invoke-RestMethod -UseBasicParsing -Uri "https://$NINJA_BASE_FQDN/ws/client/$($clientId)" -WebSession $session
    $client.client
}

function Get-NinjaWSPolicyList ($SESSIONKEY) {
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $session.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0"
    $session.Cookies.Add((New-Object System.Net.Cookie("sessionKey", "$SESSIONKEY", "/", "$NINJA_BASE_FQDN")))
    $policyList = Invoke-RestMethod -UseBasicParsing -Uri "https://$NINJA_BASE_FQDN/ws/policy/list?nodeClassGroup=RMM" `
    -WebSession $session
    $policyList  
}

function Get-NinjaWSPolicy ($SESSIONKEY,$policyId) {
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $session.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0"
    $session.Cookies.Add((New-Object System.Net.Cookie("sessionKey", "$SESSIONKEY", "/", "$NINJA_BASE_FQDN")))
    $policy = Invoke-RestMethod -UseBasicParsing -Uri "https://$NINJA_BASE_FQDN/ws/policy/$($policyId)" `
    -WebSession $session
    $policy  
}

function Get-NinjaWSOrgPolicyMap ($orgId,$SESSIONKEY) {
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $session.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0"
    $session.Cookies.Add((New-Object System.Net.Cookie("sessionKey", "$SESSIONKEY", "/", "$NINJA_BASE_FQDN")))
    $response = Invoke-RestMethod -UseBasicParsing -Uri "https://$NINJA_BASE_FQDN/ws/client/$($orgId)" `
    -WebSession $session
    $response.client.nodeRolePolicyMap
}

function Create-NinjaWSInheritedPolicy ($nodeClass,$policyName,$inheritedPolicyId,$SESSIONKEY) {
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $session.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0"
    $session.Cookies.Add((New-Object System.Net.Cookie("sessionKey", "$SESSIONKEY", "/", "$NINJA_BASE_FQDN")))
    Invoke-NinjaWSRestMethod -Uri "https://$NINJA_BASE_FQDN/ws/policy" `
    -Method "POST" `
    -SESSIONKEY $SESSIONKEY `
    -ContentType "application/json" `
    -Body "{`"enabled`":true,`"name`":`"$policyName`",`"nodeClassDefault`":false,`"nodeClass`":`"$nodeClass`",`"description`":null,`"parentPolicyId`":$inheritedPolicyId}"
}

function Get-NinjaWSPolicyByID ($policyid,$SESSIONKEY) {
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $session.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
    $session.Cookies.Add((New-Object System.Net.Cookie("sessionKey", "$SESSIONKEY", "/", "$NINJA_BASE_FQDN")))
    $response = Invoke-RestMethod -UseBasicParsing -Uri "https://$NINJA_BASE_FQDN/ws/policy/$($policyid)" -WebSession $session -Method Get
    $response.policy
}

function Update-NinjaWSPolicyMapMapping ($orgId,$nodeRoleId,$policyid,$SESSIONKEY) {
    #get policymap for $org
    $policymap = Get-NinjaWSOrgPolicyMap -orgId $orgId -SESSIONKEY $Sessionkey
    $policy = Get-NinjaWSPolicyByID -policyId $PolicyId -SESSIONKEY $Sessionkey
    #update node in policymap
    foreach ($item in $policymap) {
        if ($item.nodeRoleId -eq $nodeRoleId) {
            $item.policyId = $policyId
            $item.policyName = $policy.name
            break  # Exit the loop once the item is found and updated
        }
    }

    $body = Get-NinjaWSClientById -clientId $orgId -SESSIONKEY $SessionKey

    $body.nodeRolePolicyMap = $policyMap
    $body = $body | ConvertTo-Json -Depth 10
    
    #update organization with new body
    Invoke-NinjaWSRestMethod -Uri "https://$NINJA_BASE_FQDN/ws/client/$($orgID)" `
    -Method "PUT" `
    -SESSIONKEY $Sessionkey `
    -ContentType "application/json" `
    -Body $body

}

function Patch-NinjaWSPolicyByID ($policyid,$policy,$SESSIONKEY) {
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $session.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
    $session.Cookies.Add((New-Object System.Net.Cookie("sessionKey", "$SESSIONKEY", "/", "$NINJA_BASE_FQDN")))
    $policy = $policy | ConvertTo-Json -Depth 10

    Invoke-NinjaWSRestMethod -Uri "https://$NINJA_BASE_FQDN/ws/policy/$($policyid)" -Method "PUT" -SESSIONKEY $SESSIONKEY -ContentType 'application/json' -Body $policy

}

function Get-NinjaWSGlobalCustomFields {
    param (
        [string]$CustomFieldScope,
        [ValidateSet("AllTypes","Organization", "Location", "Device")]
        [string]$AllowedSelections = "AllTypes",
        [string]$SESSIONKEY
    )

    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $session.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
    $session.Cookies.Add((New-Object System.Net.Cookie("sessionKey", "$SESSIONKEY", "/", "$NINJA_BASE_FQDN")))

    switch ($CustomFieldScope) {

        "Organization" {
            Write-Host "Custom field type is Organization."
            $optionalURIString = "?definitionScope=ORGANIZATION"

        }
        "Location" {
            Write-Host "Custom field type is Location."
            $optionalURIString = "?definitionScope=LOCATION"
        }
        "Device" {
            Write-Host "Custom field type is Device."
            $optionalURIString = "?definitionScope=NODE"
        }
        "AllTypes" {
            Write-Host "Custom field type is AllTypes."
            $optionalURIString = ""
        }
        default {
            Write-Host "Unknown custom field type: $CustomFieldScope. Returning AllTypes instead."
            $optionalURIString = ""
        }
    }

    Invoke-RestMethod -UseBasicParsing -Uri "https://$NINJA_BASE_FQDN/ws/attributes/node/global$optionalURIString" `
        -WebSession $session `
        -ContentType "application/json"

}

function Get-NinjaGlobalOrgCustomFieldValues ($orgId,$SESSIONKEY) {
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $session.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
    $session.Cookies.Add((New-Object System.Net.Cookie("sessionKey", "$SESSIONKEY", "/", "$NINJA_BASE_FQDN")))
    $OrgFieldValues = Invoke-RestMethod -UseBasicParsing -Uri "https://$NINJA_BASE_FQDN/ws/attributes/node/client/$($orgId)/values" `
    -Method "Get" `
    -WebSession $session `
    -ContentType "application/json"
    $OrgFieldValues
}

function Get-NinjaGlobalOrgCustomFieldValue ($orgId,$customFieldName,$SESSIONKEY) {
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $session.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
    $session.Cookies.Add((New-Object System.Net.Cookie("sessionKey", "$SESSIONKEY", "/", "$NINJA_BASE_FQDN")))

    $customFields = Get-NinjaWSGlobalCustomFields -customfieldscope Organization -SESSIONKEY $SESSIONKEY
    $field = $customFields | ?{$_.fieldName -eq $customFieldName}

    if ($field) {
        $orgFieldValues = Invoke-RestMethod -UseBasicParsing -Uri "https://$NINJA_BASE_FQDN/ws/attributes/node/client/$($orgId)/values" `
        -Method "Get" `
        -WebSession $session `
        -ContentType "application/json"
        $orgFieldValues | ? {$_.attributeId -eq $field.id} | Select id,attributeId,value
    } else {
        throw "Custom Field with name $customFieldName not found!" 
    }
}

#May need to be updated to use the "retry" Rest method, TBD
#Currently it updates timestamps and UpdatedBy on each pass. See if we can include this in the dataset (update the get-{value} function)
function Set-NinjaWSOrgCustomFieldValue ($orgId,$customFieldName,$newCustomFieldValue,$SESSIONKEY) {
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $session.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
    $session.Cookies.Add((New-Object System.Net.Cookie("sessionKey", "$SESSIONKEY", "/", "$NINJA_BASE_FQDN")))

    $customFields = Get-NinjaWSGlobalCustomFields -customfieldscope Organization -SESSIONKEY $SESSIONKEY
    $field = $customFields | ?{$_.fieldName -eq $customFieldName}

    #if the field exists by name, globally
    if ($field) {
        #get all field values for this org
        $orgFieldValues = Get-NinjaGlobalOrgCustomFieldValues -orgId $orgId -SessionKey $SESSIONKEY
        #Write-Output $orgFieldValues
        #check to see if the current field value list contains this attribute. If not we'll have to add it.
        if ($orgFieldValues | ?{$_.attributeid -eq $field.id}) {
            foreach ($value in $orgFieldValues) {
                if ($value.attributeid -eq $field.id) {
                    $value.value = $newCustomFieldValue
                    break
                }
            }
        } else {
            $valuesArray = @()
            foreach ($value in $orgFieldValues) {
                $valuesArray += $value
            }
            $orgFieldValue = @{}
            $orgFieldValue | Add-Member -MemberType NoteProperty -Name attributeId -value $field.id
            $orgFieldValue | Add-Member -MemberType NoteProperty -Name value -value $newCustomFieldValue
            $valuesArray += $orgFieldValue
            $orgFieldValues = $valuesArray
        }

        $orgFieldValues = $orgFieldValues | ConvertTo-Json -Depth 10
        Write-Output $orgFieldValues
        Invoke-RestMethod -UseBasicParsing -Uri "https://$NINJA_BASE_FQDN/ws/attributes/node/client/$($orgId)/values" `
        -Method "Put" `
        -WebSession $session `
        -ContentType "application/json" `
        -Body $orgFieldValues
        
    } else {
        throw "Custom Field with name $customFieldName not found!" 
    }
} 

#INCOMPLETE
function Get-NinjaWSDeviceCustomFieldValue ($deviceId,$customFieldName,$SESSIONKEY) {
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $session.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
    $session.Cookies.Add((New-Object System.Net.Cookie("sessionKey", "$SESSIONKEY", "/", "$NINJA_BASE_FQDN")))
}

#INCOMPLETE
function Set-NinjaWSDeviceCustomFieldValue ($deviceId,$customFieldName,$newCustomFieldValue,$SESSIONKEY) {
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $session.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
    $session.Cookies.Add((New-Object System.Net.Cookie("sessionKey", "$SESSIONKEY", "/", "$NINJA_BASE_FQDN")))
}
function Invoke-NinjaWSRestMethod {
    param (
        [string] $Uri,
        [string] $Method = 'GET',
        [string] $ContentType = 'application/json',
        [string] $SESSIONKEY,
        [object] $Body
    )
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $session.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
    $session.Cookies.Add((New-Object System.Net.Cookie("sessionKey", "$SESSIONKEY", "/", "$NINJA_BASE_FQDN")))

        try {            
            # Invoke the REST request
            # Write-Output "Session: $SESSIONKEY"
            # Write-Output "Invoke-RestMethod -Uri $Uri -Method $Method -WebSession $session -ContentType $ContentType -Body $Body"
            $response = Invoke-RestMethod -Uri $Uri -Method $Method -WebSession $session -ContentType $ContentType -Body $Body

            # If successful, return the response
            return $response


        } catch [System.Net.WebException] {
            Write-Host "WebException occurred: $_"

            # Accessing the response from the exception
            $response = $_ | ConvertFrom-Json
            $resultCode = $response.resultCode

            if ($resultCode -eq "MFA_REQUIRED") {
                $RetryDelayInSeconds = Get-OTPRemainingSeconds + 1
                Write-Host "Retrying in $RetryDelayInSeconds seconds..."
                Start-Sleep -Seconds $RetryDelayInSeconds
                $totpCode = get-otp -SECRET $MFASECRET -LENGTH 6 -WINDOW 30
                
                if ($Uri -contains '?') {
                    $Uri += "&"
                } else {
                    $Uri += "?"
                }

                $response = Invoke-RestMethod -Uri "$($Uri)token=$($response.loginToken)&mfacode=$($totpCode)"  -Method $Method -WebSession $session -ContentType $ContentType -Body $body

                return $response

            } else {
                throw $_.Exception
            }
        }

}

function Invoke-NinjaWSWebRequest {
    param (
        [string] $Uri,
        [string] $Method = 'GET',
        [string] $ContentType = 'application/json',
        [string] $SESSIONKEY,
        [object] $Body
    )
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $session.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
    $session.Cookies.Add((New-Object System.Net.Cookie("sessionKey", "$SESSIONKEY", "/", "$NINJA_BASE_FQDN")))

        try {            
            # Invoke the REST request
            # Write-Output "Session: $SESSIONKEY"
            #Write-Output "Invoke-WebRequest -UseBasicParsing -Uri $Uri -Method $Method -WebSession $session -ContentType $ContentType -Body $Body"
            $response = Invoke-WebRequest -UseBasicParsing  -Uri $Uri -Method $Method -WebSession $session -ContentType $ContentType -Body $Body

            # If successful, return the response
            return $response


        } catch [System.Net.WebException] {
            Write-Host "WebException occurred: $_"

            # Accessing the response from the exception
            $response = $_ | ConvertFrom-Json
            $resultCode = $response.resultCode

            if ($resultCode -eq "MFA_REQUIRED") {
                $RetryDelayInSeconds = Get-OTPRemainingSeconds + 1
                Write-Host "Retrying in $RetryDelayInSeconds seconds..."
                Start-Sleep -Seconds $RetryDelayInSeconds
                $totpCode = get-otp -SECRET $MFASECRET -LENGTH 6 -WINDOW 30
                
                $response = Invoke-WebRequest -UseBasicParsing  -Uri "$Uri?token=$($response.loginToken)&mfacode=$($totpCode)"  -Method $Method -WebSession $session -ContentType $ContentType -Body $body

                return $response

            } else {
                throw $_.Exception
            }
        }

}

function Get-OrgShortName ([string]$OrgName){
    $OrgName -replace '\W', '' 
}

function Get-NinjaWSUsers ($SESSIONKEY) {
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $session.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0"
    $session.Cookies.Add((New-Object System.Net.Cookie("sessionKey", "$SESSIONKEY", "/", "$NINJA_BASE_FQDN")))
    #this gets Technicians
    $users = Invoke-RestMethod -UseBasicParsing -Uri "https://$NINJA_BASE_FQDN/ws/appuser" `
    -WebSession $session `
    -ContentType "application/json"
    #this gets EndUsers
    $users += Invoke-RestMethod -UseBasicParsing -Uri "https://$NINJA_BASE_FQDN/ws/appuser?userType=END_USER" `
    -WebSession $session `
    -ContentType "application/json"
    $users
}