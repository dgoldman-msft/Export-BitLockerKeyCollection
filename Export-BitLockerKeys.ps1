
function Get-TimeStamp {
    <#
        .SYNOPSIS
            Get a time stamp
        
        .DESCRIPTION
            Get a time stamp
        
        .EXAMPLE
            None
        
        .NOTES
            Internal function
    #>

    [cmdletbinding()]
    param()
    return "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
    
}

function Save-Output {
    <#
        .SYNOPSIS
            Save output
        
        .DESCRIPTION
            Overload function for Write-Output
        
        .PARAMETER InputObject
            Inbound object to be printed and saved to log
        
        .EXAMPLE
            None
        
        .NOTES
            None
    #>

    [cmdletbinding()]
    param(
        [string]
        $InputObject
    )

    process {
        Write-Output $InputObject
        Out-File -FilePath (Join-Path -Path $Directory -ChildPath $File) -InputObject $InputObject -Encoding utf8 -Append
    }
}

function Export-BitLockerKeyCollection {
    <#
        .SYNOPSIS
            Export Bitlocker keys from Azure

        .DESCRIPTION
            Login to an Azure tenant and retreive the Bitlocker keys for Microsoft Endpoint devices

        .PARAMETER ExportFile
            HTML report with all the exported keys

        .PARAMETER Directory
            Logging directory

        .PARAMETER File
            Logfile

        .PARAMETER ExportToHTML
            Switch to indicating the file will be exported to HTML

        .EXAMPLE 
            Export-BitLockerKeyCollection

            Export bitlocker keys and display them in the console

        .EXAMPLE 
            Export-BitLockerKeyCollection -ExportToHTML

            Export bitlocker keys and save them to an HTLM file

        .NOTES
            Credit: Original code from: https://f12.hu/2020/11/11/retrieve-bitlocker-keys-stored-in-azuread-with-powershell/
    #>

    [CmdletBinding()]
    param (
        [string]
        $ExportFile = "C:\TEMP\BitLockerReport.html",

        [string]
        $Directory = 'C:\PSLogging',

        [string]
        $File = 'ScriptExecutionLogging.txt',

        [switch]
        $ExportToHTML
    )
    
    begin {
        Save-Output "$(Get-TimeStamp) Starting process!"
        if (-NOT( Test-Path -Path $Directory)) {
            try {
                Save-Output "$(Get-TimeStamp) Directory not found. Creating $Directory"
                New-Item -Path $Directory -Type Directory -ErrorAction Stop
            }
            catch {
                Save-Output "$(Get-TimeStamp) ERROR: $_.Exception"
                return
            }
        }

        try {
            $modules = @('Az.Accounts')
            
            foreach ($module in $modules) {
                Save-Output "$(Get-TimeStamp) Searching for module: $($module)"
                if (Get-Module -Name $module -ListAvailable | Where-Object Name -eq $module) {
                    Save-Output "$(Get-TimeStamp) $($module) module found. Importing"
                }
                else {
                    Save-Output "$($module) module not found. Installing and importing"
                    Install-Module -Name $module -Force -Repository PSGallery -ErrorAction Stop
                    Import-Module -Name $module -Force -ErrorAction Stop
                }
            }
        }
        catch {
            Save-Output "$(Get-TimeStamp) ERROR: $_.Exception"
            return
        }
    }
    
    process {
        try {
            Save-Output "$(Get-TimeStamp) Logging in to the AzureRM account"
            Login-AzureRmAccount -ErrorAction Stop

            Save-Output "$(Get-TimeStamp) Obtaining Azure Context"
            $context = Get-AzureRmContext -ErrorAction Stop
            $tenantId = $context.Tenant.Id
            Save-Output "$(Get-TimeStamp) Obtaining refresh token"
            $refreshToken = @($context.TokenCache.ReadItems() | Where-Object { $_.tenantId -eq $tenantId -and $_.ExpiresOn -gt (Get-Date) })[0].RefreshToken
            $body = "grant_type=refresh_token&refresh_token=$($refreshToken)&resource=74658136-14ec-4630-ad9b-26e160ff0fc6"
            $apiToken = Invoke-RestMethod "https://login.windows.net/$tenantId/oauth2/token" -Method POST -Body $body -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
            $header = @{
                'Authorization'          = 'Bearer ' + $apiToken.access_token
                'X-Requested-With'       = 'XMLHttpRequest'
                'x-ms-client-request-id' = [guid]::NewGuid()
                'x-ms-correlation-id'    = [guid]::NewGuid()
            }

            Save-Output "$(Get-TimeStamp) Connecting to AzureAD"
            Connect-AzureAD -ErrorAction Stop
            $AzureADDevices = Get-AzureADDevice -all $true | Where-Object { $_.deviceostype -eq "Windows" }

            Save-Output "$(Get-TimeStamp) Obtaining Azure AD device records"
            $deviceRecords = @()
            $deviceRecords = foreach ($device in $AzureADDevices) {
                $url = "https://main.iam.ad.ext.azure.com/api/Device/$($device.objectId)"
                $deviceRecord = Invoke-RestMethod -Uri $url -Headers $header -Method Get -ErrorAction Stop
                $deviceRecord
            }

            Save-Output "$(Get-TimeStamp) Obtaining Bitlocker keys from Azure tenant"
            $Devices_BitlockerKey = $deviceRecords.Where({ $_.BitlockerKey.count -ge 1 })
            $obj_report_Bitlocker = foreach ($device in $Devices_BitlockerKey) {
                foreach ($BLKey in $device.BitlockerKey) {
                    [pscustomobject]@{
                        DisplayName = $device.DisplayName
                        driveType   = $BLKey.drivetype
                        keyID       = $BLKey.keyIdentifier
                        recoveryKey = $BLKey.recoveryKey
                    }
                }
            }

            $body = $null
            $body += "<p><b>AzureAD Bitlocker key report</b></p>"
            $body += @"
    <table style=width:100% border="1">
      <tr>
        <th>Device</th>
        <th>DriveType</th>
        <th>KeyID</th>
        <th>RecoveryKey</th>
      </tr>
"@

            $body += foreach ($obj in $obj_report_Bitlocker) {
                "<tr><td>" + $obj.DisplayName + " </td>"
                "<td>" + $obj.DriveType + " </td>"
                "<td>" + $obj.KeyID + " </td>"
                "<td>" + $obj.RecoveryKey + "</td></tr>"
            }

            $body += "</table>"

            # Export the file for review
            if ($ExportToHTML.IsPresent) {
                Save-Output "$(Get-TimeStamp) Report exported to $($exportFile)"
                $body > $exportFile
                try {
                    Invoke-Item $exportFile -ErrorAction Stop
                }
                catch {
                    Save-Output "$(Get-TimeStamp) ERROR: $_.Exception"
                }
            }
            else {
                $body
            }
        }
        catch {
            Save-Output "$(Get-TimeStamp) ERROR: $_.Exception"
            return
        }

        Save-Output "$(Get-TimeStamp) Finished! Loading report!"
    }
}
