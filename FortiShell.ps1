### Created for Fortigate automation by Tomer Setty 2018

## Bypass Security.
$AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
[System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

function Forti-Init {

     param(
            [Parameter(Mandatory=$true)]
            [string]$device,
            [Parameter(Mandatory=$true)]
            [string]$username,
            [Parameter(Mandatory=$true)]
            [string]$password
        )

    $url = "https://$device/logincheck"
    ## Create Connection.
    $creds = @{username=$username;secretkey=$password}
    $session = Invoke-WebRequest -Uri $url -Method POST -Body $creds -SessionVariable websession 
    $cookies = $websession.Cookies.GetCookies($url) 

    ## Create CSRF Token header.
    foreach ($cookie in $cookies) {
        if ($cookie.Name -eq 'ccsrftoken')
        {
        $csrftoken = $cookie.Value
        $csrftoken = $csrftoken -replace '"', ""
        }      
    }

    ## Create Cookie Object
    $session_cookie = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $apscookie = New-Object System.Net.Cookie 
      $apscookie.Name = $cookies[0].name
      $apscookie.Value = $cookies[0].value
      $apscookie.Domain = $cookies[0].Domain
    ## Implement Cookie in Session.
    $session_cookie.Cookies.Add($apscookie);

    ## Return Init hashmap.
    @{"cookie"=$session_cookie;"csrftoken"=$csrftoken;"device"=$device;}

}


function Forti-GetObj {

     param(
            [Parameter(Mandatory=$true)]
            $Init,
            [Parameter(Mandatory=$true)]
            [string]$VDOM,
            [Parameter(Mandatory=$false)]
            [string]$Name
        )

        $cookie = $Init.cookie
        $device = $Init.device
        if($Name){
        $name = ($Name + "/")
        }

        $uri = "https://$device/api/v2/cmdb/firewall/address/" + $name + "?vdom=$VDOM"

try{
    $response = (Invoke-RestMethod -WebSession $cookie -Uri $uri -Method GET).results
    $response
    }

Catch{
    $ErrorMessage = $_.Exception.Message
    $ErrorMessage
    }

}


function Forti-CreateObj {

     param(
            [Parameter(Mandatory=$true)]
            $Init,
            [Parameter(Mandatory=$true)]
            [string]$VDOM,
            [Parameter(Mandatory=$true)]
            [string]$Name,
            [Parameter(Mandatory=$true)]
            [string]$Subnet,
            [Parameter(Mandatory=$true)]
            [string]$IPAddress
        )

        $cookie = $Init.cookie
        $device = $Init.device
        $token = $Init.csrftoken
        $headers = @{'X-CSRFTOKEN'="$token";}
        $obj = @{'name'=$Name;'subnet'="$IPAddress $Subnet";} | ConvertTo-Json
        $uri = "https://$device/api/v2/cmdb/firewall/address/?vdom=$VDOM"


try{
    $response = Invoke-RestMethod -WebSession $cookie -Uri $uri -Method POST -body $obj -Headers $headers
    $response
    }

Catch{
    $ErrorMessage = $_.Exception.Message
    $ErrorMessage
    }

}



function Forti-DeleteObj {

     param(
            [Parameter(Mandatory=$true)]
            $Init,
            [Parameter(Mandatory=$true)]
            [string]$VDOM,
            [Parameter(Mandatory=$true)]
            [string]$Name

        )

        $cookie = $Init.cookie
        $device = $Init.device
        $token = $Init.csrftoken
        $headers = @{'X-CSRFTOKEN'="$token";}

        $uri = "https://$device/api/v2/cmdb/firewall/address/$Name/?vdom=$VDOM"


try{
    $response = Invoke-RestMethod -WebSession $cookie -Uri $uri -Method DELETE -Headers $headers
    $response
    }

Catch{
    $ErrorMessage = $_.Exception.Message
    $ErrorMessage
    }

}


function Forti-GetGroup {

     param(
            [Parameter(Mandatory=$true)]
            $Init,
            [Parameter(Mandatory=$true)]
            [string]$VDOM,
            [Parameter(Mandatory=$false)]
            [string]$Name
        )

        $cookie = $Init.cookie
        $device = $Init.device
        if($Name){
        $name = ($Name + "/")
        }

        $uri = "https://$device/api/v2/cmdb/firewall/addrgrp/" + $name + "?vdom=$VDOM"

try{
    $response = (Invoke-RestMethod -WebSession $cookie -Uri $uri -Method GET).results
    $response
    }

Catch{
    $ErrorMessage = $_.Exception.Message
    $ErrorMessage
    }

}


function Forti-CreateGroup {

     param(
            [Parameter(Mandatory=$true)]
            $Init,
            [Parameter(Mandatory=$true)]
            [string]$VDOM,
            [Parameter(Mandatory=$true)]
            [string]$Name,
            [Parameter(Mandatory=$true)]
            [array]$members

        )

        $cookie = $Init.cookie
        $device = $Init.device
        $token = $Init.csrftoken
        $headers = @{'X-CSRFTOKEN'="$token";}
        $obj = @{'name'=$Name;}
        if($members){
            foreach ($member in $members){
             [array]$obj.member += @{'name'=$member;}
            }
        }

        $uri = "https://$device/api/v2/cmdb/firewall/addrgrp/?vdom=$VDOM"


try{
    $response = Invoke-RestMethod -WebSession $cookie -Uri $uri -Method POST -Headers $headers -body ($obj|ConvertTo-Json) -ContentType "application/json"
    $response
    }

Catch{
    $ErrorMessage = $_.Exception.Message
    $ErrorMessage
    }

}
