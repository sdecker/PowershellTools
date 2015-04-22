######################################################################################
# Written by Ashley Poole  -  http://www.ashleypoole.co.uk                           #
#                                                                                    #
# Checks servers SSL implementation for the given host(s).                           #
# This is achived by consuming SSL Labs Assessment Api Via SSLLWrapper (Api Wrapper) #
######################################################################################

#region Construction
[CmdletBinding(DefaultParameterSetName='passedHost')]
Param
(
 	[Parameter(Mandatory=$true,position=0,ParameterSetName='passedHost')]
	[ValidateNotNullOrEmpty()]
	[String[]]
	[alias("host")]
	[alias("hostInput")]
	$Hostname,

	[Parameter(Mandatory=$true,ParameterSetName='HostFromFile')]
	[ValidateNotNullOrEmpty()]
	[String]
	[alias("hosts")]
	[alias("hostsInput")]
    [ValidateScript({Test-Path $_})]
	$Path,

 	[Parameter(Mandatory=$false,ParameterSetName='passedHost')]
	[Parameter(Mandatory=$false,ParameterSetName='HostFromFile')]
	[switch]
	[alias("endpointdetails")]
	$WriteEndpointDetails,

 	[Parameter(Mandatory=$false,ParameterSetName='passedHost')]
	[Parameter(Mandatory=$false,ParameterSetName='HostFromFile')]
	[switch]
	$Raw

)

$ErrorActionPreference = "stop"

# Variables
$SSLLabsApiUrl = "https://api.ssllabs.com/api/v2/"

switch ($PsCmdlet.ParameterSetName) {

    'HostFromFile'
    {
        $Hosts = Get-Content -Path $Path
        break;
    }

    'passedHost'
    {
        $Hosts = @($hostname) 
        break;
    }

    default
    {
        # Should never get here
        Throw "Invalid parameter"
    }
}

$SSLLWrapperFilePath = $PSScriptRoot.ToString() + "\SSLLWrapper\SSLLWrapper.dll"
$NewtonsoftJsonFilePath = $PSScriptRoot.ToString() + "\SSLLWrapper\NewtonSoft.Json.dll"

# Loading DLLs
Add-Type -Path $NewtonsoftJsonFilePath
Add-Type -Path $SSLLWrapperFilePath

# Creating SSLLService
$SSLService = New-Object SSLLWrapper.SSLLService($SSLLabsApiUrl)

#endregion

clear
Write-Host "`n"
Write-Host "Starting analysis... This process may take several minutes per endpoint, per host..."
Write-Host "`n"

# Testing if Api is online
$ApiInfo = $SSLService.Info()

If ($ApiInfo.Online -ne $true)
{
    # Api is not online. Exiting.
    Write-Error "Api " $SSLLabsApiUrl " is not online, contactable or is incorrect.`r`nExiting."
}

if ($Raw) 
{
    $RawOutput = @()
}


Foreach ($myHost In $Hosts)
{

    # Analysising host with a maximum of a 5 minute wait time
    #$HostAnalysis = $SSLService.AutomaticAnalyze($myHost, 500, 10)
    
    if ($myHost -notlike 'https://.*')
    {
      Write-host "Adding HTTPS:// because the .Net library expects it"
      
      $myHost = "https://" + $myHost
    }
    
    Write-Host "**********************************************************************************"
    Write-Host $myHost " - " (Get-Date -format "dd-MM-yyyy HH:mm:ss")
    Write-Host "**********************************************************************************"

    $HostAnalysis = $SSLService.AutomaticAnalyze($myHost, [SSLLWrapper.SSLLService+Publish]::Off, [SSLLWrapper.SSLLService+ClearCache]::Ignore, [SSLLWrapper.SSLLService+FromCache]::On,[SSLLWrapper.SSLLService+All]::On,500,10)

    if ($Raw) 
    {
        $RawOutput += $HostAnalysis
    }
    else
    {

        Write-Host "Endpoints #           :" ($HostAnalysis.endpoints).Count

        if ($HostAnalysis.HasErrorOccurred) 
        {
            Write-Host "Analysis Error        :" $hostAnalysis.Errors.message
        }

        Write-Host "`n"

        Foreach ($Endpoint In $HostAnalysis.endpoints)
        {
            Write-Host "Endpoint                        :" $Endpoint.ipAddress

            Write-Host "Grade                           :" $Endpoint.grade
            Write-Host "Has Warnings                    :" $Endpoint.hasWarnings

            # Output extra details if EndpointDetails is true and analysis data is good (i.e check grade exists)
            If (($WriteEndpointDetails) -and ($Endpoint.grade))
            {
                $EndpointAnalysis = $SSLService.GetEndpointData($HostAnalysis.host, $Endpoint.ipAddress)

                Write-Host "Server Signature                :" $EndpointAnalysis.Details.serverSignature

				switch ($EndpointAnalysis.Details.chain.issues)
				{
                    #bit 0 (1) - unused
                    1 { $chainIssues = "unused" }
                    #bit 1 (2) - incomplete chain (set only when we were able to build a chain by adding missing intermediate certificates from external sources)
                    2 { $chainIssues = "Incomplete " }
                    #bit 2 (4) - chain contains unrelated or duplicate certificates (i.e., certificates that are not part of the same chain)
                    4 { $chainIssues = "unrelated or duplicates" }
                    #bit 3 (8) - the certificates form a chain (trusted or not), but the order is incorrect
                    8 { $chainIssues = "Incorrect order" }
                    #bit 4 (16) - contains a self-signed root certificate (not set for self-signed leafs)
                    16 { $chainIssues = "self-signed root" }
                    #bit 5 (32) - the certificates form a chain (if we added external certificates, bit 1 will be set), but we could not validate it. If the leaf was trusted, that means that we built a different chain we trusted.
                    32 { $chainIssues = "Could not validate" }

                    default { $chainIssues = "None" }
				}
                Write-Host "Cert Chain Issue                :" $chainIssues
 
				switch ($EndpointAnalysis.Details.forwardSecrecy)
				{
                    # bit 0 (1) - set if at least one browser from our simulations negotiated a Forward Secrecy suite.
					1 { $forwardSecrecy = "With some browsers"}
                    # bit 1 (2) - set based on Simulator results if FS is achieved with modern clients. For example, the server supports ECDHE suites, but not DHE.
					2 { $forwardSecrecy = "With modern browsers"}
                    # bit 2 (4) - set if all simulated clients achieve FS. In other words, this requires an ECDHE + DHE combination to be supported.
					4 { $forwardSecrecy = "Yes (with most browsers) ROBUST"}
                    default { $forwardSecrecy = "Unknown" }
				}
                Write-Host "Forward Secrecy                 :" $forwardSecrecy
                Write-Host "Supports RC4                    :" $EndpointAnalysis.Details.supportsRc4
                Write-Host "Beast Vulnerable                :" $EndpointAnalysis.Details.vulnBeast
                Write-Host "Heartbleed Vulnerable           :" $EndpointAnalysis.Details.heartbleed

				switch ($EndpointAnalysis.Details.renegSupport)
				{
					# bit 0 (1) - set if insecure client-initiated renegotiation is supported
					1 { $Renegotiation = "Insecure Client-Initiated"}
					# bit 1 (2) - set if secure renegotiation is supported
					2 { $Renegotiation = "Secure Renegotiation SUPPORTED"}
					# bit 2 (4) - set if secure client-initiated renegotiation is supported
					4 { $Renegotiation = "Secure Client-Initiated"}
					# bit 3 (8) - set if the server requires secure renegotiation support
					8 { $Renegotiation = "Secure Renegotiation REQUIRED"}
                    default { $Renegotiation = "Unknown" }
				}
				Write-Host "Renegotiation Support           :" $Renegotiation

				switch ($EndpointAnalysis.Details.sessionResumption)
				{
					# 0 - session resumption is not enabled and we're seeing empty session IDs
					0 { $sessionResumption = "Not enabled"}
					# 1 - endpoint returns session IDs, but sessions are not resumed
					1 { $sessionResumption = "endpoint returns session IDs, but sessions not resumed"}
					# 2 - session resumption is enabled
					2 { $sessionResumption = "Enabled"}
                    default { $sessionResumption = "Unknown" }
				}
				Write-Host "Session Resumption (Cached)     :" $sessionResumption

				switch ($EndpointAnalysis.Details.sessionTickets)
				{
                    # bit 0 (1) - set if session tickets are supported
					1 { $sessionTickets = "Supported"}
                    # bit 1 (2) - set if the implementation is faulty [not implemented]
					2 { $sessionTickets = "Implemenation faulty"}
                    # bit 2 (4) - set if the server is intolerant to the extension
					4 { $sessionTickets = "Intolerant"}
                    default { $sessionTickets = "No" }
				}
				Write-Host "Session Resumption (Tickets)    :" $sessionTickets

				switch ($EndpointAnalysis.Details.openSslCcs)
				{
                    # -1 - test failed
					-1 { $openSslCcs = "Test failed"}
                    # 0 - unknown
					0 { $openSslCcs = "Unknown"}
                    # 1 - not vulnerable
					1 { $openSslCcs = "Not vulnerable"}
                    # 2 - possibly vulnerable, but not exploitable
					2 { $openSslCcs = "Possibly vulnerable, but not exploitable"}
                    # 3 - vulnerable and exploitable
					3 { $openSslCcs = "Vulnerable and exploitable"}

                    default { $openSslCcs = "Unknown" }
				}
				Write-Host "OpenSSL CCS vuln (CVE-2014-0224):" $openSslCcs

				switch ($EndpointAnalysis.Details.compressionMethods)
				{
                    # bit 0 is set for DEFLATE
					0 { $compressionMethods = "DEFLATE"}

                    default { $compressionMethods = "No" }
				}
				Write-Host "TLS Compression                 :" $compressionMethods

				switch ($EndpointAnalysis.Details.poodleTls)
				{
                    # -1 - test failed
					-1 { $poodleTls = "Test failed"}
                    # 0 - unknown
					0 { $poodleTls = "Unknown"}
                    # 1 - not vulnerable
					1 { $poodleTls = "Not vulnerable"}
                    # 2 - vulnerable
					2 { $poodleTls = "Vulnerable"}

                    default { $poodleTls = "Unknown" }
				}
				Write-Host "POODLE (TLS)                    :" $poodleTls
#Missing from .Net class
#				Write-Host "POODLE                          :" $EndpointAnalysis.Details.poodle
				Write-Host "Heartbeat (extension)           :" $EndpointAnalysis.Details.heartbeat
				Write-Host "Next Protocol Negotiation (NPN) :" $EndpointAnalysis.Details.supportsNpn
				Write-Host "OCSP stapling                   :" $EndpointAnalysis.Details.ocspStapling

                Write-Host "Protocols                       :" 
                $EndpointAnalysis.Details.protocols | Format-Table -Property name,version -AutoSize
               

                $EndpointAnalysis.Details.suites.list | Format-Table -Property name, cipherStrength, ecdhBits, ecdhStrength, dhStrength, dhP, dhG, dhYs -AutoSize

                Write-Host "Signing key      :" $EndpointAnalysis.Details.key.alg $EndpointAnalysis.Details.key.strength
                $EndpointAnalysis.Details.cert | Format-List
           
            }

        }
        Write-Host "`r`n"
    }

}

if ($Raw) 
{
    $RawOutput
}
