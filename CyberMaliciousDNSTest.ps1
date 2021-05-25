<#

Application: DNS filtering Test 
Publisher: Omer Friedman
Version: 0.9
Date: 19-05-2021

#>

CLS
if ((Get-NetConnectionProfile).IPv4Connectivity -eq "Internet")
{
    Write-Host "Your computer is connected to the internet, we can continue with the tests" -ForegroundColor Green
    $NetAdapterInterfaceIndex = (Get-NetConnectionProfile).InterfaceIndex
}
else {
    Read-Host "Your computer is not connected to the internet, press [Enter] to exit" -ForegroundColor Red
    break
}

$DNSBAKFILE = "C:\Temp\BackupDNSSettings.bak"
$BlockedDomainsFile = "c:\temp\BlockeDomains.txt" 
$BlockedUsingLocalDNSFile = "C:\temp\BlockedUsingLocalDNS.txt"
$BlockedUsingDNSFiltersFile = "C:\temp\BlockedUsingDNSFilters.txt"

Remove-Item -Path $BlockedUsingLocalDNSFile -Force -ErrorAction SilentlyContinue
Remove-Item -Path $BlockedUsingDNSFiltersFile -Force -ErrorAction SilentlyContinue

#$TotalByNameServer = @{Cloudflare=0;CloudflareMalware=0;CloudflareMalwareAndPorn=0;Quad9=0;OpenDNS=0;AdGuard=0;AdGuardFamily=0}
#$nameservers = @{Cloudflare='1.1.1.1';CloudflareMalware='1.1.1.2';CloudflareMalwareAndPorn='1.1.1.3';Quad9='9.9.9.9';OpenDNS='208.67.222.222';AdGuard='94.140.14.14';AdGuardFamily='94.140.14.15'}

$TotalByNameServer = @{Cloudflare=0;CloudflareMalware=0;CloudflareMalwareAndPorn=0;Quad9=0;OpenDNS=0}
$nameservers = @{Cloudflare='1.1.1.1';CloudflareMalware='1.1.1.2';CloudflareMalwareAndPorn='1.1.1.3';Quad9='9.9.9.9';OpenDNS='208.67.222.222'}

$TotalBLWithFilter = 0
$TotalBLLocalDNS = 0

$localRegisteredDNS = Get-DnsClientServerAddress -AddressFamily IPv4 | foreach {$_.ServerAddresses}
if ($localRegisteredDNS.Count -ge 2)
{
    $localDNS1 = $localRegisteredDNS[0]
    $localDNS2 = $localRegisteredDNS[1]
}
else
{
    $localDNS1 = $localRegisteredDNS
    $localDNS2 = ""
}

if (Test-Path -Path $DNSBAKFILE -PathType Leaf)
{
    Write-Host "Your original DNS ip adresses are already saved in $DNSBAKFILE" -ForegroundColor Green
    $origIP = Get-Content $DNSBAKFILE
    if ($origIP[0] -ne $localDNS1)
    {
        Write-Host "Note: Your Current DNS settings [$localDNS1] is different than the original settings [$origIP]" -ForegroundColor Red
        $input = read-host "Press [R] to restore original DNS settings or [Enter] to continue with current DNS"
        if ($input -eq "R")
        {
            Set-DnsClientServerAddress -InterfaceIndex $NetAdapterInterfaceIndex -ServerAddresses $origIP[0],$origIP[1]    
            $localDNS1 = $origIP[0]
            $localDNS2 = $origIP[1]
        }
    }
}
else
{
    Write-Host "Backing up your DNS settings to $DNSBAKFILE" -ForegroundColor Yellow
    $localRegisteredDNS | Out-File $DNSBAKFILE #backing up dns settings if needed to be restored later
}

$filteringServices = $nameservers.keys | Sort-Object
$help = @("

DNS filtering Test
------------------

This test can help you figure out if your DNS server is protecting you from dns resolving of dangerous domains 
that are used in serving Ads, Phishing, Malvertising, Malware, Spyware, Ransomware, CryptoJacking, Fraud, 
Scam,Telemetry, Analytics, Tracking and more...

Step 1 - Run the tests using your current configured Primary DNS server: $localDNS1
Step 2 - Run the tests with different dns filtering services
Step 3 - Help you change DNS settings to a filtering service from

List of Filtering services:
")
Write-Host $help
foreach ($fService in $filteringServices)
{
    Write-Host "*" $fService "-->" $nameservers.$fservice 
}
Write-Host ""

$checkPrimaryDns = foreach ($ns1 in $nameservers.Keys) {if ($nameservers.$ns1.Equals($localDNS1)){$ns1}}
$checkSecondaryryDns = foreach ($ns2 in $nameservers.Keys) {if ($nameservers.$ns2.Equals($localDNS2)){$ns2}}

 if (($checkPrimaryDns) -and ($checkSecondaryryDns))
 {
    Write-Host "Your Primary DNS server $localDNS1 is pointing to --> "$checkPrimaryDns -ForegroundColor Green
    Write-Host "Your Secondary DNS server $localDNS2 is pointing to --> "$checkSecondaryryDns -ForegroundColor Yellow
    $nameservers.Remove($checkPrimaryDns)
 } 

 if (($checkPrimaryDns) -and !($checkSecondaryryDns))
 {
    Write-Host "Your Primary DNS server $localDNS1 is pointing to --> "$checkPrimaryDns -ForegroundColor Green
    Write-Host "Note: You dont have a Secondary DNS Server" -ForegroundColor Red
    $nameservers.Remove($checkPrimaryDns)
    $TotalByNameServer.Remove($checkPrimaryDns)
 } 

Write-Host ""
#download the basic blocked domains list from dbl.oisd.nl and store data in file
if (Test-Path -Path $BlockedDomainsFile -PathType Leaf)
{
    Write-Host "You already downloaded before the blocked domain list $BlockedDomainsFile" -ForegroundColor Green
}
else
{
    Write-Host "Downloading the basic blocked domains list from dbl.oisd.nl and storing in $BlockedDomainsFile file" -ForegroundColor Yellow
    $getBlockedDomains = Invoke-WebRequest -Uri "https://dbl.oisd.nl/basic/"
    $BlockedDomains = $getBlockedDomains.Content
    Set-Content $BlockedDomainsFile -Value $BlockedDomains -Force
}

#read the data from file and create it as a randomized array
Write-Host "Parsing the blocked domain list file and creating a randomized list of domains to check" -ForegroundColor Yellow
$BlockedDomainsFile = [System.IO.File]::ReadALLLines($BlockedDomainsFile)
$totalBlockedDomains = $BlockedDomainsFile.Count - 15 #13 lines banner and 2 lines at the end of file
$banner = $BlockedDomainsFile[0..12]
Write-Output $banner
$BlockedDomains =  $BlockedDomainsFile | Sort-Object {Get-Random}
Write-Host "The (basic) list contains $totalBlockedDomains blocked domains" -ForegroundColor Green
Write-Host ""


do {
  $inputString = read-host "Input the numbers of blocked domains to test (Min=25 | Max=$totalBlockedDomains)"
  $input = $inputString -as [Double]
  $ok = $input -ne $NULL
  if (-not $ok) { write-host "You must enter a numeric value, Please try again" -ForegroundColor Red}
}
until ($ok)

if ($input -lt 25) {$input = 10}
Write-Host ""
Write-Host "The test will done on $input randomally domains chosen from the domains list"

$domains = $BlockedDomains 
$BadDomains = $domains[0..([int]$input-1)]
$totalChecks = $nameservers.Count * $input

#run test using current dns configuration
$CSVnoLocalDNSFile = @() #initialize array for CSV file creation
$i = 0 #counter for progress bar
foreach ($dom in $BadDomains)
{
   $CSVrows = New-Object System.Object
   $DNSRes = Resolve-DnsName $dom -Server $localDNS1 -ErrorAction SilentlyContinue
   if ((($DNSRes.IP4Address).count -ge 1) -and ($DNSRes.IP4Address -notlike '0.0.0.0'))
   {
     Write-Progress -Activity "Step 1 - Resolving domain [$dom] using [$localDNS1] [Not Blacklisted]" -Status "$i out of $input"
     $CSVrows | Add-Member -MemberType NoteProperty -name "$localDNS1" -Value "X"    
     $i++
   }
   else
   {
     Write-Progress -Activity "Step 1 - Resolving domain [$dom] using [$localDNS1] [Blacklisted]" -Status "$i out of $input"
     $CSVrows | Add-Member -MemberType NoteProperty -name "$localDNS1" -Value "$dom"         
     $i++
     $TotalBLLocalDNS++
   } 
   $CSVnoLocalDNSFile += $CSVrows
}



#run test using dns filtering services

#initialize array for CSV file creation
$CSVFile = @() #initialize array for CSV file creation
$i = 0 #counter for progress bar
foreach ($dom in $BadDomains)
{
   $CSVrows = New-Object System.Object
   foreach ($nameserver in $nameservers.Keys)
   {
        $DNSRes = Resolve-DnsName $dom -Server $nameservers.$nameserver -ErrorAction SilentlyContinue
        if ((($DNSRes.IP4Address).count -ge 1) -and ($DNSRes.IP4Address -notlike '0.0.0.0'))
        {
           Write-Progress -Activity "Step 2 - Resolving domain [$dom] using [$nameserver] [Not Blacklisted]" -Status "$i out of $totalChecks"
           $CSVrows | Add-Member -MemberType NoteProperty -name "$nameserver" -Value "X"    
           $i++
        }
        else
        {
           Write-Progress -Activity "Step 2 - Resolving domain [$dom] using [$nameserver] [Blacklisted]" -Status "$i out of $totalChecks" 
           $CSVrows | Add-Member -MemberType NoteProperty -name "$nameserver" -Value "$dom"                
           $i++
           $TotalByNameServer.$nameserver++
           $TotalBLWithFilter++
        }
    }
    $CSVFile += $CSVrows
}

$MaxbByServer = ($TotalByNameServer.Values | Measure -Maximum).Maximum
Write-Host "************************************************************************" -ForegroundColor Yellow 
Write-Host "Total domains filtered using dns filtering services:" -ForegroundColor Yellow
Write-Host ($TotalByNameServer | Out-String)  -ForegroundColor Yellow
Write-Host "Maximum filtered domains by DNS filtering service server is: $MaxbByServer/$input" -ForegroundColor Yellow
Write-Host "Filtered using the Currently configured Primary DNS server: $TotalBLLocalDNS/$input"  -ForegroundColor Yellow
Write-Host "************************************************************************" -ForegroundColor Yellow 

"**************Report of Local DNS settings***************" | Out-File $BlockedUsingLocalDNSFile
"Filtered using the Currently configured Primary DNS server: $TotalBLLocalDNS/$input" | Out-File $BlockedUsingLocalDNSFile -Append
$CSVnoLocalDNSFile | FT | Out-File $BlockedUsingLocalDNSFile -Append

"**************Report of Filtering DNS services**********" | Out-File $BlockedUsingDNSFiltersFile
($TotalByNameServer | Out-String) | Out-File $BlockedUsingDNSFiltersFile -Append
"Maximum filtered domains by DNS filtering service server is: $MaxbByServer/$input" |  Out-File $BlockedUsingDNSFiltersFile -Append
$CSVFile | FT | Out-File $BlockedUsingDNSFiltersFile -Append

Write-Host ""

if ($MaxbByServer -gt $TotalBLLocalDNS)
{
    #find the best DNS filetring service
    $bestDNS = foreach ($t in $TotalByNameServer.Keys) {if ($TotalByNameServer.$t -eq $MaxbByServer) {$t}}
     if ($bestDNS.Count -eq 1)
    {
        $recommend = $bestDNS
    }
    else
    {
        foreach ($d in $bestDNS)
        {
            $recommend = $bestDNS[0]
        }
    }

    Write-Host "Note: We recommend changing the current configured DNS to a more protective DNS filtering service [$recommend]" -ForegroundColor red -BackgroundColor Black
    Write-Host ""
    #if connected to domain we dont change DNS settings in local machine but in the local DNS server
    $menuNumber = 1 #for enumerating the nameservers menu
    if  ($env:USERDOMAIN -eq $env:COMPUTERNAME)
    {
        Write-Host "Please select option number to change your primary DNS settings:"
        Write-Host "---------------------------------------------------------------"
        foreach ($ns in $nameservers.Keys)
        {
            if ($ns -eq $recommend)
            {
                Write-Host "[$menuNumber] $ns =" $nameservers.$ns "(Recommended)" -ForegroundColor Green
            }
            else
            {
                Write-Host "[$menuNumber] $ns =" $nameservers.$ns
            }
            $menuNumber++
        }
        Write-Host ""
        $menu = Read-Host "Input your selection or [Enter] to continue without changing"

        #create list of dns filters ip addresses
        $ip = @()
        foreach ($ns in $nameservers.Values)
            {
                $ip += $ns
            }
    
        #create menu
        switch ($menu)
        {
            1 {
                Write-Host "Setting DNS ip to:" $ip[0]
                Set-DnsClientServerAddress -InterfaceIndex $NetAdapterInterfaceIndex -ServerAddresses $ip[0]
                }
            2 {
                Write-Host "Setting DNS ip to:" $ip[1]
                Set-DnsClientServerAddress -InterfaceIndex $NetAdapterInterfaceIndex -ServerAddresses $ip[1]
                }

            3 {
                Write-Host "Setting DNS ip to:" $ip[2]
                Set-DnsClientServerAddress -InterfaceIndex $NetAdapterInterfaceIndex -ServerAddresses $ip[2]
                }

            4 {
                Write-Host "Setting DNS ip to:" $ip[3]
                Set-DnsClientServerAddress -InterfaceIndex $NetAdapterInterfaceIndex -ServerAddresses $ip[3]
                }
            5 {
                Write-Host "Setting DNS ip to:" $ip[4]
                Set-DnsClientServerAddress -InterfaceIndex $NetAdapterInterfaceIndex -ServerAddresses $ip[4]
                }
        }
    }
    else
    {
        Write-Host "Note: Because you are connected to a DOMAIN please dont change settings locally, the changes should be done"
        Write-Host "in the local dns server [$localDNS1] so it resolves external addresses from any of the filtering services"
    }

    if ($menu -ne $NULL)
    {
        Write-Host "Trying to ping google.com in order to check that the changing is working..." -ForegroundColor Yellow -BackgroundColor Black
        if ((Test-NetConnection -ComputerName 'google.com').pingsucceeded)
        {
            Write-Host "DNS resolving is working after the change, this is great" -ForegroundColor Green
        }
        else
        {
            $input = Read-Host "press [R] to restore original DNS settings or [Enter] to leave the changes"
            if ($input -eq "R")
            {
                $origIP = Get-Content $DNSBAKFILE
                Set-DnsClientServerAddress -InterfaceIndex $NetAdapterInterfaceIndex -ServerAddresses $origIP[0],$origIP[1]    
            }
        }
    }
} 
else 
{
    Write-Host "Note: Your current configured DNS server [$localDNS1] is doing great, no need to change it" -ForegroundColor Green -BackgroundColor Black
}

Write-Host ""

Read-Host "Press [Enter] to open report files and finish the test"
Invoke-Expression $BlockedUsingLocalDNSFile
Invoke-Expression $BlockedUsingDNSFiltersFile