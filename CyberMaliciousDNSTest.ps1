<#

Application: DNS filtering Test 
Publisher: Omer Friedman
Version: 0.9
Date: 19-05-2021

#>

CLS

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


$filteringServices = $nameservers.keys | Sort-Object
$help = @("
DNS filtering Test
------------------
This test can help you figure out if your DNS server is protecting you from dns resolving of domains that are used in
serving Ads, Phishing, Malvertising, Malware, Spyware, Ransomware, CryptoJacking, Fraud, Scam,Telemetry, Analytics, Tracking and more...

Step 1 - Run the tests using your current configured Primary DNS server: $localDNS1

Step 2 - Run the tests with different dns filtering services from the list below:
")
Write-Host $help
foreach ($fService in $filteringServices)
{
    Write-Host "*" $fService "-->" $nameservers.$fservice 
}
Write-Host ""

Write-Host "Checking if your primary DNS server [$localDNS1] is already in our DNS filtering servers list ..." -ForegroundColor Yellow
If ($localDNS2)
{
    Write-Host "Your Secondary DNS [$localDNS2] is only used when the primary DNS is not available, so it is not relevant for this test" -ForegroundColor Yellow
}


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
 } 

Write-Host ""
#download the basic blocked domains list from dbl.oisd.nl and store data in file
Write-Host "Downloading the basic blocked domains list from dbl.oisd.nl and storing in $BlockedDomainsFile file"
if (!(Get-ChildItem $BlockedDomainsFile -ErrorAction SilentlyContinue).Exists)
{
    $getBlockedDomains = Invoke-WebRequest -Uri "https://dbl.oisd.nl/basic/"
    $BlockedDomains = $getBlockedDomains.Content
    Set-Content $BlockedDomainsFile -Value $BlockedDomains -Force
}

#read the data from file and create it as a randomized array
$BlockedDomainsFile = [System.IO.File]::ReadALLLines($BlockedDomainsFile)
$totalBlockedDomains = $BlockedDomainsFile.Count - 15 #13 lines banner and 2 lines at the end of file
$banner = $BlockedDomainsFile[0..12]
Write-Output $banner
$BlockedDomains =  $BlockedDomainsFile | Sort-Object {Get-Random}
Write-Host "The (basic) list contains $totalBlockedDomains blocked domains" -ForegroundColor Green
Write-Host ""

$input = Read-Host "Input the numbers of blocked domains to test (Min=25 | Max=$totalBlockedDomains)"
if ($input -lt 25) {$input = 25}
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
"Maximum filtered domains by DNS filtering service server is: $MaxbByServer/$input" |  Out-File $BlockedUsingDNSFiltersFile -Append
$CSVFile | FT | Out-File $BlockedUsingDNSFiltersFile -Append

Write-Host ""

if ($MaxbByServer -gt $TotalBLLocalDNS)
{
    Write-Host "Note: We suggest replacing the current configured DNS settings to a DNS filtering service" -ForegroundColor red -BackgroundColor Black
} 
else 
{
    Write-Host "Note: Your current configured DNS server is doing great, no need to change it" -ForegroundColor Green -BackgroundColor Black
}

Write-Host ""
Read-Host "Press [Enter] to open report files and finish the test"

Invoke-Expression $BlockedUsingLocalDNSFile
Invoke-Expression $BlockedUsingDNSFiltersFile


