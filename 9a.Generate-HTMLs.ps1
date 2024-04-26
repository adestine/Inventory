# This script generate HTML report from info collectect with 9.Inventory.ps1
# Arnaud Destine (c)
# 
# -----------------------------------#

param(
    [parameter(Mandatory=$false)]
    [String]$cmd,
    [String]$hostname
)

$outputDir = "C:\Users\arnau\OneDrive\Desktop\LS2024\Output"
$ogDir =  "C:\Users\arnau\OneDrive\Desktop\LS2024\Output\OGs"
$latestDir =  "C:\Users\arnau\OneDrive\Desktop\LS2024\Output\Latests"
$backupsDir =  "C:\Users\arnau\OneDrive\Desktop\LS2024\Output\Backups"
$reportsDir =  "C:\Users\arnau\OneDrive\Desktop\LS2024\Output\Reports"
$exhaustiveCompare = 1 # If set to true, compare Hashes, process list and netstat
 
$colorh3 = "OrangeRed"
$colorh1 = "Turquoise"

function Generate-Html-report-diff {
    param (
        [Parameter(Mandatory=$true)][string]$og_results,
        [Parameter(Mandatory=$true)][string]$new_results,
        [Parameter(Mandatory=$true)][string]$hostname,
        [Parameter(Mandatory=$true)][string]$reportDir
    )
    
    if((Test-Path $og_results\autoruns.html) -and (Test-Path $new_results\autoruns.html)){
        write-host "[+] Comparing Autorunsc entries."
        $autoruns_og = Get-Content -Path $og_results\autoruns.html
        $autoruns_new = Get-Content -Path $new_results\autoruns.html
        $autoruns_diff = Compare-Object -ReferenceObject $autoruns_og -DifferenceObject $autoruns_new -PassThru | Where-Object {$_.SideIndicator -eq '=>'}
    }
    <#if((Test-Path $og_results\fwrules.html) -and (Test-Path $new_results\fwrules.html)){
        write-host "[+] Comparing Firewall rules."
        $fwrules_og = Get-Content -Path $og_results\fwrules.html
        $fwrules_new = Get-Content -Path $new_results\fwrules.html
        $fwrules_diff = Compare-Object -ReferenceObject $fwrules_og -DifferenceObject $fwrules_new -PassThru | Where-Object {$_.SideIndicator -eq '=>'}
    }#>
    if((Test-Path $og_results\netshares.html) -and (Test-Path $new_results\netshares.html)){
        write-host "[+] Comparing Network Shares information."
        $netshares_og = Get-Content -Path $og_results\netshares.html
        $netshares_new = Get-Content -Path $new_results\netshares.html
        $netshares_diff = Compare-Object -ReferenceObject $netshares_og -DifferenceObject $netshares_new -PassThru | Where-Object {$_.SideIndicator -eq '=>'}   
    }
    <#if($exhaustiveCompare){
        if((Test-Path $og_results\hashes.html) -and (Test-Path $new_results\hashes.html)){
            write-host "[+] Comparing Hashes of files of interest."
            $hashes_og = Get-Content -Path $og_results\hashes.html
            $hashes_new = Get-Content -Path $new_results\hashes.html
            $hashes_diff = Compare-Object -ReferenceObject $hashes_og -DifferenceObject $hashes_new -PassThru | Where-Object {$_.SideIndicator -eq '=>'}
        }
    }
    if((Test-Path $og_results\localusers.html) -and (Test-Path $new_results\localusers.html)){
        write-host "[+] Comparing Local Users."
        $localusers_og = Get-Content -Path $og_results\localusers.html
        $localusers_new = Get-Content -Path $new_results\localusers.html
        $localusers_diff = Compare-Object -ReferenceObject $localusers_og -DifferenceObject $localusers_new -PassThru | Where-Object {$_.SideIndicator -eq '=>'}
    }#>
    if((Test-Path $og_results\sshkeys.html) -and (Test-Path $new_results\sshkeys.html)){
        write-host "[+] Comparing Authorized SSH Keys."
        $sshkeys_og = Get-Content -Path $og_results\sshkeys.html
        $sshkeys_new = Get-Content -Path $new_results\sshkeys.html    
        $sshkeys_diff = Compare-Object -ReferenceObject $sshkeys_og -DifferenceObject $sshkeys_new -PassThru | Where-Object {$_.SideIndicator -eq '=>'}
    }
    <#if($exhaustiveCompare){
        if((Test-Path $og_results\netstat.html) -and (Test-Path $new_results\netstat.html)){
            write-host "[+] Comparing Netstat output."
            $netstat_og = Get-Content -Path $og_results\netstat.html
            $netstat_new = Get-Content -Path $new_results\netstat.html
            $netstat_diff = Compare-Object -ReferenceObject $netstat_og -DifferenceObject $netstat_new -PassThru | Where-Object {$_.SideIndicator -eq '=>'}
        }
    }#>
    if((Test-Path $og_results\hotfix.html) -and (Test-Path $new_results\hotfix.html)){
        write-host "[+] Comparing Hotfix installed."
        $hotfix_og = Get-Content -Path $og_results\hotfix.html
        $hotfix_new = Get-Content -Path $new_results\hotfix.html
        $hotfix_diff = Compare-Object -ReferenceObject $hotfix_og -DifferenceObject $hotfix_new -PassThru | Where-Object {$_.SideIndicator -eq '=>'}
    }
    if((Test-Path $og_results\products.html) -and (Test-Path $new_results\products.html)){
        write-host "[+] Comparing Products installed."
        $products_og = Get-Content -Path $og_results\products.html
        $products_new = Get-Content -Path $new_results\products.html
        $products_diff = Compare-Object -ReferenceObject $products_og -DifferenceObject $products_new -PassThru | Where-Object {$_.SideIndicator -eq '=>'}
    }
    if((Test-Path $og_results\dnscache.html) -and (Test-Path $new_results\dnscache.html)){
        write-host "[+] Comparing DNS Cache entries."
        $dnscache_og = Get-Content -Path $og_results\dnscache.html
        $dnscache_new = Get-Content -Path $new_results\dnscache.html
        $dnscache_diff = Compare-Object -ReferenceObject $dnscache_og -DifferenceObject $dnscache_new -PassThru | Where-Object {$_.SideIndicator -eq '=>'}
    }
    if($exhaustiveCompare){
        if((Test-Path $og_results\pslist.html) -and (Test-Path $new_results\pslist.html)){
            write-host "[+] Comparing Processes."
            $pslist_og = Get-Content -Path $og_results\pslist.html
            $pslist_new = Get-Content -Path $new_results\pslist.html
            $pslist_diff = Compare-Object -ReferenceObject $pslist_og -DifferenceObject $pslist_new -PassThru | Where-Object {$_.SideIndicator -eq '=>'}
        }
    }
    <#if((Test-Path $og_results\dirlist.html) -and (Test-Path $new_results\dirlist.html)){
        write-host "[+] Comparing Users directory listing entries."
        $dirlist_og = Get-Content -Path $og_results\dirlist.html
        $dirlist_new = Get-Content -Path $new_results\dirlist.html    
        $dirlist_diff = Compare-Object -ReferenceObject $dirlist_og -DifferenceObject $dirlist_new -PassThru | Where-Object {$_.SideIndicator -eq '=>'}
    }#>
    if((Test-Path $og_results\svcfailure.html) -and (Test-Path $new_results\svcfailure.html)){
        write-host "[+] Comparing Service Failure Actions."
        $svcfailure_og = Get-Content -Path $og_results\svcfailure.html
        $svcfailure_new = Get-Content -Path $new_results\svcfailure.html    
        $svcfailure_diff = Compare-Object -ReferenceObject $svcfailure_og -DifferenceObject $svcfailure_new -PassThru | Where-Object {$_.SideIndicator -eq '=>'}
    }
    if((Test-Path $og_results\defexcl.html) -and (Test-Path $new_results\defexcl.html)){
        write-host "[+] Comparing Defender Exclusion entries."
        $defexcl_og = Get-Content -Path $og_results\defexcl.html
        $defexcl_new = Get-Content -Path $new_results\defexcl.html    
        $defexcl_diff = Compare-Object -ReferenceObject $defexcl_og -DifferenceObject $defexcl_new -PassThru | Where-Object {$_.SideIndicator -eq '=>'}
    }
    if((Test-Path $og_results\fltmc.html) -and (Test-Path $new_results\fltmc.html)){
        write-host "[+] Comparing Minifilters."
        $fltmc_og = Get-Content -Path $og_results\fltmc.html
        $fltmc_new = Get-Content -Path $new_results\fltmc.html    
        $fltmc_diff = Compare-Object -ReferenceObject $fltmc_og -DifferenceObject $fltmc_new -PassThru | Where-Object {$_.SideIndicator -eq '=>'}
    }
    if((Test-Path $og_results\status.html) -and (Test-Path $new_results\status.html)){
        write-host "[+] Comparing Critical Service status."
        $status_og = Get-Content -Path $og_results\status.html
        $status_new = Get-Content -Path $new_results\status.html    
        $status_diff = Compare-Object -ReferenceObject $status_og -DifferenceObject $status_new -PassThru | Where-Object {$_.SideIndicator -eq '=>'}
    }
    if(($hostname.Contains("dc1") -or $hostname.Contains("dc2")) -and (Test-Path $og_results\gpo.html) -and (Test-Path $new_results\gpo.html)) {
        write-host "[+] Comparing GPOs."
        $gpo_og = Get-Content -Path $og_results\gpo.html
        $gpo_new = Get-Content -Path $new_results\gpo.html    
        $gpo_diff = Compare-Object -ReferenceObject $gpo_og -DifferenceObject $gpo_new -PassThru | Where-Object {$_.SideIndicator -eq '=>'}
    }
    if((Test-Path $og_results\grpmembers.html) -and (Test-Path $new_results\grpmembers.html)){
        write-host "[+] Comparing Local Groups Members."
        $localgroups_og = Get-Content -Path $og_results\grpmembers.html
        $localgroups_new = Get-Content -Path $new_results\grpmembers.html    
        $localgroups_diff = Compare-Object -ReferenceObject $localgroups_og -DifferenceObject $localgroups_new -PassThru | Where-Object {$_.SideIndicator -eq '=>'}
    }
    if((Test-Path $og_results\ntfs.html) -and (Test-Path $new_results\ntfs.html)){
        write-host "[+] Comparing Network Shares NTFS Accesses."
        $ntfs_og = Get-Content -Path $og_results\ntfs.html
        $ntfs_new = Get-Content -Path $new_results\ntfs.html    
        $ntfs_diff = Compare-Object -ReferenceObject $ntfs_og -DifferenceObject $ntfs_new -PassThru | Where-Object {$_.SideIndicator -eq '=>'}
    }

    # Generate Html output

    $html = "<h1 style='color:$colorh1;'>### Comparison results for $hostname ###</h1>"
    
    #------------------#

    if($autoruns_diff){
        $html += "<h3 style='color:$colorh3;'>Sysinternals autorunsc:</h3><table>"
        $html += "<tr><th>Entry Location</th><th>Entry</th><th>Enabled</th><th>Category</th><th>Profile</th><th>Description</th><th>Signer</th><th>Company</th><th>Image Path</th><th>Version</th><th>Launch String</th><th>MD5</th><th>SHA-1</th><th>PESHA-1</th><th>PESHA-256</th><th>SHA-256</th><th>IMP</th></tr>"
        $html += $autoruns_diff
        $html += "</table>"
    }
    if($svcfailure_diff){
        $html += "<h3 style='color:$colorh3;'>Services Failure Actions:</h3><table>"
        $html += "<tr><th>ServiceName</th><th>CmdLine</th><th>FailAction1</th><th>FailAction2</th><th>FailAction3</th><th>RstPeriod</th></tr>"
        $html += $svcfailure_diff
        $html += "</table>"       
    }
    if($gpo_diff){
        $html += "<h3 style='color:$colorh3;'>GPOs:</h3><table>"
        $html += "<tr><th>Id</th><th>DisplayName</th><th>Owner</th><th>DomainName</th><th>CreationTime</th><th>ModificationTime</th><th>UserDSVersion</th><th>UserSysvolVersion</th><th>ComputerDSVersion</th><th>ComputerSysvolVersion</th><th>GpoStatus</th><th>WmiFilter</th></tr>"
        $html += $gpo_diff
        $html += "</table>"       
    }
    #------------------#

    if($localusers_diff){
        $html += "<h3 style='color:$colorh3;'>Local Users:</h3><table>"
        $html += "<tr><th>Username</th><th>SID</th><th>Description</th><th>Enabled</th><th>PasswordExpires</th><th>PasswordRequired</th><th>Groups</th></tr>"
        $html += $localusers_diff
        $html += "</table>"
    }
    if($sshkeys_diff){
        $html += "<h3 style='color:$colorh3;'>Authorized SSH Keys:</h3><table>"
        $html += "<tr><th>User</th><th>Key</th></tr>"
        $html += $sshkeys_diff
        $html += "</table>"
    }
    if($localgroups_diff){
        $html += "<h3 style='color:$colorh3;'>Local Groups Members:</h3><table>"
        $html += "<tr><th>GroupName</th><th>Members</th></tr>"
        $html += $localgroups_diff
        $html += "</table>"
    }
    if($netshares_diff){
        $html += "<h3 style='color:$colorh3;'>Network Shares:</h3><table>"
        $html += "<tr><th>Name</th><th>Path</th><th>Description</th><th>AccountName</th><th>AccessControlType</th><th>AccessRight</th></tr>"
        $html += $netshares_diff
        $html += "</table>"
    }
    if($ntfs_diff){
        $html += "<h3 style='color:$colorh3;'>Network Shares NTFS Access:</h3><table>"
        $html +="<tr><th>FullName</th><th>Account</th><th>AccessRights</th><th>AccessControlType</th><th>InheritanceFlags</th><th>InheritanceEnabled</th><th>InheritedFrom</th></tr>"
        $html += $ntfs_diff
        $html += "</table>"
    }
    if($status_diff){
        $html += "<h3 style='color:$colorh3;'>Status Firewall and Defender:</h3><table>"
        $html += "<tr><th>Service</th><th>Status</th></tr>"
        $html += $status_diff
        $html += "</table>"       
    }
    if($fwrules_diff){
        $html += "<h3 style='color:$colorh3;'>Firewall Rules:</h3><table>"
        $html += "<tr><th>Rule</th></tr>"
        $html += $fwrules_diff
        $html += "</table>"
    }
    #------------------#

    if($defexcl_diff){
        $html += "<h3 style='color:$colorh3;'>Defender Exclusions:</h3><table>"
        $html += "<tr><th>Paths</th><th>Extensions</th><th>Processes</th><th>IPs</th><th>BruteForce</th><th>AttackSurface</th></tr>"
        $html += $defexcl_diff
        $html += "</table>"
    }
    if($fltmc_diff){
        $html += "<h3 style='color:$colorh3;'>Minifilter drivers:</h3><table>"
        $html += "<tr><th>FilterName</th><th>Altitude</th><th>Frame</th></tr>"
        $html += $fltmc_diff
        $html += "</table>"
    }
    #------------------#
    
    if($hashes_diff){
        $html += "<h3 style='color:$colorh3;'>Hashes:</h3><table>"
        $html += "<tr><th>Path</th><th>SHA1</th></tr>"
        $html += $hashes_diff
        $html += "</table>"
    }
    if($dirlist_diff){
        $html += "<h3 style='color:$colorh3;'>Users directories listing:</h3><table>"
        $html += "<tr><th>FileName</th></tr>"
        $html += $dirlist_diff
        $html += "</table>"
    }
    #------------------#

    if($products_diff){
        $html += "<h3 style='color:$colorh3;'>Products:</h3><table>"
        $html += "<tr><th>IdentifyingNumber</th><th>Name</th><th>Caption</th><th>Vendor</th><th>Version</th><th>InstallLocation</th><th>InstallDate</th><th>LocalPackage</th></tr>"
        $html += $products_diff
        $html += "</table>"
    }
    if($hotfix_diff){
        $html += "<h3 style='color:$colorh3;'>HotFixs:</h3><table>"
        $html += "<tr><th>HotfixID</th><th>Caption</th><th>Description</th><th>InstalledBy</th><th>InstalledOn</th></tr>"
        $html += $hotfix_diff
        $html += "</table>"
    }
    #------------------#

    if($dnscache_diff){
        $html += "<h3 style='color:$colorh3;'>DNS Cache:</h3><table>"
        $html += "<tr><th>Entry</th><th>Name</th><th>RecordType</th><th>DataLength</th><th>Data</th></tr>"
        $html += $dnscache_diff
        $html += "</table>"
    }
    if($netstat_diff){
        $html += "<h3 style='color:$colorh3;'>Netstat:</h3><table>"
        $html += "<tr><th>LocalAddress</th><th>LocalPort</th><th>RemoteAddress</th><th>RemotePort</th><th>State</th><th>ProcessName</th><th>ProcessPath</th></tr>"
        $html += $netstat_diff
        $html += "</table>"
    }
    if($pslist_diff){
        $html += "<h3 style='color:$colorh3;'>Process listing:</h3><table>"
        $html += "<tr><th>ProcessName</th><th>Path</th><th>FileVersion</th><th>Description</th><th>Product</th><th>SHA1</th></tr>"
        $html += $pslist_diff
        $html += "</table>"
    }  
    return $html
}

function Generate-Html-report {
    param (
        [Parameter(Mandatory=$true)][string]$results,
        [Parameter(Mandatory=$true)][string]$hostname,
        [Parameter(Mandatory=$true)][string]$reportDir
    )
      
    $html = "<h1 style='color:$colorh1;'>### Inventory report for $hostname ###</h1>"
        
    $html += "<h3 style='color:$colorh3;'>Local Users:</h3>"
    $html += Get-Content -Path $results\localusers.html

    $html += "<h3 style='color:$colorh3;'>Authorized SSH Keys:</h3><table>"
    $html += Get-Content -Path $results\sshkeys.html

    $html += "<h3 style='color:$colorh3;'>Local Groups Members:</h3>"
    $html += Get-Content -Path $results\grpmembers.html

    if($hostname.Contains("dc1") -or $hostname.Contains("dc2")){
        $html += "<h3 style='color:$colorh3;'>GPOs:</h3><table>"
        $html += Get-Content -Path $results\gpo.html
    }
    
    $html += "<h3 style='color:$colorh3;'>Network Shares:</h3><table>"
    $html += Get-Content -Path $results\netshares.html

    $html += "<h3 style='color:$colorh3;'>Network Shares NTFS Access:</h3>"
    $html += Get-Content -Path $results\ntfs.html

    $html += "<h3 style='color:$colorh3;'>Status Firewall and Defender:</h3><table>"
    $html += Get-Content -Path $results\status.html

    $html += "<h3 style='color:$colorh3;'>Defender Exclusions:</h3><table>"
    $html += Get-Content -Path $results\defexcl.html

    $html += "<h3 style='color:$colorh3;'>Minifilter drivers:</h3><table>"
    $html += Get-Content -Path $results\fltmc.html

    $html += "<h3 style='color:$colorh3;'>DNS Cache:</h3><table>"
    $html += Get-Content -Path $results\dnscache.html

    $html += "<h3 style='color:$colorh3;'>Netstat:</h3><table>"
    $html += Get-Content -Path $results\netstat.html

    $html += "<h3 style='color:$colorh3;'>Process listing:</h3><table>"
    $html += Get-Content -Path $results\pslist.html

    $html += "<h3 style='color:$colorh3;'>Firewall Rules:</h3><table>"
    $html += Get-Content -Path $results\fwrules.html

    $html += "<h3 style='color:$colorh3;'>Products:</h3><table>"
    $html += Get-Content -Path $results\products.html

    $html += "<h3 style='color:$colorh3;'>HotFixs:</h3><table>"
    $html += Get-Content -Path $results\hotfix.html
    
    $html += "<h3 style='color:$colorh3;'>Services Failure Actions:</h3><table>"
    $html += Get-Content -Path $results\svcfailure.html
    
    $html += "<h3 style='color:$colorh3;'>Sysinternals autorunsc:</h3><table>"
    $html += Get-Content -Path $results\autoruns.html

    $html += "<h3 style='color:$colorh3;'>Users directories listing:</h3><table>"
    $html += Get-Content -Path $results\dirlist.html

    $html += "<h3 style='color:$colorh3;'>Hashes:</h3><table>"
    $html += Get-Content -Path $results\hashes.html
    
    return $html
}

function Generate-Html-hardening-report {
    param (
        [Parameter(Mandatory=$true)][string]$results,
        [Parameter(Mandatory=$true)][string]$hostname,
        [Parameter(Mandatory=$true)][string]$reportDir
    )
      
    $html = "<h1 style='color:$colorh1;'>### Hardening report for $hostname ###</h1>"
        
    $html += "<h3 style='color:$colorh3;'>Local Users:</h3>"
    $html += Get-Content -Path $results\localusers.html

    $html += "<h3 style='color:$colorh3;'>Authorized SSH Keys:</h3><table>"
    $html += Get-Content -Path $results\sshkeys.html

    $html += "<h3 style='color:$colorh3;'>Local Groups Members:</h3>"
    $html += Get-Content -Path $results\grpmembers.html

    if($hostname.Contains("dc1") -or $hostname.Contains("dc2")){
        $html += "<h3 style='color:$colorh3;'>GPOs:</h3><table>"
        $html += Get-Content -Path $results\gpo.html
    }
    
    $html += "<h3 style='color:$colorh3;'>Network Shares:</h3><table>"
    $html += Get-Content -Path $results\netshares.html

    $html += "<h3 style='color:$colorh3;'>Network Shares NTFS Access:</h3>"
    $html += Get-Content -Path $results\ntfs.html

    $html += "<h3 style='color:$colorh3;'>Status Firewall and Defender:</h3><table>"
    $html += Get-Content -Path $results\status.html

    $html += "<h3 style='color:$colorh3;'>Defender Exclusions:</h3><table>"
    $html += Get-Content -Path $results\defexcl.html

    $html += "<h3 style='color:$colorh3;'>Products:</h3><table>"
    $html += Get-Content -Path $results\products.html
    
    return $html
}

function Generate-Html-newModules-report {
    param (
        [Parameter(Mandatory=$true)][string]$og_results,
        [Parameter(Mandatory=$true)][string]$new_results,
        [Parameter(Mandatory=$true)][string]$hostname,
        [Parameter(Mandatory=$true)][string]$reportDir
    )
      
    $html = "<h1 style='color:$colorh1;'>### NewModules report for $hostname ###</h1>"
    
    if((-Not (Test-Path $og_results\localusers.html)) -and (Test-Path $new_results\localusers.html)){
        $html += "<h3 style='color:$colorh3;'>Local Users:</h3>"
        $html += Get-Content -Path $new_results\localusers.html
    }
    if((-Not (Test-Path $og_results\sshkeys.html)) -and (Test-Path $new_results\sshkeys.html)){
        $html += "<h3 style='color:$colorh3;'>Authorized SSH Keys:</h3><table>"
        $html += Get-Content -Path $new_results\sshkeys.html
    }
    
    if((-Not (Test-Path $og_results\grpmembers.html)) -and (Test-Path $new_results\grpmembers.html)){
        $html += "<h3 style='color:$colorh3;'>Local Groups Members:</h3>"
        $html += Get-Content -Path $new_results\grpmembers.html
    }
    if(($hostname.Contains("dc1") -or $hostname.Contains("dc2")) -and (-Not (Test-Path $og_results\gpo.html)) -and (Test-Path $new_results\gpo.html)) {
        $html += "<h3 style='color:$colorh3;'>GPOs:</h3><table>"
        $html += Get-Content -Path $new_results\gpo.html
    }
    if((-Not (Test-Path $og_results\netshares.html)) -and (Test-Path $new_results\netshares.html)){
        $html += "<h3 style='color:$colorh3;'>Network Shares:</h3><table>"
        $html += Get-Content -Path $new_results\netshares.html
    }
    if((-Not (Test-Path $og_results\ntfs.html)) -and (Test-Path $new_results\ntfs.html)){
        $html += "<h3 style='color:$colorh3;'>Network Shares NTFS Access:</h3>"
        $html += Get-Content -Path $new_results\ntfs.html
    }
    if((-Not (Test-Path $og_results\status.html)) -and (Test-Path $new_results\status.html)){
        $html += "<h3 style='color:$colorh3;'>Status Firewall and Defender:</h3><table>"
        $html += Get-Content -Path $new_results\status.html
    }
    if((-Not (Test-Path $og_results\defexcl.html)) -and (Test-Path $new_results\defexcl.html)){
        $html += "<h3 style='color:$colorh3;'>Defender Exclusions:</h3><table>"
        $html += Get-Content -Path $new_results\defexcl.html
    }
    if((-Not (Test-Path $og_results\fltmc.html)) -and (Test-Path $new_results\fltmc.html)){
        $html += "<h3 style='color:$colorh3;'>Minifilter drivers:</h3><table>"
        $html += Get-Content -Path $new_results\fltmc.html
    }
    if((-Not (Test-Path $og_results\dnscache.html)) -and (Test-Path $new_results\dnscache.html)){
        $html += "<h3 style='color:$colorh3;'>DNS Cache:</h3><table>"
        $html += Get-Content -Path $new_results\dnscache.html
    }
    if((-Not (Test-Path $og_results\netstat.html)) -and (Test-Path $new_results\netstat.html)){
        $html += "<h3 style='color:$colorh3;'>Netstat:</h3><table>"
        $html += Get-Content -Path $new_results\netstat.html
    }
    if((-Not (Test-Path $og_results\pslist.html)) -and (Test-Path $new_results\pslist.html)){
        $html += "<h3 style='color:$colorh3;'>Process listing:</h3><table>"
        $html += Get-Content -Path $new_results\pslist.html
    }
    if((-Not (Test-Path $og_results\fwrules.html)) -and (Test-Path $new_results\fwrules.html)){
        $html += "<h3 style='color:$colorh3;'>Firewall Rules:</h3><table>"
        $html += Get-Content -Path $new_results\fwrules.html
    }
    if((-Not (Test-Path $og_results\products.html)) -and (Test-Path $new_results\products.html)){
        $html += "<h3 style='color:$colorh3;'>Products:</h3><table>"
        $html += Get-Content -Path $new_results\products.html
    }
    if((-Not (Test-Path $og_results\hotfix.html)) -and (Test-Path $new_results\hotfix.html)){
        $html += "<h3 style='color:$colorh3;'>HotFixs:</h3><table>"
        $html += Get-Content -Path $new_results\hotfix.html
    }
    if((-Not (Test-Path $og_results\svcfailure.html)) -and (Test-Path $new_results\svcfailure.html)){
        $html += "<h3 style='color:$colorh3;'>Services Failure Actions:</h3><table>"
        $html += Get-Content -Path $new_results\svcfailure.html
    }
    if((-Not (Test-Path $og_results\autoruns.html)) -and (Test-Path $new_results\autoruns.html)){
        $html += "<h3 style='color:$colorh3;'>Sysinternals autorunsc:</h3><table>"
        $html += Get-Content -Path $new_results\autoruns.html
    }
    if((-Not (Test-Path $og_results\dirlist.html)) -and (Test-Path $new_results\dirlist.html)){
        $html += "<h3 style='color:$colorh3;'>Users directories listing:</h3><table>"
        $html += Get-Content -Path $new_results\dirlist.html
    }   
    if((-Not (Test-Path $og_results\hashes.html)) -and (Test-Path $new_results\hashes.html)){
        $html += "<h3 style='color:$colorh3;'>Hashes:</h3><table>"
        $html += Get-Content -Path $new_results\hashes.html
    }
    
    return $html
}


# Take all the zip in output folder, deflate them and store them in latest directory + store the zip in backup folder
if($cmd -eq "update"){
    $archives = Get-ChildItem -Path $outputDir | Where-Object {$_.Name.EndsWith(".zip")}
    Write-Host "[+] Cleaning directory "$latestDir -foregroundcolor green
    Remove-Item -Path $latestDir -Recurse -Force
    Write-Host "[+] Extracting archives in "$latestDir -foregroundcolor yellow
    foreach($archive in $archives){
        Expand-Archive -Path $archive.FullName -DestinationPath $latestDir
        Copy-Item -Path $archive.FullName -Destination $backupsDir
        if(Test-Path $backupsDir\$archive){
            Remove-Item $archive.FullName
        }
    }
    Write-Host "[+] Backups stored in "$backupsDir -foregroundcolor green   
}

# Generate diff report for all hosts or for a specific hotname if mentioned
if($cmd -eq "diff"){
    
    $currentTime = Get-Date -Format "yyyyMMdd_HHmmss"
   
    if($hostname){
        $latests = Get-ChildItem -Path $latestDir -Directory | Where-Object {$_.Name.Contains($hostname)}
         $reportFileName =  $reportsDir+"\Diff_"+$hostname+"_report_"+$currentTime+".html"
    }else{
        $latests = Get-ChildItem -Path $latestDir -Directory
         $reportFileName =  $reportsDir+"\Aggregated_report_"+$currentTime+".html"
    }
 
    if ($latests.Count -eq 0){
        Write-Host "[!] Cannot find data for hostname:$hostname in $latestDir" -foregroundcolor red
    }
    else{
        $html = "<html><head><style>table { border-collapse: collapse; width: 100%; } th, td { border: 1px solid #dddddd; text-align: left; padding: 8px; }</style></head><body>"
        foreach($latest in $latests){
            $hostname = ($latest -split '_')[1]
            $ogPath = Get-ChildItem -Path $ogDir | Where-Object {$_.Name.Contains($hostname)}
            if($ogPath.Count -eq 0){
                Write-Host "[!] Cannot find original data for $hostname in $ogPath" -foregroundcolor red
            }else{
                Write-Host "[+] Aggregating data from host: "$hostname -foregroundcolor yellow
                $html += Generate-Html-report-diff $ogPath.FullName $latest.FullName $hostname $reportsDir
                
            }    
        }
        $html += "</body></html>" 
        $html | Out-File -FilePath $reportFileName
        Write-Host "[+] HTML report generated at "$reportFileName -foregroundcolor green
    }
}

# Generates full inventory report for all host or for a specific hostname if provided 
if($cmd -eq "report"){
    
    $currentTime = Get-Date -Format "yyyyMMdd_HHmmss"
    
    if($hostname){
        $latest = Get-ChildItem -Path $latestDir -Directory | Where-Object {$_.Name.Contains($hostname)}
        if($latest.count -eq 0){
            Write-Host "[!] Cannot find data for hostname:$hostname in $latestDir" -foregroundcolor red
            exit
        }else{
            
            $reportFileName =  $reportsDir+"\"+$hostname+"_report_"+$currentTime+".html"
            
            $html = "<html><head><style>table { border-collapse: collapse; width: 100%; } th, td { border: 1px solid #dddddd; text-align: left; padding: 8px; }</style></head><body>"
            $html += Generate-Html-report $latest.FullName $hostname $reportsDir
            $html += "</body></html>"
            
            $html | Out-File -FilePath $reportFileName 
            Write-Host "[+] HTML report generated at "$reportFileName -foregroundcolor green
        }

    }else{
        
        $latests = Get-ChildItem -Path $latestDir -Directory
        foreach($latest in $latests){
            
            $hostname = ($latest -split '_')[1]
            $reportFileName =  $reportsDir+"\"+$hostname+"_report_"+$currentTime+".html"
            
            $html = "<html><head><style>table { border-collapse: collapse; width: 100%; } th, td { border: 1px solid #dddddd; text-align: left; padding: 8px; }</style></head><body>"
            $html += Generate-Html-report $latest.FullName $hostname $reportsDir
            $html += "</body></html>"
            
            $html | Out-File -FilePath $reportFileName 
        }
        Write-Host "[+] HTML reports generated at in report directory" -foregroundcolor green
    }
}


# Generates small report usefull for hardening 
if($cmd -eq "hardening"){
    
    $currentTime = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFileName =  $reportsDir+"\Hardening_report_"+$currentTime+".html"

    $latests = Get-ChildItem -Path $latestDir -Directory
    foreach($latest in $latests){
        $hostname = ($latest -split '_')[1]    
        $html = "<html><head><style>table { border-collapse: collapse; width: 100%; } th, td { border: 1px solid #dddddd; text-align: left; padding: 8px; }</style></head><body>"
        $html += Generate-Html-hardening-report $latest.FullName $hostname $reportsDir
        $html += "</body></html>"

        $html | Out-File -FilePath $reportFileName -Append
    }
    Write-Host "[+] HTML reports generated at in report directory" -foregroundcolor green    
}

# Generates small report listing all new module information (not in OG result but in Latest results) 
if($cmd -eq "new"){
    
    $currentTime = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFileName =  $reportsDir+"\NewModules_report_"+$currentTime+".html"
    $html = "<html><head><style>table { border-collapse: collapse; width: 100%; } th, td { border: 1px solid #dddddd; text-align: left; padding: 8px; }</style></head><body>"
        
    $latests = Get-ChildItem -Path $latestDir -Directory
    foreach($latest in $latests){
        
        $hostname = ($latest -split '_')[1]    
        $ogPath = Get-ChildItem -Path $ogDir | Where-Object {$_.Name.Contains($hostname)}

        Write-Host "[+] Comparing data from host: "$hostname -foregroundcolor yellow
        $html += Generate-Html-newModules-report $ogPath.FullName $latest.FullName $hostname $reportsDir
        $html += "</body></html>"
    }
    $html | Out-File -FilePath $reportFileName
    Write-Host "[+] HTML reports generated at in report directory" -foregroundcolor green    
}
