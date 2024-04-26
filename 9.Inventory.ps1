# This module fetch Inventory data from all the machines for which there is an Opened PSSession
# Arnaud Destine (c)
# 
# -----------------------------------#

$prop = [ordered]@{
    'autoruns' = 1 # Collects autorunsc64 output
    'fwrules' = 1 # Collects firewall rules
    'netshares' = 1 # Collects network shares info
    'hashes' = 1 # Collects hashes of files of interest
    'localusers' = 1 # Collects local users info
    'sshkeys' = 1 # Collects authorized ssh keys
    'netstat' = 1 # Collects Netstat output
    'hotfix' = 1 # Collects system hotfix info
    'products' = 1 # Collects system installed products
    'dnscache' = 1 # Collects DNS cache ouptut
    'pslist' = 1 # Collects process list
    'dirlist' = 0 # Collects directory listing of user profiles 
    'svcfailure' = 1 # Collectes services failure actions
    'defexcl' = 1 # Collects Defender exclusion list
    'fltmc' = 1 # Collects Defender exclusion list
    'status' = 1 # Collects information on the status of Defender and Firewall
    'gpo' = 1 # Collects GPO information from DCs
    'localgroups' = 1 # Collects nested group membership information
    'ntfs' = 1 # Collects NTFS root access for all network shares
}

$config = New-Object -Type psobject -Property $prop
$PoShSessions = Get-PSSession | ? {$_.state -eq "Opened"}
$toolsDir = "C:\Users\arnau\OneDrive\Desktop\LS2024\Tools"
$outputDir = "C:\Users\arnau\OneDrive\Desktop\LS2024\Output"
$exhaustive = 1 # Extand Hashes collection but can take 20-25 min more depending on the size of Recycle.Bin or Program Files

$scriptblock = {

    param ($session,$config,$outputfilename,$toolsDir,$outputDir,$exhaustive)
    
    # Create output directory if it does not exist yet
    Invoke-Command -Session $session -ScriptBlock {
        param ($outputfilename)
        $output = "C:\tmp\"+$outputfilename
        if(-not(Test-Path $output)){$null = New-Item -Path $output -ItemType Directory}   
    } -ArgumentList $outputfilename 
    

    #----------# 
    # Autoruns # 
    #----------# 
    if($config.autoruns){
        Copy-Item -Path $toolsDir\autorunsc64.exe -ToSession $session -Destination C:\tmp\autorunsc64.exe
        $test = Invoke-Command -Session $session -ScriptBlock {Test-Path C:\tmp\autorunsc64.exe}
        if($test){
            Invoke-Command -Session $session -ScriptBlock {
                Start-Job -Name Autoruns -ScriptBlock {
                    param ($output)
                    & "C:\tmp\autorunsc64.exe" -accepteula -nobanner -a * -s -h -c | ConvertFrom-Csv | ConvertTo-Html -Fragment | Out-File -FilePath $output\autoruns.html
                    if(Test-Path $output\autoruns.html){
                        Remove-Item -Path C:\tmp\autorunsc64.exe -Force
                    }
                } -ArgumentList $output
            }
        }
        else{
            throw [System.IO.FileNotFoundException] "Autorunsc64.exe didn't copy properly on target host:"+$session.Name
        }           
    }

    #----------------# 
    # Firewall Rules # 
    #----------------# 
    if($config.fwrules){
        Invoke-Command -Session $session -ScriptBlock { 
            Start-Job -Name FWRules -ScriptBlock {
                param ($output)

                # TO SLOW -> fetch from registry instead, still human readable and much more efficient
                <#$rules = Get-NetFirewallRule 
                $rulesInfo = @()
                $rules | ForEach-Object {
                    $portFilter = $_ | Get-NetFirewallPortFilter
                    $addressFilter = $_ | Get-NetFirewallAddressFilter
                    $applicationfilter = $_ | Get-NetFirewallApplicationFilter 
                    $ruleObject = [PSCustomObject]@{
                        "Name"= $_.Name
                        "Description" = $_.Description
                        "Protocol" = $portFilter.Protocol
                        "LocalPort" = $portFilter.LocalPort
                        "RemotePort" = $portFilter.RemotePort
                        "RemoteAddress" = $addressFilter.RemoteAddress
                        "Program" = $applicationfilter.Program
                        "Enabled" = $_.Enabled.ToString()
                        "Profile" = $_.Profile.ToString()
                        "Direction" = $_.Direction.ToString()
                        "Action" = $_.Action.ToString()
                    }
                    $rulesInfo += $ruleObject
                }  
                $rulesInfo | ConvertTo-Html -Fragment | Out-File -FilePath $output\fwrules.html 
                #>

                Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules | Get-Member -MemberType Properties | Select-Object Definition | ConvertTo-Html -Fragment | Out-File -FilePath $output\fwrules.html
            } -ArgumentList $output
        } 
    }

    #----------------# 
    # Network Shares #
    #----------------#
    if($config.netshares){
        Invoke-Command -Session $session -ScriptBlock { 
            Start-Job -Name NetShares -ScriptBlock{
                param ($output)
                Get-SmbShare | ForEach-Object {
                    $Path= $_.Path
                    $Name= $_.Name
                    $Description = $_.Description
                    Get-SmbShareAccess -Name $Name | ForEach-Object {
                        New-Object PSObject -Property @{
                        Name = $Name;
                        Path = $Path;
                        Description = $Description;
                        AccountName = $_.AccountName;
                        AccessControlType = $_.AccessControlType;
                        AccessRight = $_.AccessRight
                        } | Select-Object Name, Path, Description, AccountName, AccessControlType, AccessRight
                    }
                } | ConvertTo-Html -Fragment | Out-File -FilePath $output\netshares.html
            } -ArgumentList $output    
        }   
    }

    #-----------------------------# 
    # Hashes of files of interest #
    #-----------------------------#
    if($config.hashes){
        Invoke-Command -Session $session -ScriptBlock { 
            param($exhaustive)
            Start-Job -Name Hashes -ScriptBlock{
                param ($output,$exhaustive)

                $directoriesRec = "C:\Windows\System32","C:\Windows\SysWOW64"
                $directories = "C:\","C:\Windows"

                if($exhaustive){
                    $directoriesRec += "C:\`$Recycle.Bin","C:\Program Files","C:\Program Files (x86)"
                }
                $ExtList = "",".exe",".pif",".iso",".application",".gadget",".msi",".msp",".com",".scr",".hta",".cpl",".msc",".jar",".bat",".cmd",".vbs",".vb",".vbe",".js",".jse",".ws",".wsf",".wsc",".wsh",".ps1",".ps1xml",".ps2",".ps2xml",".psc1",".psc2",".msh",".msh1",".msh2",".mshxml",".msh1xml",".msh2xml",".scf",".lnk",".url",".inf",".reg",".dll",".zip",".tar"
                $exclude = "config\systemprofile\AppData\Local\Mozilla\Firefox\Profiles"
                $hashes =@()
                foreach ($dir in $directoriesRec){
                    $hashes += Get-ChildItem -Path $dir -File -Recurse -Force -ErrorAction SilentlyContinue | Where-Object {$ExtList.Contains($_.Extension) -and ($_.Length -lt 10000000) -and (-Not $_.FullName.Contains($exclude))} | Get-FileHash -Algorithm SHA1 -ErrorAction SilentlyContinue   
                }
                foreach ($dir in $directories){
                    $hashes += Get-ChildItem -Path $dir -File -Force -ErrorAction SilentlyContinue | Where-Object {$ExtList.Contains($_.Extension) -and ($_.Length -lt 10000000)} | Get-FileHash -Algorithm SHA1 -ErrorAction SilentlyContinue   
                }
                $hashes | Select-Object Hash,Path | ConvertTo-Html -Fragment | Out-File -FilePath $output\hashes.html
            
            } -ArgumentList $output, $exhaustive 
        } -ArgumentList $exhaustive
    }

    #-------------# 
    # Local Users #
    #-------------#
    if($config.localusers){
        Invoke-Command -Session $session -ScriptBlock {
            Start-Job -Name LocalUsers -ScriptBlock {
                param ($output)
                $localUser = Get-LocalUser
                $usersInfo = @()
                foreach ($user in $localUser){
                    $groups = Get-LocalGroup | where-object {$user.SID -in ($_ | Get-LocalGroupMember | Select-Object -ExpandProperty "SID")} | Select-Object -ExpandProperty "Name"  

                    if($user.PasswordExpires){$pwdExp=$user.PasswordExpires.ToString()}else{$pwdExp=""}
                    #if($user.PasswordChangeableDate){$pwdCh=$user.PasswordChangeableDate.ToString()}else{$pwdCh=""}
                    #if($user.PasswordLastSet){$pwdLs=$user.PasswordLastSet.ToString()}else{$pwdLs=""}
                    #if($user.LastLogon){$pwdLl=$user.LastLogon.ToString()}else{$pwdLl=""}

                    $userObject = [PSCustomObject]@{
                        "Username" = $user.Name;
                        "SID" = $user.SID.Value;
                        "Description" = $user.Description;
                        "Enabled" = $user.Enabled;
                        "PasswordExpires" = $pwdExp;
                        #"PasswordChangeableDate" = $pwdCh;
                        #"PasswordLastSet" = $pwdLs;
                        "PasswordRequired" = $user.PasswordRequired;
                        #"LastLogon" = $pwdLl;
                        "Groups" = $groups -join ', ';
                    }
                    $usersInfo += $userObject
                }
                $usersInfo | ConvertTo-Html -Fragment | Out-File -FilePath $output\localusers.html
            } -ArgumentList $output
        }
    }

    #---------------------# 
    # Authorized SSH Keys #
    #---------------------#
    if($config.sshkeys){
        Invoke-Command -Session $session -ScriptBlock {
            Start-Job -Name SSHKeys -ScriptBlock {
                param ($output)
                $userProfiles = Get-ChildItem -Path "C:\Users" -Directory
                $sshInfo = @()
                foreach ($profile in $userProfiles) {
                    $userName = $profile.Name
                    $authorizedKeysFile = "C:\Users\$userName\.ssh\authorized_keys"

                    if (Test-Path $authorizedKeysFile) {
                        $authorizedKeys = Get-Content $authorizedKeysFile
                        foreach ($key in $authorizedKeys) {
                            if(-Not [string]::IsNullOrWhitespace($key)){
                                $sshObject = [PSCustomObject]@{
                                    "User" = $userName
                                    "Key" = $key
                                }
                                $sshInfo += $sshObject
                            }
                        }
                    }
                }
                $sshInfo | ConvertTo-Html -Fragment | Out-File -FilePath $output\sshkeys.html
            } -ArgumentList $output
        }
    }

    #---------# 
    # Netstat #
    #---------#
    if($config.netstat){
        Invoke-Command -Session $session -ScriptBlock {
            Start-Job -Name Netstat -ScriptBlock {
                param ($output)
                Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, @{Name="State";Expression={$_.State.ToString()}} ,@{Name="ProcessName";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}}, @{Name="ProcessPath";Expression={(Get-Process -Id $_.OwningProcess).Path}}, @{Name="PID";Expression={$_.OwningProcess}} | ConvertTo-Html -Fragment | Out-File -FilePath $output\netstat.html
            } -ArgumentList $output
        }
    }

    #------------------# 
    # HotFix Installed #
    #------------------#
    if($config.hotfix){
        Invoke-Command -Session $session -ScriptBlock {
            Start-Job -Name HotFix -ScriptBlock {
                param ($output)
                $hotfix = Get-HotFix | Select-Object HotfixID, Caption, Description, InstalledBy, InstalledOn 
                $hotfixInfo =@()
                foreach($fix in $hotfix) {
                    $hotfixObject = [PSCustomObject]@{
                        "HotfixID"=$fix.HotfixID;
                        "Caption"=$fix.Caption;
                        "Description"=$fix.Description;
                        "InstalledBy"=$fix.InstalledBy;
                        "InstalledOn"=$fix.InstalledOn.DateTime;
                    }
                    $hotfixInfo += $hotfixObject
                }
                $hotfixInfo | Sort-Object InstalledOn | ConvertTo-Html -Fragment | Out-File -FilePath $output\hotfix.html
            } -ArgumentList $output
        }
    }

    #------------------# 
    # Product Insalled #
    #------------------#
    if($config.products){
        Invoke-Command -Session $session -ScriptBlock {
            Start-Job -Name Products -ScriptBlock {
                param ($output)
                Get-WmiObject Win32_Product | Select-Object IdentifyingNumber, Name, Caption, Vendor, Version, InstallLocation, InstallDate, LocalPackage | ConvertTo-Html -Fragment | Out-File -FilePath $output\products.html
            } -ArgumentList $output
        }
    }
    

    #-----------# 
    # DNS cache #
    #-----------#
    if($config.dnscache){
        Invoke-Command -Session $session -ScriptBlock {
            Start-Job -Name DNSCache -ScriptBlock {
                param ($output)
                $dnsmapping =@{
                    1 = "A"
                    2 = "NS"
                    5 = "CNAME"
                    12 = "PTR"
                    28 = "AAAA"
                }
                Get-DnsClientCache | Select-Object Entry,Name,@{Name="RecordType";Expression={$dnsmapping[[int]$_.Type]}},DataLength,Data | ConvertTo-Html -Fragment | Out-File -FilePath $output\dnscache.html
            } -ArgumentList $output
        }
    }

    #--------------# 
    # Process list #
    #--------------#
    if($config.pslist){
        Invoke-Command -Session $session -ScriptBlock {
            Start-Job -Name PSList -ScriptBlock {
                param ($output)
                Get-Process | Select-Object -Property Id,ProcessName,Path,FileVersion,Description,Product, @{Name="SHA1";Expression={(Get-FileHash -Path $_.Path -Algorithm SHA1 -ErrorAction SilentlyContinue).Hash}} | ConvertTo-Html -Fragment | Out-File -FilePath $output\pslist.html
            } -ArgumentList $output
        }
    }

    #-------------------------------------# 
    # Directory listing of users profiles #
    #-------------------------------------#
    if($config.dirlist){
        Invoke-Command -Session $session -ScriptBlock {
            Start-Job -Name DirList -ScriptBlock {
                param ($output)
                $userProfiles = Get-ChildItem -Path "C:\Users" -Directory
                $listing =@()
                foreach ($profile in $userProfiles) {
                    $listing += Get-ChildItem -Path $profile.FullName -Recurse -ErrorAction SilentlyContinue | Select-Object FullName
                }
                $listing | ConvertTo-Html -Fragment | Out-File -FilePath $output\dirlist.html
            } -ArgumentList $output
        }
    }

    #--------------------------#
    # Services Failure Actions #
    #--------------------------#
    if($config.svcfailure){
        Invoke-Command -Session $session -ScriptBlock {
            Start-Job -Name SvcFailure -ScriptBlock {
                param ($output)
                
                $data = & $env:windir\system32\sc query | ForEach-Object {
                    $svc = $_
                    if ($svc -match "SERVICE_NAME:\s(.*)") { 
                        & $env:windir\system32\sc qfailure $($matches[1])
                    }
                }

                $servicesInfo = @()

                $ServiceName = $RstPeriod = $CmdLine = $FailAction1 = $FailAction2 = $FailAction3 = $null
                $data | ForEach-Object {
                    $line = $_
                    
                    $line = $line.Trim()
                    if ($line -match "^S.*\:\s(?<SvcName>[-_A-Za-z0-9]+)") {
                        
                        if ($ServiceName) {
                            $serviceObject = [PSCustomObject]@{
                                "ServiceName"=$ServiceName;
                                "CmdLine"=$CmdLine;
                                "FailAction1"=$FailAction1;
                                "FailAction2"=$FailAction2;
                                "FailAction3"=$FailAction3;
                                "RstPeriod"=$RstPeriod;
                            }
                            $servicesInfo += $serviceObject
                            $ServiceName = $RstPeriod = $CmdLine = $FailAction1 = $FailAction2 = $FailAction3 = $null
                        }
                        $ServiceName = $matches['SvcName']
                    } elseif ($line -match "^RESE.*\:\s(?<RstP>[0-9]+|INFINITE)") {
                        $RstPeriod = $matches['RstP']
                    } elseif ($line -match "^C.*\:\s(?<Cli>.*)") {
                        $CmdLine = $matches['Cli']
                    } elseif ($line -match "^F.*\:\s(?<Fail1>.*)") {
                        $FailAction1 = $matches['Fail1']
                        $FailAction2 = $FailAction3 = $False
                    } elseif ($line -match "^(?<FailNext>REST.*)") {
                        if ($FailAction2) {
                            $FailAction3 = $matches['FailNext']
                        } else {
                            $FailAction2 = $matches['FailNext']
                        }
                    }
                }
                $serviceObject = [PSCustomObject]@{
                    "ServiceName"=$ServiceName;
                    "CmdLine"=$CmdLine;
                    "FailAction1"=$FailAction1;
                    "FailAction2"=$FailAction2;
                    "FailAction3"=$FailAction3;
                    "RstPeriod"=$RstPeriod;
                }
                $servicesInfo += $serviceObject
                $servicesInfo | ConvertTo-Html -Fragment | Out-File -FilePath $output\svcfailure.html

            } -ArgumentList $output
        }
    }

    #-------------------------# 
    # Defender Exclusion List #
    #-------------------------#
    if($config.defexcl){
        Invoke-Command -Session $session -ScriptBlock {
            Start-Job -Name DefExcl -ScriptBlock {
                param ($output)
                $exclusions = Get-MpPreference
                $exclPath = $exclusions.ExclusionPath
                $exclExt = $exclusions.ExclusionExtension
                $exclProcess = $exclusions.ExclusionProcess
                $exclIP = $exclusions.ExclusionIpAddress
                $exclBF = $exclusions.BruteForceProtectionExclusions
                $exclAS = $exclusions.AttackSurfaceReductionOnlyExclusions

                #Math::Max method only allow for 2 arguments so instead of comparing all of them 2 by 2 I add all of them to a list to use measure-object method.
                $sizes = @()
                $sizes += $exclPath.Length
                $sizes += $exclExt.Length
                $sizes += $exclProcess.Length
                $sizes += $exclIP.Length
                $sizes += $exclBF.Length
                $sizes += $exclAS.Length
                $maxLength = ($sizes | Measure-Object -Maximum).Maximum

                #Not using convertto-html because it does not print in a pretty way (one big line instead of one entry per line 
                $htmlTable = "<table><tr><th>Paths</th><th>Extensions</th><th>Processes</th><th>IPs</th><th>BruteForce</th><th>AttackSurface</th></tr>"
                for($i=0;$i -lt $maxLength;$i++){
                    $htmlTable +="<tr>"
                    if($exclPath){$htmlTable +="<td>$($exclPath[$i] -replace '^$', '')</td>"}else{$htmlTable +="<td></td>"}
                    if($exclExt){$htmlTable +="<td>$($exclExt[$i] -replace '^$', '')</td>"}else{$htmlTable +="<td></td>"}
                    if($exclProcess){$htmlTable +="<td>$($exclProcess[$i] -replace '^$', '')</td>"}else{$htmlTable +="<td></td>"}
                    if($exclIP){$htmlTable +="<td>$($exclIP[$i] -replace '^$', '')</td>"}else{$htmlTable +="<td></td>"}
                    if($exclBF){$htmlTable +="<td>$($exclBF[$i] -replace '^$', '')</td>"}else{$htmlTable +="<td></td>"}
                    if($exclAS){$htmlTable +="<td>$($exclAS[$i] -replace '^$', '')</td>"}else{$htmlTable +="<td></td>"}
                    $htmlTable +="</tr>"
                }
                $htmlTable += "</table>"
                $htmlTable | Out-File -FilePath $output\defexcl.html
            } -ArgumentList $output
        }
    }
    
    #--------------# 
    # Fltmc output #
    #--------------#
    if($config.fltmc){
        Invoke-Command -Session $session -ScriptBlock {
            Start-Job -Name Fltmc -ScriptBlock {
                param ($output)
                $fltmc = Invoke-Expression -Command "fltmc"
                $fltmcInfo = @()
                $fltmc | ForEach-Object {
                    if($_ -and (-not $_.startswith("Filter Name")) -and (-not $_.startswith("--------"))){
                        $line = $_.split(" ",[System.StringSplitOptions]::RemoveEmptyEntries)
                        $fltmcObject = [PSCustomObject]@{
                            'FilterName' = $line[0]
                            #'Instances' = $line[1]
                            'Altitude' = $line[2]
                            'Frame' = $line[3]
                        }
                        $fltmcInfo += $fltmcObject
                    }
                }
                $fltmcInfo | ConvertTo-Html -Fragment | Out-File -FilePath $output\fltmc.html
            } -ArgumentList $output
        }
    }

    #---------------# 
    # Status output #
    #---------------#
    if($config.status){
        Invoke-Command -Session $session -ScriptBlock {
            Start-Job -Name Status -ScriptBlock {
                param ($output)
                $htmlTable = "<table><tr><th>Service</th><th>Status</th></tr>"

                $FWService = Get-Service | Where-Object { $_.Name -eq "mpssvc" }
                $htmlTable += "<tr><td>Firewall Service</td><td>"+$FWService.Status+"</td></tr>"
            
                $FWProfiles = Get-NetFirewallProfile
                $FWProfiles | ForEach-Object {
                    $htmlTable += "<tr><td>FW Profile ("+$_.Name+")</td><td>"+$_.Enabled+"</td></tr>"
                
                }
            
                $DefenderStatus = Get-MpComputerStatus
                $htmlTable += "<tr><td>Defender - AntispywareEnabled</td><td>"+$DefenderStatus.AntispywareEnabled+"</td></tr>"
                $htmlTable += "<tr><td>Defender - AntivirusEnabled</td><td>"+$DefenderStatus.AntivirusEnabled+"</td></tr>"
                $htmlTable += "<tr><td>Defender - BehaviorMonitorEnabled</td><td>"+$DefenderStatus.BehaviorMonitorEnabled+"</td></tr>"
                $htmlTable += "<tr><td>Defender - IoavProtectionEnabled</td><td>"+$DefenderStatus.IoavProtectionEnabled+"</td></tr>"
                $htmlTable += "<tr><td>Defender - IsTamperProtected</td><td>"+$DefenderStatus.IsTamperProtected+"</td></tr>"
                $htmlTable += "<tr><td>Defender - NISEnabled</td><td>"+$DefenderStatus.NISEnabled+"</td></tr>"
                $htmlTable += "<tr><td>Defender - OnAccessProtectionEnabled</td><td>"+$DefenderStatus.OnAccessProtectionEnabled+"</td></tr>"
                $htmlTable += "<tr><td>Defender - RealTimeProtectionEnabled</td><td>"+$DefenderStatus.RealTimeProtectionEnabled+"</td></tr>"
                $htmlTable += "<tr><td>Defender - TDTStatus</td><td>"+$DefenderStatus.TDTStatus+"</td></tr>"
                
                $enabledASRRules = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
                foreach ($ruleId in $enabledASRRules) {
                    $htmlTable += "<tr><td>Defender - ASR Rules</td><td>"+$ruleId+"</td></tr>"
                }

                $htmlTable += "</table>"
                $htmlTable | Out-File -FilePath $output\status.html
            } -ArgumentList $output
        }
    }

    #------------# 
    # GPO output #
    #------------#
    if($config.gpo -and ($session.Name.Contains("dc1") -or $session.Name.Contains("dc2"))){
        Invoke-Command -Session $session -ScriptBlock {
            Start-Job -Name Gpo -ScriptBlock {
                param ($output)
                Get-GPO -All | Select-Object Id, DisplayName, Owner, DomainName, CreationTime, ModificationTime, @{Name="UserDSVersion";Expression={$_.User.DSVersion}},@{Name="UserSysvolVersion";Expression={$_.User.SysvolVersion}}, @{Name="ComputerDSVersion";Expression={$_.Computer.DSVersion}}, @{Name="ComputerSysvolVersion";Expression={$_.Computer.SysvolVersion}}, GpoStatus,WmiFilter | ConvertTo-Html -Fragment | Out-File -FilePath $output\gpo.html
            } -ArgumentList $output
        }
    }

    #---------------------# 
    # Local groups output #
    #---------------------#

    if($config.localgroups){
        Invoke-Command -Session $session -ScriptBlock {
            
            # Function to get all member of local groups and subgroups 
            $getLocalMembers = 'function Get-NestedLocalGroupsMembers {
            param (
                [Parameter(mandatory=$true)]$GroupName,
                [string[]]$GroupsParsed
            )
    
            if($GroupsParsed -contains $GroupName){
                return
            }
    
            $GroupsParsed += $Group 
            $members = Get-LocalGroupMember -Group $GroupName
            $resultArray = @()
       
            foreach($member in $members){
                if($member.PrincipalSource -eq "Local"){
                    $memberName = ($member.Name -split "\\")[1]
                    if($member.ObjectClass -eq "Group"){    
                        $resultArray += Get-NestedLocalGroupsMembers -GroupName $memberName -GroupsParsed $GroupsParsed
                    }
                    if($member.ObjectClass -eq "User"){
                        $resultArray += $memberName
                    }
                }
            }
            return $resultArray}'

            Start-Job -Name LocalGroups -ScriptBlock {
                param ($output,$getLocalMembers)
                $groups = Get-LocalGroup
                
                $html = "<table><tr><th>GroupName</th><th>Members</th></tr>"
                foreach($group in $groups){  
                    $fct = $getLocalMembers
                    $fct += 'Get-NestedLocalGroupsMembers -GroupName "'+$group.Name+'" -GroupsParsed @()'
                    $script = [scriptblock]::Create($fct)
                    $members = & $script
                    $members = $members -join ', '
                    $html += "<tr><td>"+$Group+"</td><td>"+$members+"</td></tr>"
                }
                
                $html += "</table>"
                $html | Out-File -FilePath $output\grpmembers.html
            } -ArgumentList $output,$getLocalMembers
        }
    }

    #-------------------# 
    # NTFS Share access #
    #-------------------#
    if($config.ntfs){
        
        $check = Invoke-Command -Session $session -ScriptBlock {Get-Module -ListAvailable -Name NTFSSecurity} 
        if(-Not $check){
            Copy-Item -Path $toolsDir\NTFSSecurity.zip -ToSession $session -Destination C:\Windows\System32\WindowsPowerShell\v1.0\Modules\NTFSSecurity.zip
            Invoke-Command -Session $session -ScriptBlock {
                Expand-Archive -Path C:\Windows\System32\WindowsPowerShell\v1.0\Modules\NTFSSecurity.zip -DestinationPath C:\Windows\System32\WindowsPowerShell\v1.0\Modules\
                Import-Module -Name NTFSSecurity -Force
            } 
        }
        
        Invoke-Command -Session $session -ScriptBlock {
            Start-Job -Name Ntfs -ScriptBlock {
                param ($output)
                $shares = Get-SmbShare | Where-Object {-Not [string]::IsNullOrEmpty($_.Path)}
                $ntfsAccessInfo = @()
                foreach($share in $shares){
                    $accesses = Get-NTFSAccess -Path $share.Path | Select-Object FullName, Account, AccessRights,AccessControlType,InheritanceFlags,InheritanceEnabled,InheritedFrom 
                    foreach($access in $accesses){
                        $ntfsAccessObject = [PSCustomObject]@{
                            'FullName' = $access.FullName
                            'Account' = $access.Account
                            'AccessRights' = $access.AccessRights
                            'AccessControlType' = $access.AccessControlType
                            'InheritanceFlags' = $access.InheritanceFlags
                            'InheritanceEnabled' = $access.InheritanceEnabled
                            'InheritedFrom' = $access.InheritedFrom
                        }
                        $ntfsAccessInfo += $ntfsAccessObject 
                    }
                }
                $ntfsAccessInfo | ConvertTo-Html -Fragment | Out-File -FilePath $output\ntfs.html -Append
            } -ArgumentList $output
        } 
    }


    # Wait for all the jobs started from this script to finish (do not use Get-Job -Name * | wait-job to not be impacted by others people jobs) 
    Invoke-Command -Session $session -ScriptBlock {Get-Job -Name Autoruns,FWRules,NetShares,Hashes,LocalUsers,SSHKeys,Netstat,HotFix,Products,DNSCache,PSList,DirList,SvcFailure,DefExcl,Fltmc,Status,Gpo,LocalGroups,Ntfs | Wait-Job }
    # Remove all jobs to keep it clean
    Invoke-Command -Session $session -ScriptBlock {Remove-Job -Name Autoruns,FWRules,NetShares,Hashes,LocalUsers,SSHKeys,Netstat,HotFix,Products,DNSCache,PSList,DirList,SvcFailure,DefExcl,Fltmc,Status,Gpo,LocalGroups,Ntfs  -ErrorAction SilentlyContinue}

    # Create the output archive on target host and delete the output folder
    Invoke-Command -Session $session -ScriptBlock {
        $archive =  $output+".zip"
        Compress-Archive -Path $output -DestinationPath $archive   
        If(Test-Path $archive){
            Remove-Item -Path $output -Recurse -Force
        } 
    }

    # Get the archive from the remote host on the local host and delete the archive from the remote host
    $archivename = $outputfilename+".zip"
    $archive = "C:\tmp\"+$archivename
    Copy-Item -FromSession $session -Path $archive -Destination $outputDir\$archivename
    if(Test-Path $outputDir\$archivename){
        Invoke-Command -Session $session -ScriptBlock {Remove-Item -Path $archive -Force}
    }
}


# Defines Runspaces for parallele execution 
$availableProcessors = [System.Environment]::ProcessorCount
$maxRunspaces = [Math]::Min($PoshSessions.Count, $availableProcessors)

$runspacePool = [RunspaceFactory]::CreateRunspacePool(1,$maxRunspaces)
$runspacePool.Open()

$runspaces = $PoShSessions | ForEach-Object {
    $PoshSession = $_
    $currentTime = Get-Date -Format "yyyyMMdd_HHmmss"
    $outputfilename = "Inventory_"+$PoshSession.Name+"_"+$currentTime
    Write-Host "[+] Initiating runspace for evidence collection on "$PoshSession.Name -ForegroundColor yellow
    $runspace = [PowerShell]::Create().AddScript($scriptblock).AddParameter("session",$PoshSession).AddParameter("config",$config).AddParameter("outputfilename",$outputfilename).AddParameter("toolsDir",$toolsDir).AddParameter("outputDir",$outputDir).AddParameter("exhaustive",$exhaustive)
    $runspace.RunspacePool = $runspacePool
    $runspace
}

$Threads = @()
Write-Host "[+] Starting all runspaces." -foregroundcolor yellow
$runspaces | ForEach-Object {
    $Threads += $_.BeginInvoke()
}

while($Threads.IsCompleted -contains $false){
    Start-Sleep -Milliseconds 100
}
Write-Host "[+] Evidence collected in "$outputDir -foregroundcolor green


$runspacePool.Close()
$runspacePool.Dispose()
