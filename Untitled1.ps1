$PoShSessions = Get-PSSession | ? {$_.state -eq "Opened"}

ForEach ($PoshSession in $PoShSessions) {
    Write-Host "[!] Running on host $($PoshSession.Name)" -foregroundcolor yellow          
    $result = Invoke-Command -Session $PoshSession -ScriptBlock {
        $sids = Get-ChildItem "Registry::\HKEY_USERS\"
        foreach($sid in $sids){
            set-itemproperty -path "Registry::\HKEY_USERS\$target_sid\Software\Policies\Microsoft\Windows\Installer" -name AlwaysInstallElevated -propertytype DWORD -Value 0 -Force;
        }
    }
    write-host $result
}