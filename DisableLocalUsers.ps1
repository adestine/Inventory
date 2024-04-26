$PoShSessions = Get-PSSession | ? {$_.state -eq "Opened"}

ForEach ($PoshSession in $PoShSessions) {
    Write-Host "[!] Running on host $($PoshSession.Name)" -foregroundcolor yellow


        Write-Host "[+] removing local users"

        
        Invoke-Command -Session $PoshSession -ScriptBlock {

        $sExcludedUsers = "gt|scoringbot|BT2"
        $test = 0
        foreach ($oUser in $(Get-LocalUser | ? {$_.Name -notmatch $sExcludedUsers -and $_.Enabled})) { 
            Write-host "Disabling user :" $oUser
            Disable-LocalUser $oUser
            $test = 1
        }
        if($test) {Restart-Service sshd}
        
    }
}
