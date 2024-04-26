$PoShSessions = Get-PSSession | ? {$_.state -eq "Opened"}

ForEach ($PoshSession in $PoShSessions) {
    Write-Host "[!] Running on host $($PoshSession.Name)" -foregroundcolor yellow
        Invoke-Command -Session $PoshSession -ScriptBlock {

        $Task = Get-ScheduledTask -TaskName "UpnpAutoreconf" 
        if($Task){
            Unregister-ScheduledTask -TaskName "UpnpAutoreconf" -Confirm:$false 
            write-host "task removed :"$Task
        }
    }
}
