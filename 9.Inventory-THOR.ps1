# This module fetch Thor output from all established PowerShell sessions
# Arnaud Destine (c)
# 
# -----------------------------------#

$PoShSessions = Get-PSSession | ? {$_.state -eq "Opened"}
$toolsDir = "C:\Users\arnau\OneDrive\Desktop\LS2024\Tools"
$outputDir = "C:\Users\arnau\OneDrive\Desktop\LS2024\Output\Thor"

$scriptblock = {

    param ($session,$outputfilename,$toolsDir,$outputDir)
    
    # Create output directory if it does not exist yet
    Invoke-Command -Session $session -ScriptBlock {
        param ($outputfilename)
        $output = "C:\tmp\"+$outputfilename
        if(-not(Test-Path $output)){$null = New-Item -Path $output -ItemType Directory} 
    } -ArgumentList $outputfilename 
    
    $check = Invoke-Command -Session $session -ScriptBlock {Test-Path C:\tmp\thor\thor64-lite.exe}
    
    if(-not $check){
        Copy-Item -Path $toolsDir\thor-lite-win.zip -ToSession $session -Destination C:\tmp\thor-lite-win.zip

        Invoke-Command -Session $session -ScriptBlock {
            param ($output)
            $archive = "C:\tmp\thor-lite-win.zip"
            if(Test-Path $archive){
                Expand-Archive -Path $archive -DestinationPath C:\tmp\thor\
                if(Test-Path C:\tmp\thor\thor64-lite.exe){
                    Remove-Item $archive
                }
            }
        } -ArgumentList $output
    }    

    Invoke-Command -Session $session -ScriptBlock {
        $csv = "C:\tmp\"+$outputfilename+"\thor_md5s.csv"
        $html = "C:\tmp\"+$outputfilename+"\thor.html"
        Start-Job -Name Thor -ScriptBlock {
            param ($output,$csv,$html)
            $thor = & C:\tmp\thor\thor64-lite.exe --csvfile $csv --htmlfile $html
        } -ArgumentList $output, $csv, $html
    }
                    
    # Wait for the job to finish 
    Invoke-Command -Session $session -ScriptBlock {Get-Job -Name Thor | Wait-Job }
    # Remove all jobs to keep it clean
    Invoke-Command -Session $session -ScriptBlock {Remove-Job -Name Thor -ErrorAction SilentlyContinue}


    Invoke-Command -Session $session -ScriptBlock {
        $output = "C:\tmp\"+$outputfilename
        $archive =  $output+".zip"
        Compress-Archive -Path $output -DestinationPath $archive   
        If(Test-Path $archive){
            Remove-Item -Path $output -Recurse -Force
        } 
    }

    # Get the output from the remote host
    $archivename = $outputfilename+".zip"
    $archive = "C:\tmp\"+$archivename
    Copy-Item -FromSession $session -Path $archive -Destination $outputDir\$archivename
    if(Test-Path $outputDir\$archivename){
        Invoke-Command -Session $session -ScriptBlock {Remove-Item -Path $archive -Force}
    }
}

# Defines Runspaces for parallele execution 
$availableProcessors = 50 #[System.Environment]::ProcessorCount
$maxRunspaces = [Math]::Min($PoshSessions.Count, $availableProcessors)

$runspacePool = [RunspaceFactory]::CreateRunspacePool(1,$maxRunspaces)
$runspacePool.Open()

$runspaces = $PoShSessions | ForEach-Object {
    $PoshSession = $_
    $currentTime = Get-Date -Format "yyyyMMdd_HHmmss"
    $outputfilename = "Thor_"+$PoshSession.Name+"_"+$currentTime
    Write-Host "[+] Initiating runspace for THOR collection on "$PoshSession -ForegroundColor yellow
    $runspace = [PowerShell]::Create().AddScript($scriptblock).AddParameter("session",$PoshSession).AddParameter("outputfilename",$outputfilename).AddParameter("toolsDir",$toolsDir).AddParameter("outputDir",$outputDir)
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