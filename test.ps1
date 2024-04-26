$latestDir =  "C:\Users\arnau\OneDrive\Desktop\LS2024\Output\Latests"

$filenames = @("defexcl.html","status.html","grpmembers.html")
function fixHtml{
    param (
        [Parameter(mandatory=$true)]$htmlIN
    )   
    
    $filename = Split-Path -Path $htmlIn -Leaf
    if($filenames -contains $filename){
        write-host "Fixing CRLF in "$filename
        $old = $htmlIN+".old"
        copy-item -Path $htmlIN -Destination $old
    

        $table = ((Get-Content -Path $htmlIN) -split '<table>')[1]
        $rows = ($table -split '</table>')[0]
    
        $row = $rows -split '<tr>'
        $html = "<table>`r`n"
        foreach($r in $row){
            if(-Not [string]::IsNullOrEmpty($r)){$html += "<tr>"+$r+"`r`n"}
        }
        $html += "</table>"
        $html | Out-File -FilePath $htmlIN
    }
}

$filesIN = (Get-ChildItem -Path $latestDir -Directory).FullName
foreach($fileIN in $filesIN){
    $files = (Get-ChildItem -Path $fileIN).FullName
    foreach($file in $files){
        fixHtml $file
    }
} 

function fixPsListHTML{
    param (
        [Parameter(mandatory=$true)]$htmlIN
    )   
        $old = $htmlIN+".old"
        copy-item -Path $htmlIN -Destination $old
    
        $table = Get-Content -Path $htmlIN
        $html = ""

        foreach($line in $table){
            if($line.StartsWith("<tr><th>Id</th>")){
                $brol = $line -replace "<th>Id</th>", ""
            }elseif($line.StartsWith("<colgroup><col/>")){
                $brol = $line -replace "<colgroup>.*?</colgroup>", ""
            }
            elseif($line.StartsWith("<tr><td></td>")){
                $brol = $line -replace "<tr><td></td>", ""
            }
            else{
                $brol = $line -replace "<td>\d{1,5}</td>", ""
            }
            $html += $brol+"`r`n"
        }
        $html | Out-File -FilePath $htmlIN

}

$latests = (Get-ChildItem -Path $latestDir -Directory).FullName
foreach($latest in $latests){
    write-host $latest
    $files = Get-ChildItem -Path $latest | Where-Object {$_.Name.Contains("pslist.html")}
    foreach($file in $files){
        write-host "Parsing "$file
        fixPsListHTML $file.FullName
    }
}

function fixNetstatHTML{
    param (
        [Parameter(mandatory=$true)]$htmlIN
    )   
        $old = $htmlIN+".old"
        copy-item -Path $htmlIN -Destination $old
    
        $table = Get-Content -Path $htmlIN
        $html = ""

        foreach($line in $table){
            if($line.EndsWith("<th>PID</th></tr>")){
                $brol = $line -replace "<th>PID</th>", ""
            }elseif($line.StartsWith("<colgroup><col/>")){
                $brol = $line -replace "<colgroup>.*?</colgroup>", ""
            }
            else{
                $brol = $line -replace "<td>\d{1,5}</td></tr>", "</tr>"
            }
            $html += $brol+"`r`n"
        }
        $html | Out-File -FilePath $htmlIN

}

$latests = (Get-ChildItem -Path $latestDir -Directory).FullName
foreach($latest in $latests){
    write-host $latest
    $files = Get-ChildItem -Path $latest | Where-Object {$_.Name.Contains("netstat.html")}
    foreach($file in $files){
        write-host "Parsing "$file
        fixNetstatHTML $file.FullName
    }
}

function fixAutorunsHTML{
    param (
        [Parameter(mandatory=$true)]$htmlIN
    )   
    
    $old = $htmlIN+".old"
    copy-item -Path $htmlIN -Destination $old
    
    $table = Get-Content -Path $htmlIN
    $html = ""
    foreach($line in $table){
        if($line.StartsWith("<tr><th>Time</th>")){
            $brol = $line -replace "<th>Time</th>", ""
        }elseif($line.StartsWith("<colgroup><col/>")){
            $brol = $line -replace "<colgroup>.*?</colgroup>", ""
        }
        elseif($line.StartsWith("<tr><td></td>")){
            $brol = $line -replace "<tr><td></td>", ""
        }
        else{
            $brol = $line -replace "<td>.*?(AM|PM)</td>", ""
        }
        $html += $brol+"`r`n"
    }
    $html | Out-File -FilePath $htmlIN
}

$latests = (Get-ChildItem -Path $latestDir -Directory).FullName
foreach($latest in $latests){
    write-host $latest
    $files = Get-ChildItem -Path $latest | Where-Object {$_.Name.Contains("autoruns.html")}
    foreach($file in $files){
        write-host "Parsing "$file
        fixAutorunsHTML $file.FullName
    }
}



#Compare-Object -ReferenceObject $og -DifferenceObject $latest