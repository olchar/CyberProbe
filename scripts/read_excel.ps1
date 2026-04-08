$excel = New-Object -ComObject Excel.Application
$excel.Visible = $false
$excel.DisplayAlerts = $false
try {
    $wb = $excel.Workbooks.Open("$PSScriptRoot\..\reports\ExportedEstimate.xlsx")
    foreach ($ws in $wb.Worksheets) {
        Write-Output "=== Sheet: $($ws.Name) ==="
        $usedRange = $ws.UsedRange
        $rowCount = [math]::Min($usedRange.Rows.Count, 100)
        $colCount = $usedRange.Columns.Count
        for ($r = 1; $r -le $rowCount; $r++) {
            $vals = @()
            for ($c = 1; $c -le $colCount; $c++) {
                $v = $usedRange.Cells($r, $c).Text
                if ($v -ne '') { $vals += $v }
            }
            if ($vals.Count -gt 0) { Write-Output ("  Row ${r}: " + ($vals -join ' | ')) }
        }
    }
    $wb.Close($false)
} finally {
    $excel.Quit()
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($excel) | Out-Null
}
