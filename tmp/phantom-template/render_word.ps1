$ErrorActionPreference = 'Stop'
$word = New-Object -ComObject Word.Application
$word.Visible = $false
$word.DisplayAlerts = 0
$src = 'D:\project-1\output\PHANTOM_Project_Report_Word\PHANTOM_Project_Report_Final.docx'
$pdf = 'D:\project-1\tmp\phantom-template\word-preview-final.pdf'
$doc = $null
try {
  $doc = $word.Documents.Open($src, $false, $false, $false)
  $doc.Fields.Update() | Out-Null
  foreach ($toc in $doc.TablesOfContents) { $toc.Update() | Out-Null }
  foreach ($tof in $doc.TablesOfFigures) { $tof.Update() | Out-Null }
  $doc.Save()
  $doc.ExportAsFixedFormat($pdf, 17)
  Write-Output ("TOCs=" + $doc.TablesOfContents.Count + " TOFs=" + $doc.TablesOfFigures.Count)
} finally {
  if ($doc -ne $null) { $doc.Close(0) | Out-Null }
  $word.Quit() | Out-Null
  [System.Runtime.InteropServices.Marshal]::ReleaseComObject($doc) | Out-Null
  [System.Runtime.InteropServices.Marshal]::ReleaseComObject($word) | Out-Null
}
Get-Item $src,$pdf | Select-Object FullName,Length,LastWriteTime
