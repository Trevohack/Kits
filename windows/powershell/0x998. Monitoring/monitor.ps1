$watcher = New-Object System.IO.FileSystemWatcher 
$watcher.Path = "C:\data"
$watcher.IncludeSubdirectories = $true
$watcher.EnableRaisingEvents = $true
$watcher.NotifyFilter = [System.IO.NotifyFilters]'FileName,DirectoryName,LastWrite'

Register-ObjectEvent $watcher 'Changed' -Action { Write-Host "ACCESS DETECTED: $($Event.SourceEventArgs.FullPath)" }
Register-ObjectEvent $watcher 'Created' -Action { Write-Host "ACCESS DETECTED: $($Event.SourceEventArgs.FullPath)" }
Register-ObjectEvent $watcher 'Deleted' -Action { Write-Host "ACCESS DETECTED: $($Event.SourceEventArgs.FullPath)" } 
