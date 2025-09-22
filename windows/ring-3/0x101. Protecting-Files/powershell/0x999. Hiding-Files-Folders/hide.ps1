
$FolderPath = "C:\SensitiveData"
$Acl = Get-Acl $FolderPath
$Ar = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone","ReadAndExecute","Deny")
$Acl.AddAccessRule($Ar)
Set-Acl $FolderPath $Acl
