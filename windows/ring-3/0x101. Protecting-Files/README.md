
# Killshot

- This windows kit uses [detours](https://github.com/microsoft/Detours)

## Functionality 

- CreateFileW — intercepts attempts to open/create files (used to block opens that request write/delete access).
- WriteFile — intercepts writes to an open file handle (used to detect writes to the protected file and overwrite/deny them) 
- DeleteFileW — intercepts filename-based delete requests (used to block deletes of the protected paths).
- SetFileAttributesW — intercepts attribute changes (used to block attribute modifications like making the file hidden/system).
- MoveFileW — intercepts simple renames/moves using filename arguments (blocks moving the protected file).
- MoveFileExW — intercepts extended move/rename operations (covers additional flags/options when moving the file).
- CreateProcessW — intercepts process creation (logs the command line and attempts to inject the DLL into child processes)

> This DLL is essentially a file protector + process logger/injector.
It uses Microsoft Detours to hook common Win32 APIs and enforce rules:
Protect specific files from being written, deleted, moved, or having attributes changed.
Force overwrite attempts with a specific string 
Log all process creation events and inject itself into child processes.
Log events into hidden log files under C:\ProgramData\Microsoft\Diagnostics

