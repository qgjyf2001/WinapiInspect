#include "apihook.h"
#include "hook_dll.h"
#include <iostream>
#include <tlhelp32.h>


ApiHook::ApiHook()
{
}

void UpdateAllThreads(std::vector<HANDLE>& handles,bool loop = true) {
    int updateTime = 0;
    std::unordered_set<DWORD> updatedThread;

    updatedThread.insert(GetCurrentThreadId());
    DetourUpdateThread(GetCurrentThread());

    while (true) {
        HookDllManager::instance().output("update thread for " + std::to_string(updateTime++) + " times");
        auto pid = GetCurrentProcessId();
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            std::cerr << "Failed to create thread snapshot." << std::endl;
            return;
        }

        THREADENTRY32 te32;
        te32.dwSize = sizeof(THREADENTRY32);

        if (!Thread32First(hSnapshot, &te32)) {
            std::cerr << "Failed to get first thread." << std::endl;
            CloseHandle(hSnapshot);
            return;
        }

        bool needUpdated = false;
        do {
            if (te32.th32OwnerProcessID == pid) {
                if (updatedThread.find(te32.th32ThreadID) != updatedThread.end()) {
                    continue;
                }
                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
                updatedThread.insert(te32.th32ThreadID);
                needUpdated = true;
                DetourUpdateThread(hThread);
                if (hThread != nullptr) {
                    handles.push_back(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te32));

        CloseHandle(hSnapshot);
        if (!needUpdated || !loop) {
            break;
        }
    }
}

registry::registry_ registry::clazz_;
void OnAttach() {
    auto pid = GetCurrentProcessId();
    auto outputFunction = [pid](std::string s){
        s = "[pid " + std::to_string(pid) + "]" + s;
        int flag = HookDllManager::instance().getRealFunction(WaitNamedPipeA)(pipeName, NMPWAIT_WAIT_FOREVER);
        if (flag != 0) {
            DWORD writeLength = 0;
//#define DEBUG_SELF
#ifdef DEBUG_SELF
            std::cout<<s<<std::endl;
#else
            auto hPipe = HookDllManager::instance().getRealFunction(CreateFileA)(pipeName,
                               GENERIC_READ | GENERIC_WRITE,
                               0,
                               NULL,
                               OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL,
                               NULL
                               );

            if (hPipe == INVALID_HANDLE_VALUE) {
                hPipe = NULL;
                return;
            }
            HookDllManager::instance().getRealFunction(WriteFile)( hPipe, s.data(), s.length()+1, &writeLength, NULL);
            HookDllManager::instance().getRealFunction(DisconnectNamedPipe)(hPipe);
#endif
        }
    };
    std::vector<HANDLE> handles;

    HookManager::instance().outputFunction = outputFunction;
    HookDllManager::instance().outputFunction = outputFunction;
    DetourTransactionBegin();
    UpdateAllThreads(handles);
    outputFunction("attaching process " + std::to_string(pid));
    HookManager::instance().startHook();
    HookDllManager::instance().startHook();;
    DetourTransactionCommit();
    for (auto handle: handles) {
        CloseHandle(handle);
    }
    handles.clear();

    DetourTransactionBegin();
    UpdateAllThreads(handles);
    HookDllManager::instance().feedback();
    DetourTransactionCommit();
    for (auto handle: handles) {
        CloseHandle(handle);
    }
    handles.clear();
}

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpvReserved )  // reserved
{
    // Perform actions based on the reason for calling.
    switch( fdwReason )
    {
    case DLL_PROCESS_ATTACH:
        OnAttach();
        break;

    case DLL_THREAD_ATTACH:
        // Do thread-specific initialization.
        break;

    case DLL_THREAD_DETACH:
        // Do thread-specific cleanup.
        break;

    case DLL_PROCESS_DETACH:

        if (lpvReserved != nullptr)
        {
            break; // do not do cleanup if process termination scenario
        }

        // Perform any necessary cleanup.
        break;
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}
