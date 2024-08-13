#include "apihook.h"
#include <iostream>

ApiHook::ApiHook()
{
}

registry::registry_ registry::clazz_;
void OnAttach() {
    auto pid = GetCurrentProcessId();
    HookManager::instance().outputFunction = [pid](std::string s){
        s = "[pid " + std::to_string(pid) + "]" + s;
        int flag = WaitNamedPipeA(pipeName, NMPWAIT_WAIT_FOREVER);
        if (flag != 0) {
            DWORD writeLength = 0;
            auto hPipe = CreateFileA(pipeName,
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
            WriteFile( hPipe, s.data(), s.length()+1, &writeLength, NULL);
            DisconnectNamedPipe(hPipe);
        }
    };
    HookManager::instance().startHook();
    HookManager::instance().output("attaching process " + std::to_string(pid));
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
