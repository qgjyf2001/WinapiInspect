#ifndef HOOK_DLL_H
#define HOOK_DLL_H

#include <windows.h>
#include <functional>
#include "detours.h"
#include <unordered_map>
#include <sstream>
PVOID reportFunctionCall(unsigned char* address);

__declspec(naked) void __cdecl traceFunction() {
    __asm{
        pop eax
        pushad
        push eax
        call reportFunctionCall
        mov [esp+32], eax
        pop eax
        popad
        jmp eax
    }
}
class HookDllManager {
private:
    HookDllManager() = default;

    static BOOL __stdcall exportsCallBack(_In_opt_ PVOID pContext,
                                                                    _In_ ULONG nOrdinal,
                                                                    _In_opt_ LPCSTR pszName,
                                _In_opt_ PVOID pCode) {
        if (pszName!=nullptr) {
            PVOID function_addr = (PVOID)GetProcAddress((HMODULE)pContext, pszName);
            auto& pair = instance().functor_map[function_addr];
            pair = {function_addr, pszName};
            if (DetourAttach(&pair.first, (PVOID)traceFunction) == NO_ERROR) {
                instance().output("attaching " + std::string(pszName));
            }
        }
        return true;
    }
    std::unordered_map<PVOID, std::pair<PVOID, std::string_view>> functor_map;
public:
    std::function<void(std::string)> outputFunction = nullptr;
    static HookDllManager& instance() {
        static HookDllManager instance;
        return instance;
    }

    template <typename T>
    T getRealFunction(T functor) {
        auto iter = functor_map.find((PVOID)functor);
        if (iter == functor_map.end()) {
            return functor;
        }
        return (T)iter->first;
    }

    void feedback() {
        for (auto& [originFunc, funcPair] : functor_map) {
            SIZE_T writen;
            char call_addr[] = {'\xe8'};
            getRealFunction(WriteProcessMemory)(getRealFunction(GetCurrentProcess)(), (LPVOID)originFunc, call_addr, 1, &writen);
        }
    }

    std::pair<PVOID, std::string_view> getFunction(PVOID address) {
        auto iter = functor_map.find(address);
        if (iter == functor_map.end()) {
            return {};
        }
        return iter->second;
    }

    void startHook() {
        char path[256] = {0};
        GetTempPathA(sizeof(path), path);
        strcat(path, "hook_dll_list.txt");
        auto file = fopen(path,"r");
        while (fscanf(file,"%s", path) != EOF) {
            auto module = LoadLibraryA(path);
            if (module == nullptr) {
                continue;
            }
            DetourEnumerateExports(module, module, exportsCallBack);
        }
        fclose(file);
    }

    void output(std::string s) {
        if (outputFunction != nullptr) {
            outputFunction("[dll hook]" + s);
        }
    }
};


PVOID reportFunctionCall(unsigned char* address) {
    address -= 5;
    std::stringstream ss;
    ss << "[address " << (void*)address << "]";
    auto [jmpAddr, functionName] = HookDllManager::instance().getFunction(address);
    if (jmpAddr != NULL) {
        ss << functionName << " called";
    } else {
        ss << "[panic] can't find function name and return address";
    }
    HookDllManager::instance().output(ss.str());
    return jmpAddr;
}


#endif // HOOK_DLL_H
