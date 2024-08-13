#ifndef HOOK_FACTORY_H
#define HOOK_FACTORY_H
#include <tuple>
#include <Windows.h>
#include <vector>
#include "detours.h"
#include "magic_enum.h"
#include <sstream>
#include <functional>
std::tuple hookFunctionDefs = {
#include "hook_function_def.txt"
};
enum class hookFunctionEnum : size_t {
#include "hook_function_def.txt"
};

class HookManager {
private:
    HookManager() = default;
public:
    std::function<void(std::string)> outputFunction = nullptr;
    static HookManager& instance() {
        static HookManager instance;
        return instance;
    }
    template <typename returnType, typename... Args>
    void addHookFunc(returnType (__stdcall * pPointer)(Args...),
                     returnType (__stdcall *pDetour)(Args...)) {
        hookFunctions.push_back({(PVOID)pPointer, (PVOID)pDetour});
    }
    PVOID getOriginFunc(size_t index) {
        return hookFunctions[index].first;
    }
    PVOID getHookFunc(size_t index) {
        return hookFunctions[index].second;
    }
    void output(std::string s) {
        if (outputFunction != nullptr) {
            outputFunction(s);
        }
    }
    void startHook() {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        for (auto &[pPointer, pDetour] : hookFunctions) {
            DetourAttach(&pPointer, pDetour);
        }
        DetourTransactionCommit();
    }
private:
    std::vector<std::pair<PVOID,PVOID>> hookFunctions;
};

template <typename T, typename std::enable_if<std::is_integral<T>::value, void*>::type value = nullptr>
std::string formatArg(T arg) {
    return std::to_string(arg);
}
std::string formatArg(const char* arg) {
    if (arg == nullptr) {
        return "[nullptr]";
    }
    return arg;
}
std::string formatArg(void *arg) {
    std::stringstream ss;
    ss<<arg;
    return ss.str();
}


template <size_t index, typename func>
struct DebugHelper;
template <size_t index, typename returnType, typename... Args>
struct DebugHelper<index, returnType (__stdcall *)(Args...)> {
    using Functor = returnType (__stdcall *)(Args...);
    static returnType __stdcall Debug(Args... args) {
        auto functor = (Functor)HookManager::instance().getOriginFunc(index);
        auto result = functor(args...);
        auto function_name = magic_enum::enum_name(static_cast<hookFunctionEnum>(index));
        auto title = "[" + std::string(function_name) + "_" + std::to_string(rand()%1000) + "]";
        {
            std::stringstream ss;
            ss<<title<<"args:";
            ((ss<<formatArg(args)<<","),...);
            HookManager::instance().output(ss.str());
        }
        {
            std::stringstream ss;
            ss<<title<<"res:"<<result;
            HookManager::instance().output(ss.str());
        }
        return result;
    }
};

class registry {
public:
    registry() {
    }
protected:
    class registry_ {
    public:
        template <size_t... Indexes>
        void apply_by_index(std::index_sequence<Indexes...>) {
            (HookManager::instance().addHookFunc(std::get<Indexes>(hookFunctionDefs),
                                                 DebugHelper<Indexes,
                                                              std::remove_reference_t<decltype(std::get<Indexes>(hookFunctionDefs))>
                                                              >::Debug), ...);
        }
       registry_() {
            static constexpr auto tupleIndex = std::make_index_sequence<std::tuple_size<decltype(hookFunctionDefs)>::value>();
            apply_by_index(tupleIndex);
        }
    };
    static registry_ clazz_;
};
registry::registry_ registry::clazz_;
#endif // HOOK_FACTORY_H
