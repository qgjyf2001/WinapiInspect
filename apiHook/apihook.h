#ifndef APIHOOK_H
#define APIHOOK_H

#include "apiHook_global.h"
#include "hook_factory.h"

static constexpr auto pipeName = "\\\\.\\pipe\\hookCommutePipe";
class APIHOOK_EXPORT ApiHook
{
public:
    ApiHook();
};

#endif // APIHOOK_H
