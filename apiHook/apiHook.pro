CONFIG -= qt

TEMPLATE = lib
DEFINES += APIHOOK_LIBRARY

CONFIG += c++17

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    apihook.cpp

HEADERS += \
    apiHook_global.h \
    apihook.h \
    hook_factory.h \
    magic_enum.h \
    hook_function_def.txt

INCLUDEPATH += "E:/git/detours/include"
LIBS += user32.lib "E:/git/detours/lib.X86/detours.lib"

# Default rules for deployment.
unix {
    target.path = /usr/lib
}
!isEmpty(target.path): INSTALLS += target

DESTDIR = $$PWD/../libs

