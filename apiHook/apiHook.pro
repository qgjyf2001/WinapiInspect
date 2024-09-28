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
    hook_dll.h \
    hook_factory.h \
    magic_enum.h \
    hook_function_def.txt

INCLUDEPATH += "E:/git/detours/include"
LIBS += user32.lib ws2_32.lib advapi32.lib
contains(QT_ARCH, x86_64) {
ml64.name = ML64 ${QMAKE_FILE_IN}
ml64.input = ASM_FILES
ml64.variable_out = OBJECTS
ml64.commands = ML64 /Fo ${QMAKE_FILE_OUT} /c ${QMAKE_FILE_NAME}
ml64.output = ${QMAKE_VAR_OBJECTS_DIR}${QMAKE_FILE_IN_BASE}$${first(QMAKE_EXT_OBJ)}
ml64.CONFIG += target_predeps
QMAKE_EXTRA_COMPILERS  += ml64

ASM_FILES += \
      trace_funtion_x64.s
LIBS += "E:/git/detours/lib.X64/detours.lib"
} else {
ml.name = ML ${QMAKE_FILE_IN}
ml.input = ASM_FILES
ml.variable_out = OBJECTS
ml.commands = ML /Fo ${QMAKE_FILE_OUT} /c ${QMAKE_FILE_NAME}
ml.output = ${QMAKE_VAR_OBJECTS_DIR}${QMAKE_FILE_IN_BASE}$${first(QMAKE_EXT_OBJ)}
ml.CONFIG += target_predeps
QMAKE_EXTRA_COMPILERS  += ml

ASM_FILES += \
      trace_funtion.s
LIBS += "E:/git/detours/lib.X86/detours.lib"
}

# Default rules for deployment.
unix {
    target.path = /usr/lib
}
!isEmpty(target.path): INSTALLS += target

DESTDIR = $$PWD/../libs

DISTFILES += \
    trace_funtion.s \
    trace_funtion_x64.s

