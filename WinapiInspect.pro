TEMPLATE = subdirs

SUBDIRS += \
    apiHook \
    apiHookGui

apiHookGui.depends = apiHook
