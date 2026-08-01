//
// Hide the virtual-container environment from native inspection.
//

#ifndef BLACKDEX_PROCHIDEHOOK_H
#define BLACKDEX_PROCHIDEHOOK_H
#include "BaseHook.h"

class ProcHideHook : public BaseHook {
public:
    // Must be called (Java side) before enableIO() so the cache path is ready.
    static void setCacheDir(const char *dir);

    static void init(JNIEnv *env);
};


#endif //BLACKDEX_PROCHIDEHOOK_H
