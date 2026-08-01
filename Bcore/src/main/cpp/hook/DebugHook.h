//
// Anti-debug: neutralize android.os.Debug inspection used by packers.
//

#ifndef BLACKDEX_DEBUGHOOK_H
#define BLACKDEX_DEBUGHOOK_H
#include "BaseHook.h"

class DebugHook : public BaseHook {
public:
    static void init(JNIEnv *env);
};


#endif //BLACKDEX_DEBUGHOOK_H
