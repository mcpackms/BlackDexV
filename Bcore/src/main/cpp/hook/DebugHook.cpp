//
// Anti-debug hooks.
//
// Packed apps frequently probe the debugger state through the native
// methods of android.os.Debug and abort (self-destruct / exit) when they
// believe a debugger is attached.  BlackDex does not attach a debugger,
// but we make the probes deterministic so packers can never observe a
// "debugged" state:
//   - isDebuggerConnected()        -> false
//   - isNativeDebuggerConnected()  -> false
//   - waitingForDebugger()         -> false
//   - waitForDebugger()            -> no-op (never blocks)
//
// The hooking style (RegisterNatives replacement through JniHook) is the
// exact same one used by ProcessHook, so no new machinery is introduced.
//

#include "DebugHook.h"
#include <jni.h>
#import <JniHook.h>
#import "utils/Log.h"

HOOK_JNI(jboolean, isDebuggerConnected, JNIEnv *env, jobject obj) {
    return JNI_FALSE;
}

HOOK_JNI(jboolean, isNativeDebuggerConnected, JNIEnv *env, jobject obj) {
    return JNI_FALSE;
}

HOOK_JNI(jboolean, waitingForDebugger, JNIEnv *env, jobject obj) {
    return JNI_FALSE;
}

HOOK_JNI(void, waitForDebugger, JNIEnv *env, jobject obj) {
    // Intentionally do nothing: never block waiting for a debugger.
}

void DebugHook::init(JNIEnv *env) {
    const char *className = "android/os/Debug";

    JniHook::HookJniFun(env, className, "isDebuggerConnected", "()Z",
                        (void *) new_isDebuggerConnected,
                        (void **) (&orig_isDebuggerConnected), true);
    JniHook::HookJniFun(env, className, "isNativeDebuggerConnected", "()Z",
                        (void *) new_isNativeDebuggerConnected,
                        (void **) (&orig_isNativeDebuggerConnected), true);
    JniHook::HookJniFun(env, className, "waitingForDebugger", "()Z",
                        (void *) new_waitingForDebugger,
                        (void **) (&orig_waitingForDebugger), true);
    JniHook::HookJniFun(env, className, "waitForDebugger", "()V",
                        (void *) new_waitForDebugger,
                        (void **) (&orig_waitForDebugger), true);
}
