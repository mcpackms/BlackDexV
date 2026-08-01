//
// ProcHideHook: hide the virtual container from native /proc inspection.
//
// Packed apps (and their native shells) routinely open /proc/self/maps and
// scan it for signs of the host/container (host package install dir, host
// .so names, virtual data paths).  We intercept openat/open/fopen and
// redirect maps reads to a sanitised copy of the real maps: lines that
// carry host-container fingerprints are dropped, everything else (including
// the target app's own apk/lib paths under .../virtual/data/app/...) is
// kept intact so the shell can still locate its own code.
//
// Safety: every hook is optional.  If Dobby fails to resolve or patch a
// symbol we simply skip it and keep running with the real libc.  The
// sanitised cache lives inside the container's own writable cache dir.
//

#include "ProcHideHook.h"
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "Dobby/include/dobby.h"
#include "utils/Log.h"

static int (*orig_openat)(int, const char *, int, ...);
static int (*orig_open)(const char *, int, ...);
static FILE *(*orig_fopen)(const char *, const char *);
static FILE *(*orig_fgets)(char *, int, FILE *);
static int (*orig_fputs)(const char *, FILE *);
static int (*orig_fclose)(FILE *);

static char g_maps_cache_path[320];
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
static time_t g_last_refresh = 0;

// Fast pre-filter: only /proc/<...>/maps is interesting.
static bool is_maps_path(const char *path) {
    if (path == nullptr) {
        return false;
    }
    if (strstr(path, "/proc/") == nullptr) {
        return false;
    }
    return strstr(path, "/maps") != nullptr;
}

// Lines carrying host-container fingerprints are removed.
// The target app's own files live under ".../virtual/data/app/<pkg>/..."
// and are intentionally kept so the packer can still find its own libs.
static bool hide_line(const char *line) {
    if (strstr(line, "libblackdex") || strstr(line, "libblackbox") ||
        strstr(line, "black-hook") || strstr(line, "black-fake") ||
        strstr(line, "libblackbox_")) {
        return true;
    }
    // Host install dir (e.g. /data/app/~~xxx/top.niunaijun.blackdex-xxx/...)
    if (strstr(line, "/data/app/") != nullptr && strstr(line, "/virtual/") == nullptr) {
        return true;
    }
    // Host-internal files (vm.apk / empty.apk / junit.apk / config ...)
    if (strstr(line, "/virtual/cache/") || strstr(line, "/virtual/system")) {
        return true;
    }
    return false;
}

// Rebuild the sanitised maps cache.  Uses the original libc pointers so
// this never recurses back into the hooks.
static void refresh_maps_cache() {
    if (g_maps_cache_path[0] == '\0' || orig_fopen == nullptr ||
        orig_fgets == nullptr || orig_fputs == nullptr || orig_fclose == nullptr) {
        return;
    }
    FILE *in = orig_fopen("/proc/self/maps", "r");
    if (in == nullptr) {
        return;
    }
    FILE *out = orig_fopen(g_maps_cache_path, "w");
    if (out == nullptr) {
        orig_fclose(in);
        return;
    }
    char line[1024];
    while (orig_fgets(line, sizeof(line), in) != nullptr) {
        if (!hide_line(line)) {
            orig_fputs(line, out);
        }
    }
    orig_fclose(in);
    orig_fclose(out);
}

// Returns the cache path when the opened file is a proc maps file,
// nullptr otherwise (caller falls back to the real path).  The cache is
// refreshed at most once per second.
static const char *redirect_maps(const char *path) {
    if (!is_maps_path(path)) {
        return nullptr;
    }
    pthread_mutex_lock(&g_mutex);
    time_t now = time(nullptr);
    if (now - g_last_refresh > 1) {
        refresh_maps_cache();
        g_last_refresh = now;
    }
    const char *ret = nullptr;
    // 缓存不可用时回退真实路径，避免对调用方暴露失败的 fd
    if (g_maps_cache_path[0] != '\0' && access(g_maps_cache_path, R_OK) == 0) {
        ret = g_maps_cache_path;
    }
    pthread_mutex_unlock(&g_mutex);
    return ret;
}

int new_openat(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t) va_arg(ap, mode_t);
        va_end(ap);
    }
    const char *redirect = redirect_maps(pathname);
    if (redirect != nullptr) {
        return orig_openat(dirfd, redirect, flags, mode);
    }
    return orig_openat(dirfd, pathname, flags, mode);
}

int new_open(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t) va_arg(ap, mode_t);
        va_end(ap);
    }
    const char *redirect = redirect_maps(pathname);
    if (redirect != nullptr) {
        return orig_open(redirect, flags, mode);
    }
    return orig_open(pathname, flags, mode);
}

FILE *new_fopen(const char *path, const char *mode) {
    const char *redirect = redirect_maps(path);
    if (redirect != nullptr) {
        return orig_fopen(redirect, mode);
    }
    return orig_fopen(path, mode);
}

void ProcHideHook::setCacheDir(const char *dir) {
    if (dir == nullptr) {
        return;
    }
    size_t len = strlen(dir);
    if (len == 0 || len > sizeof(g_maps_cache_path) - 32) {
        return;
    }
    memcpy(g_maps_cache_path, dir, len);
    memcpy(g_maps_cache_path + len, "/.proc_self_maps", sizeof("/.proc_self_maps"));
}

static void try_hook(const char *symbol, void *replacement, void **orig_ptr) {
    void *addr = DobbySymbolResolver("libc.so", symbol);
    if (addr == nullptr) {
        ALOGE("ProcHideHook: symbol %s not found", symbol);
        return;
    }
    if (DobbyHook(addr, replacement, orig_ptr) != 0) {
        ALOGE("ProcHideHook: hook %s failed", symbol);
        *orig_ptr = nullptr;
        return;
    }
    ALOGD("ProcHideHook: hooked %s", symbol);
}

void ProcHideHook::init(JNIEnv *env) {
    try_hook("openat", (void *) new_openat, (void **) &orig_openat);
    try_hook("open", (void *) new_open, (void **) &orig_open);
    try_hook("fopen", (void *) new_fopen, (void **) &orig_fopen);

    // Resolve the libc helpers used to build the sanitised cache.
    orig_fgets = (FILE *(*)(char *, int, FILE *)) DobbySymbolResolver("libc.so", "fgets");
    orig_fputs = (int (*)(const char *, FILE *)) DobbySymbolResolver("libc.so", "fputs");
    orig_fclose = (int (*)(FILE *)) DobbySymbolResolver("libc.so", "fclose");
}
