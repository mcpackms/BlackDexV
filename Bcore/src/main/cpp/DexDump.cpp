//
// Created by Milk on 2021/5/16.
//

#include "DexDump.h"
#include "utils/HexDump.h"
#include "utils/Log.h"
#include "VmCore.h"
#include "utils/PointerCheck.h"
#include "jnihook/Art.h"
#include "jnihook/ArtM.h"

#include <cstdio>
#include <fcntl.h>
#include <cstring>
#include <cstdlib>
#include <map>
#include <list>
#include <mutex>
#include <sys/mman.h>
#include "unistd.h"

#include "dex/dex_file-inl.h"
#include "dex/dex_file_loader.h"
#include "jnihook/JniHook.h"
#include "xhook/xhook.h"
#include "Dobby/include/dobby.h"

#define _uintval(p)               reinterpret_cast<uintptr_t>(p)
#define _ptr(p)                   reinterpret_cast<void *>(p)
#define _align_up(x, n)           (((x) + ((n) - 1)) & ~((n) - 1))
#define _align_down(x, n)         ((x) & -(n))
#define _page_size                4096
#define _page_align(n)            _align_up(static_cast<uintptr_t>(n), _page_size)
#define _ptr_align(x)             _ptr(_align_down(reinterpret_cast<uintptr_t>(x), _page_size))
#define _make_rwx(p, n)           ::mprotect(_ptr_align(p), \
                                              _page_align(_uintval(p) + n) != _page_align(_uintval(p)) ? _page_align(n) + _page_size : _page_align(n), \
                                              PROT_READ | PROT_WRITE | PROT_EXEC)

using namespace std;
// empty.jar 中 classes.dex 的 file_size，用于在 DexFile 结构内定位 begin_/size_ 字段（旧逻辑 fallback）
static const size_t kEmptyDexSize = 1872;
// dex header 最小大小（不含任何 section 的最小合法 dex 即 0x70）
static const size_t kMinDexSize = 0x70;
// 防呆上限：防止壳篡改 header 中 file_size 字段导致超大分配或越界读
static const size_t kMaxDexSize = 512 * 1024 * 1024;

static int beginOffset = -2;
static std::string dumpPath;
std::list<size_t> dumped;
std::mutex dumpedMutex;

void handleDumpByDexFile(void *dex_file) {
    char magic[8] = {0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00};
    if (!PointerCheck::check(dex_file)) {
        return;
    }
    auto dexFile = static_cast<art_lkchan::DexFile *>(dex_file);

    size_t size = dexFile->Size();
    {
        std::lock_guard<std::mutex> lock(dumpedMutex);
        for (size_t value : dumped) {
            if (size == value) {
                return;
            }
        }
    }
    if (size < kMinDexSize || size > kMaxDexSize) {
        ALOGE("invalid dex size: %zu", size);
        return;
    }
    void *buffer = malloc(size);
    if (buffer) {
        memcpy(buffer, dexFile->Begin(), size);
        // fix magic
        memcpy(buffer, magic, sizeof(magic));

        const bool kVerifyChecksum = false;
        const bool kVerify = true;
        const art_lkchan::DexFileLoader dex_file_loader;
        std::string error_msg;
        std::vector<std::unique_ptr<const art_lkchan::DexFile>> dex_files;
        if (!dex_file_loader.OpenAll(reinterpret_cast<const uint8_t *>(buffer),
                                     size,
                                     "",
                                     kVerify,
                                     kVerifyChecksum,
                                     &error_msg,
                                     &dex_files)) {
            // Display returned error message to user. Note that this error behavior
            // differs from the error messages shown by the original Dalvik dexdump.
            ALOGE("Open dex error %s", error_msg.c_str());
            free(buffer);
            return;
        }

        char path[1024];
        sprintf(path, "%s/hook_%zu.dex", dumpPath.c_str(), size);
        auto fd = open(path, O_CREAT | O_WRONLY, 0600);
        if (fd >= 0) {
            size_t written = 0;
            while (written < size) {
                ssize_t w = write(fd, buffer + written, size - written);
                if (w <= 0) {
                    break;
                }
                written += static_cast<size_t>(w);
            }
            fsync(fd);
            if (written == size) {
                ALOGE("hook dump dex ======> %s", path);
            } else {
                remove(path);
            }
            close(fd);
        }
        free(buffer);
        {
            std::lock_guard<std::mutex> lock(dumpedMutex);
            dumped.push_back(size);
        }
    }
}

HOOK_JNI(int, kill, pid_t __pid, int __signal) {
    ALOGE("hooked so kill");
    return 0;
}

HOOK_JNI(int, killpg, int __pgrp, int __signal) {
    ALOGE("hooked so killpg");
    return 0;
}

HOOK_FUN(void, LoadMethodO, void *thiz,
         void *dex_file,
         void *method,
         void *klass,
         void *dst) {
    orig_LoadMethodO(thiz, dex_file, method, klass, dst);
    handleDumpByDexFile(dex_file);
}

HOOK_FUN(void, LoadMethodM, void *thiz,
         void *thread,
         void *dex_file,
         void *method,
         void *klass,
         void *dst) {
    orig_LoadMethodM(thiz, thread, dex_file, method, klass, dst);
    handleDumpByDexFile(dex_file);
}

HOOK_FUN(void, LoadMethodL, void *thiz,
         void *thread,
         void *dex_file,
         void *method,
         void *klass) {
    orig_LoadMethodL(thiz, thread, dex_file, method, klass);
    handleDumpByDexFile(dex_file);
}

void init(JNIEnv *env) {
    const char *soName = ".*\\.so$";
    xhook_register(soName, "kill", (void *) new_kill,
                   (void **) (&orig_kill));
    xhook_register(soName, "killpg", (void *) new_killpg,
                   (void **) (&orig_killpg));
    xhook_refresh(0);

    jlongArray emptyCookie = VmCore::loadEmptyDex(env);
    jsize arrSize = env->GetArrayLength(emptyCookie);
    if (env->ExceptionCheck() == JNI_TRUE) {
        return;
    }
    jlong *long_data = env->GetLongArrayElements(emptyCookie, nullptr);

    for (int i = 0; i < arrSize; ++i) {
        jlong cookie = long_data[i];
        if (cookie == 0) {
            continue;
        }
        auto dex = reinterpret_cast<char *>(cookie);
        for (int ii = 0; ii < 10; ++ii) {
            auto value = *(size_t *) (dex + ii * sizeof(size_t));
            // 优先方案：通过 dex magic 直接定位 DexFile::begin_
            // empty dex 由本进程加载、magic 未被加固抹除，因此一定可识别，不再依赖魔数
            if (PointerCheck::check(reinterpret_cast<void *>(value)) &&
                memcmp(reinterpret_cast<void *>(value), "dex\n", 4) == 0) {
                beginOffset = ii;
                env->ReleaseLongArrayElements(emptyCookie, long_data, 0);
                return;
            }
            // fallback：部分设备/版本上 DexFile 布局为 [begin_, size_]，
            // 通过 empty dex 的 file_size 定位 size_ 槽位，前一槽即 begin_
            if (value == kEmptyDexSize) {
                beginOffset = ii - 1;
                env->ReleaseLongArrayElements(emptyCookie, long_data, 0);
                return;
            }
        }
    }
    env->ReleaseLongArrayElements(emptyCookie, long_data, 0);
    beginOffset = -1;
}

void fixCodeItem(JNIEnv *env, const art_lkchan::DexFile *dex_file_, size_t begin) {
    for (size_t classdef_ctr = 0; classdef_ctr < dex_file_->NumClassDefs(); ++classdef_ctr) {
        const art_lkchan::DexFile::ClassDef &cd = dex_file_->GetClassDef(classdef_ctr);
        const uint8_t *class_data = dex_file_->GetClassData(cd);
        auto &classTypeId = dex_file_->GetTypeId(cd.class_idx_);
        std::string class_name = dex_file_->GetTypeDescriptor(classTypeId);

        if (class_data != nullptr) {
            art_lkchan::ClassDataItemIterator cdit(*dex_file_, class_data);
            cdit.SkipAllFields();
            while (cdit.HasNextMethod()) {
                const art_lkchan::DexFile::MethodId &method_id_item = dex_file_->GetMethodId(
                        cdit.GetMemberIndex());
                const char *method_name = dex_file_->GetMethodName(method_id_item);
                // 必须持有 std::string：直接 .c_str() 会指向临时对象析构后的悬垂内存
                std::string method_signature = dex_file_->GetMethodSignature(
                        method_id_item).ToString();
                auto java_method = VmCore::findMethod(env, class_name.c_str(), method_name,
                                                      method_signature.c_str());
                if (java_method) {
                    auto artMethod = ArtM::GetArtMethod(env, java_method);
                    if (!artMethod) {
                        cdit.Next();
                        continue;
                    }
                    const art_lkchan::DexFile::CodeItem *orig_code_item = cdit.GetMethodCodeItem();
                    if (cdit.GetMethodCodeItemOffset() && orig_code_item) {
                        size_t codeItemSize = dex_file_->GetCodeItemSize(*orig_code_item);
                        auto new_code_item =
                                reinterpret_cast<void *>(
                                        begin + ArtM::GetArtMethodDexCodeItemOffset(artMethod));
                        // 运行时 code_item 可能已被抽取/篡改，校验可读性与大小后再回填，避免越界读崩溃
                        if (codeItemSize > 0 && codeItemSize <= 0x100000 &&
                            PointerCheck::check(new_code_item)) {
                            memcpy((void *) orig_code_item, new_code_item, codeItemSize);
                        }
                    }
                } else {
                    env->ExceptionClear();
                }
                cdit.Next();
            }
        }
    }
}

void DexDump::cookieDumpDex(JNIEnv *env, jlong cookie, jstring dir, jboolean fix) {
    if (beginOffset == -2) {
        init(env);
    }
    if (beginOffset == -1) {
        ALOGD("dumpDex not support!");
        return;
    }
    char magic[8] = {0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00};
    auto base = reinterpret_cast<char *>(cookie);
    auto begin = *(size_t *) (base + beginOffset * sizeof(size_t));
    if (!PointerCheck::check(reinterpret_cast<void *>(begin))) {
        return;
    }
    auto dirC = env->GetStringUTFChars(dir, 0);

    auto dexSizeOffset = ((unsigned long) begin) + 0x20;
    size_t size = *(size_t *) dexSizeOffset;
    if (size < kMinDexSize || size > kMaxDexSize) {
        // 壳可能篡改 header 中的 file_size，这里做防呆校验
        ALOGE("invalid dex size: %zu", size);
        env->ReleaseStringUTFChars(dir, dirC);
        return;
    }

    void *buffer = malloc(size);
    if (!buffer) {
        env->ReleaseStringUTFChars(dir, dirC);
        return;
    }
    memcpy(buffer, reinterpret_cast<const void *>(begin), size);
    // fix magic
    memcpy(buffer, magic, sizeof(magic));

    const bool kVerifyChecksum = false;
    const bool kVerify = true;
    const art_lkchan::DexFileLoader dex_file_loader;
    std::string error_msg;
    std::vector<std::unique_ptr<const art_lkchan::DexFile>> dex_files;
    if (!dex_file_loader.OpenAll(reinterpret_cast<const uint8_t *>(buffer),
                                 size,
                                 "",
                                 kVerify,
                                 kVerifyChecksum,
                                 &error_msg,
                                 &dex_files)) {
        // Display returned error message to user. Note that this error behavior
        // differs from the error messages shown by the original Dalvik dexdump.
        ALOGE("Open dex error %s", error_msg.c_str());
        free(buffer);
        env->ReleaseStringUTFChars(dir, dirC);
        return;
    }

    if (fix && !dex_files.empty()) {
        fixCodeItem(env, dex_files[0].get(), begin);
    }
    char path[1024];
    sprintf(path, "%s/cookie_%zu.dex", dirC, size);
    auto fd = open(path, O_CREAT | O_WRONLY, 0600);
    if (fd >= 0) {
        size_t written = 0;
        while (written < size) {
            ssize_t w = write(fd, buffer + written, size - written);
            if (w <= 0) {
                break;
            }
            written += static_cast<size_t>(w);
        }
        fsync(fd);
        if (written == size) {
            ALOGE("cookie dump dex ======> %s", path);
        } else {
            remove(path);
        }
        close(fd);
    }
    free(buffer);
    env->ReleaseStringUTFChars(dir, dirC);
}

void DexDump::hookDumpDex(JNIEnv *env, jstring dir) {
    const char *dirC = env->GetStringUTFChars(dir, 0);
    if (dirC) {
        dumpPath = dirC;
        env->ReleaseStringUTFChars(dir, dirC);
    }
    const char *libart = "libart.so";

    // L
    void *loadMethod = DobbySymbolResolver(libart,
                                           "_ZN3art11ClassLinker10LoadMethodEPNS_6ThreadERKNS_7DexFileERKNS_21ClassDataItemIteratorENS_6HandleINS_6mirror5ClassEEE");
    if (!loadMethod) {
        // M
        loadMethod = DobbySymbolResolver(libart,
                                         "_ZN3art11ClassLinker10LoadMethodEPNS_6ThreadERKNS_7DexFileERKNS_21ClassDataItemIteratorENS_6HandleINS_6mirror5ClassEEEPNS_9ArtMethodE");
    }
    if (!loadMethod) {
        // O
        loadMethod = DobbySymbolResolver(libart,
                                         "_ZN3art11ClassLinker10LoadMethodERKNS_7DexFileERKNS_13ClassAccessor6MethodENS_6HandleINS_6mirror5ClassEEEPNS_9ArtMethodE");
    }

    if (loadMethod) {
        _make_rwx(loadMethod, _page_size);
        int ret = -1;
        if (android_get_device_api_level() >= __ANDROID_API_O__) {
            ret = DobbyHook(loadMethod, (void *) new_LoadMethodO,
                            (void **) &orig_LoadMethodO);
        } else if (android_get_device_api_level() >= __ANDROID_API_M__) {
            ret = DobbyHook(loadMethod, (void *) new_LoadMethodM,
                            (void **) &orig_LoadMethodM);
        } else {
            ret = DobbyHook(loadMethod, (void *) new_LoadMethodL,
                            (void **) &orig_LoadMethodL);
        }
        if (ret != 0) {
            ALOGE("hook LoadMethod failed: %d", ret);
        } else {
            ALOGD("hook LoadMethod success");
        }
    } else {
        ALOGE("loadMethod symbol not found");
    }
}

