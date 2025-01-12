#include "io_vproxy_vfd_windows_IOCP.h"

#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT int JNICALL Java_io_vproxy_vfd_windows_IOCP_getQueuedCompletionStatusEx(PNIEnv_int * env, HANDLE handle, OVERLAPPED_ENTRY * completionPortEntries, uint32_t count, int32_t milliseconds, uint8_t alertable) {
    ULONG nRemoved = 0;
    BOOL ok = GetQueuedCompletionStatusEx(
        handle, completionPortEntries, count,
        &nRemoved, milliseconds, alertable
    );
    if (!ok) {
        if (GetLastError() == WAIT_TIMEOUT) {
            nRemoved = 0;
        } else {
            return throwIOExceptionBasedOnErrno(env);
        }
    }
    env->return_ = nRemoved;
    return 0;
}

JNIEXPORT int JNICALL Java_io_vproxy_vfd_windows_IOCP_createIoCompletionPort(PNIEnv_dummyHANDLE * env, HANDLE fileHandle, HANDLE existingCompletionPort, void * completionKey, int32_t numberOfConcurrentThreads) {
    HANDLE handle = CreateIoCompletionPort(
        fileHandle, existingCompletionPort,
        (ULONG_PTR)completionKey, numberOfConcurrentThreads
    );
    if (handle == INVALID_HANDLE_VALUE) {
        return throwIOExceptionBasedOnErrno(env);
    }
    env->return_ = (void*)handle;
    return 0;
}

JNIEXPORT int JNICALL Java_io_vproxy_vfd_windows_IOCP_postQueuedCompletionStatus(PNIEnv_void * env, HANDLE completionPort, int32_t numberOfBytesTransferred, void * completionKey, OVERLAPPED * overlapped) {
    BOOL ok = PostQueuedCompletionStatus(
        completionPort,
        numberOfBytesTransferred,
        (ULONG_PTR)completionKey,
        overlapped
    );
    if (!ok) {
        return throwIOExceptionBasedOnErrno(env);
    }
    return 0;
}

#ifdef __cplusplus
}
#endif
// metadata.generator-version: pni 22.0.0.17
// sha256:5730e82ee6793f27cb30fde6f9a909967bd0ff262a9f6e03304b7940c80314ad
