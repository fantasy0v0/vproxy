/* DO NOT EDIT THIS FILE - it is machine generated */
/* Header for class io_vproxy_vfd_windows_VIOContext */
#ifndef _Included_io_vproxy_vfd_windows_VIOContext
#define _Included_io_vproxy_vfd_windows_VIOContext
#ifdef __cplusplus
extern "C" {
#endif

struct VIOContext;
typedef struct VIOContext VIOContext;

#ifdef __cplusplus
}
#endif

#include <jni.h>
#include <pni.h>
#include "io_vproxy_vfd_windows_Overlapped.h"
#include "io_vproxy_vfd_windows_SOCKET.h"
#include "io_vproxy_vfd_windows_SockaddrStorage.h"

#ifdef __cplusplus
extern "C" {
#endif

PNIEnvExpand(VIOContext, VIOContext *)
PNIBufExpand(VIOContext, VIOContext, 248)

struct VIOContext {
    void * ptr;
    OVERLAPPED overlapped;
    int32_t ctxType;
    PNIRef * ref;
    SOCKET socket;
    int32_t ioType;
    WSABUF buffers[2];
    int32_t bufferCount;
    struct sockaddr_storage addr;
    int32_t addrLen;
};

#ifdef __cplusplus
}
#endif
#endif // _Included_io_vproxy_vfd_windows_VIOContext
// metadata.generator-version: pni 22.0.0.17
// sha256:4de60f623eaccbf8eb775b87f2dda7366f7b56dcb34fcbb0f6b9a809287a08de