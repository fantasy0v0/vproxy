/* DO NOT EDIT THIS FILE - it is machine generated */
/* Header for class io_vproxy_vfd_posix_TapInfoST */
#ifndef _Included_io_vproxy_vfd_posix_TapInfoST
#define _Included_io_vproxy_vfd_posix_TapInfoST
#ifdef __cplusplus
extern "C" {
#endif

struct TapInfo_st;
typedef struct TapInfo_st TapInfo_st;

#ifdef __cplusplus
}
#endif

#include <jni.h>
#include <pni.h>

#ifdef __cplusplus
extern "C" {
#endif

PNIEnvExpand(TapInfo_st, TapInfo_st *)

PNI_PACK(struct, TapInfo_st, {
    char devName[16];
    int32_t fd;
});

#ifdef __cplusplus
}
#endif
#endif // _Included_io_vproxy_vfd_posix_TapInfoST
// metadata.generator-version: pni 21.0.0.8
// sha256:ed4b9509bc83f2d4094e68166f1faf6dda40beed483a109a0f498f5c35c4cae3
