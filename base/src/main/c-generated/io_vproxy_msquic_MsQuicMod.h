/* DO NOT EDIT THIS FILE - it is machine generated */
/* Header for class io_vproxy_msquic_MsQuicMod */
#ifndef _Included_io_vproxy_msquic_MsQuicMod
#define _Included_io_vproxy_msquic_MsQuicMod
#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#include <jni.h>
#include <pni.h>
#include "msquic.h"
#include "io_vproxy_msquic_CxPlatProcessEventLocals.h"
#include "io_vproxy_vfd_posix_AEFiredExtra.h"

#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT void JNICALL JavaCritical_io_vproxy_msquic_MsQuicMod_MsQuicCxPlatWorkerThreadInit(struct CxPlatProcessEventLocals * CxPlatWorkerThreadLocals);
JNIEXPORT void JNICALL JavaCritical_io_vproxy_msquic_MsQuicMod_MsQuicCxPlatWorkerThreadBeforePoll(struct CxPlatProcessEventLocals * CxPlatProcessEventLocals);
JNIEXPORT uint8_t JNICALL JavaCritical_io_vproxy_msquic_MsQuicMod_MsQuicCxPlatWorkerThreadAfterPoll(struct CxPlatProcessEventLocals * locals, int32_t num, aeFiredExtra * events);
JNIEXPORT int32_t JNICALL JavaCritical_io_vproxy_msquic_MsQuicMod_MsQuicCxPlatWorkerThreadFinalize(struct CxPlatProcessEventLocals * CxPlatWorkerThreadLocals);
JNIEXPORT int32_t JNICALL JavaCritical_io_vproxy_msquic_MsQuicMod_MsQuicSetEventLoopThreadDispatcher(void);
JNIEXPORT int32_t JNICALL JavaCritical_io_vproxy_msquic_MsQuicMod_CxPlatGetCurThread(void * Thread);

#ifdef __cplusplus
}
#endif
#endif // _Included_io_vproxy_msquic_MsQuicMod
// metadata.generator-version: pni 21.0.0.11
// sha256:2a5c4761f586197139f8dc5586a39ca8927f0656414d10ad83288d41ea760ac3