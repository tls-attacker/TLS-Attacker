/* Header for jnetpcap_utils utility methods */

#ifndef _Included_winpcap_ids_h
#define _Included_winpcap_ids_h
#ifdef __cplusplus
extern "C" {
#define	EXTERN extern "C"
#endif

#include "export.h"
	
#include <jni.h>
	
// WinPcapSamp
extern jclass winPcapSampClass;
extern jfieldID winPcapSampPhysicalFID;
extern jmethodID winPcapSampConstructorMID;

// WinPcapStat
extern jclass WinPcapStatClass;
extern jmethodID WinPcapStatConstructorMID;

// WinPcapRmtAuth
extern jclass winPcapRmtAuthClass;
extern jfieldID winPcapRmtAuthTypeFID;
extern jfieldID winPcapRmtAuthUsernameFID;
extern jfieldID winPcapRmtAuthPasswordFID;

#ifdef __cplusplus
}
#endif
#endif
