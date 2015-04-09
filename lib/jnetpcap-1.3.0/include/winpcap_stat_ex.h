#include <jni.h>
/* Header for jnetpcap_utils utility methods */

#ifndef _Included_org_jnetpcap_WinWinPcapStat
#define _Included_org_jnetpcap_WinWinPcapStat
#ifdef __cplusplus
extern "C" {
#define	EXTERN extern "C"
#endif
	
extern	jclass winWinPcapStatClass;

// Prototypes
jobject newWinPcapStat(JNIEnv *env);
void setWinPcapStat(JNIEnv *env, jobject jstats, struct pcap_stat *stats, 
		int size);


#ifdef __cplusplus
}
#endif
#endif
