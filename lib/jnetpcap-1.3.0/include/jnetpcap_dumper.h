#include <jni.h>
/* Header for jnetpcap_dumper methods */

#ifndef _Included_org_jnetpcap_PcapDumper
#define _Included_org_jnetpcap_PcapDumper
#ifdef __cplusplus
extern "C" {
#define	EXTERN extern "C"
#endif
	
extern	jclass pcapDumperClass;

extern jclass pcapDumperClass;

extern jmethodID pcapDumperConstructorMID;

extern jfieldID pcapDumperPhysicalFID;

// Prototypes
void setPcapDumper(JNIEnv *env, jobject obj, pcap_dumper_t *dumper);
pcap_dumper_t *getPcapDumper(JNIEnv *env, jobject obj);
jobject newPcapDumper(JNIEnv *env, pcap_dumper_t *dumper);

#ifdef __cplusplus
}
#endif
#endif
