/* Header for jnetpcap_utils utility methods */

#ifndef _Included_nio_jmemory_h
#define _Included_nio_jmemory_h
#ifdef __cplusplus
extern "C" {
#define	EXTERN extern "C"
#endif

#include <stdint.h>
#include "export.h"

#include <jni.h>

typedef struct memory_usage_t {
	uint64_t total_allocated;
	uint64_t total_deallocated;

	uint64_t total_allocate_calls;
	uint64_t total_deallocate_calls;

	uint64_t seg_0_255_bytes;
	uint64_t seg_256_or_above_bytes;

	uint64_t max_direct;
	uint64_t soft_direct;
	uint64_t reserved_direct;
	uint64_t available_direct;

} memory_usage_t;

typedef struct jni_global_ref_t {
	int count; // Number of references held
	jobject reference[]; // array of references held
} jni_global_ref_t;


extern	jclass jmemoryClass;
extern	jclass jmemoryPoolClass;
extern	jclass jmemoryReferenceClass;

extern  jmethodID jmemoryToDebugStringMID;
extern  jmethodID jmemoryMaxDirectMemoryBreachMID;
extern  jmethodID jmemorySoftDirectMemoryBreachMID;
extern  jmethodID jmemoryCleanupMID;
extern  jmethodID jmemoryPeer0MID;
extern  jmethodID jmemoryAllocateMID;
extern  jmethodID jmemorySetSize0MID;

extern	jfieldID jmemoryPhysicalFID;
extern	jfieldID jmemorySizeFID;
extern	jfieldID jmemoryOwnerFID;
extern	jfieldID jmemoryKeeperFID;
extern	jfieldID jmemoryRefFID;
extern  jfieldID jmemoryRefAddressFID;
extern	jobject  jmemoryPOINTER_CONST; // JMemory.POINTER constant reference

extern jmethodID jmemoryPoolAllocateExclusiveMID;
extern jmethodID jmemoryPoolDefaultMemoryPoolMID;

extern jobject defaultMemoryPool;

extern memory_usage_t memory_usage;

// Prototypes
void init_jmemory(JNIEnv *env);
void *getJMemoryPhysical(JNIEnv *env, jobject obj);
void setJMemoryPhysical(JNIEnv *env, jobject obj, jlong value);
void jmemoryCleanup(JNIEnv *env, jobject obj);

jint jmemoryPeer(JNIEnv *env, jobject obj, const void *ptr, size_t length, jobject owner);

char *jmemoryPoolAllocate(JNIEnv *env, size_t size, jobject *obj_ref);
void jmemoryResize(JNIEnv *env, jobject obj, size_t size);
char *jmemoryAllocate(JNIEnv *env, size_t size, jobject obj);
char *jmemoryToDebugString(JNIEnv *env, jobject obj, char *buf);


#ifdef __cplusplus
}
#endif
#endif
